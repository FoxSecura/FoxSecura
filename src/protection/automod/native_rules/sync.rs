// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Exécution de la réconciliation des règles natives, derrière un client
//! HTTP abstrait ([`AutoModRuleClient`]) : le runtime branche serenity, les
//! tests un faux client.
//!
//! - **Permission** : sans `MANAGE_GUILD` (d'après le cache), un seul
//!   résultat [`ReconcileOutcome::MissingPermission`] et **aucun** appel.
//! - **Verrou par guilde** : toute réconciliation et toute suppression
//!   tiennent le verrou de la guilde, de la lecture des règles au dernier
//!   appel. Un basculement dans `/config` et une restauration par la garde ne
//!   s'entrelacent donc jamais (sinon : deux lectures « règle absente », deux
//!   créations, un doublon).
//! - **Échec isolé** : l'échec d'un appel n'arrête pas les autres règles ;
//!   le rapport ([`RuleSyncReport`]) dit, par règle, ce qui a été fait.
//!
//! Mono-instance : le verrou est en mémoire, deux processus sur la même
//! guilde ne se coordonnent pas.

use std::future::Future;

use serde_json::Value;

use crate::protection::lockdown::GuildLocks;
use crate::protection::quarantine::DiscordFailure;

use super::payload::{
    AUTOMOD_CLEANUP_REASON, AUTOMOD_DUPLICATE_CLEANUP_REASON, AUTOMOD_MIGRATE_REASON,
    AUTOMOD_NO_KEYWORDS_REASON, AUTOMOD_SETUP_REASON, KeywordLimitReport, apply_discord_limits,
    create_payload, update_payload,
};
use super::reconciler::{
    ExistingAutoModRule, RuleMutation, SyncPlan, UpdateMode, plan_reconciliation,
};
use super::spec::{AUTOMOD_RULE_PREFIX, AutoModRuleKey, AutoModRuleSkipReason, AutoModRuleSpec};

/// Appels Discord des règles AutoMod (`MANAGE_GUILD`).
pub trait AutoModRuleClient {
    /// Règles de la guilde.
    fn list_rules(
        &self,
        guild_id: u64,
    ) -> impl Future<Output = Result<Vec<ExistingAutoModRule>, DiscordFailure>> + Send;

    /// Crée une règle ; renvoie son identifiant.
    fn create_rule(
        &self,
        guild_id: u64,
        payload: &Value,
        reason: &str,
    ) -> impl Future<Output = Result<u64, DiscordFailure>> + Send;

    fn edit_rule(
        &self,
        guild_id: u64,
        rule_id: u64,
        payload: &Value,
        reason: &str,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;

    fn delete_rule(
        &self,
        guild_id: u64,
        rule_id: u64,
        reason: &str,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;
}

/// Une règle à réconcilier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRequest {
    pub spec: AutoModRuleSpec,
    /// État voulu, d'après l'interrupteur lié.
    pub enabled: bool,
    /// Règle existante à reprendre comme la règle de cette spécification,
    /// quel que soit son nom actuel (garde : règle renommée puis désactivée).
    pub adopt_rule_id: Option<u64>,
}

impl RuleRequest {
    pub fn new(spec: AutoModRuleSpec, enabled: bool) -> Self {
        Self {
            spec,
            enabled,
            adopt_rule_id: None,
        }
    }
}

/// Demande de réconciliation d'une guilde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileRequest {
    pub guild_id: u64,
    pub rules: Vec<RuleRequest>,
    /// `false` (basculement, garde) : une règle absente et désactivée n'est
    /// pas créée. `true` (synchronisation, liste de mots) : elle l'est.
    pub create_when_disabled: bool,
    /// `MANAGE_GUILD` du bot d'après le cache ; `None` si inconnu (les
    /// appels sont tentés, Discord tranche).
    pub manage_guild: Option<bool>,
}

/// Ce qui est arrivé à une règle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSyncStatus {
    Created {
        enabled: bool,
    },
    Updated {
        enabled: bool,
    },
    /// Absente et désactivée : rien à créer.
    Missing,
    /// Non créée ou supprimée : liste vide, ou type unique déjà pris par une
    /// règle étrangère.
    Skipped(AutoModRuleSkipReason),
    Failed(DiscordFailure),
}

/// Rapport d'une règle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSyncReport {
    pub key: AutoModRuleKey,
    pub status: RuleSyncStatus,
    /// Règles supprimées (doublons, migration, liste vide).
    pub removed: usize,
    /// Échecs non bloquants (doublon non supprimé).
    pub failures: Vec<DiscordFailure>,
    /// Mots-clés écartés par les limites Discord.
    pub limits: KeywordLimitReport,
}

impl RuleSyncReport {
    /// La règle est en place selon la configuration.
    pub const fn succeeded(&self) -> bool {
        matches!(
            self.status,
            RuleSyncStatus::Created { .. } | RuleSyncStatus::Updated { .. }
        )
    }
}

/// Issue d'une réconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Le bot n'a pas `MANAGE_GUILD` : aucune règle touchée, aucun appel.
    MissingPermission,
    /// Lecture des règles impossible : aucune règle touchée.
    ReadFailed(DiscordFailure),
    Synced(Vec<RuleSyncReport>),
}

/// Issue de la suppression des règles FoxSecura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    MissingPermission,
    ReadFailed(DiscordFailure),
    Done {
        deleted: usize,
        /// Nom de la règle (valeur Discord, non fiable) et échec.
        failures: Vec<(String, DiscordFailure)>,
    },
}

/// Règles FoxSecura : le nom commence par [`AUTOMOD_RULE_PREFIX`]. Une règle
/// d'un autre bot ou d'un modérateur n'est jamais touchée.
pub fn foxsecura_rules(rules: &[ExistingAutoModRule]) -> Vec<&ExistingAutoModRule> {
    rules
        .iter()
        .filter(|rule| rule.name.starts_with(AUTOMOD_RULE_PREFIX))
        .collect()
}

/// Réconcilie les règles demandées, sous le verrou de la guilde.
pub async fn reconcile_guild<C: AutoModRuleClient>(
    locks: &GuildLocks,
    client: &C,
    request: ReconcileRequest,
) -> ReconcileOutcome {
    if request.manage_guild == Some(false) {
        return ReconcileOutcome::MissingPermission;
    }
    let guild_id = request.guild_id;
    let _guard = locks.lock(guild_id).await;
    let existing = match client.list_rules(guild_id).await {
        Ok(rules) => rules,
        Err(failure) => return ReconcileOutcome::ReadFailed(failure),
    };

    let mut reports = Vec::with_capacity(request.rules.len());
    for rule in request.rules {
        let (spec, limits) = apply_discord_limits(&rule.spec);
        let adopted;
        let rules = match rule.adopt_rule_id {
            Some(rule_id) => {
                adopted = adopt(&existing, rule_id, spec.name);
                &adopted
            }
            None => &existing,
        };
        let plan = plan_reconciliation(rules, &spec, rule.enabled, request.create_when_disabled);
        reports.push(execute_rule(client, guild_id, &spec, &plan, limits).await);
    }
    ReconcileOutcome::Synced(reports)
}

/// Supprime toutes les règles FoxSecura (préfixe), sous le verrou de la
/// guilde.
pub async fn delete_foxsecura_rules<C: AutoModRuleClient>(
    locks: &GuildLocks,
    client: &C,
    guild_id: u64,
    manage_guild: Option<bool>,
) -> CleanupOutcome {
    if manage_guild == Some(false) {
        return CleanupOutcome::MissingPermission;
    }
    let _guard = locks.lock(guild_id).await;
    let existing = match client.list_rules(guild_id).await {
        Ok(rules) => rules,
        Err(failure) => return CleanupOutcome::ReadFailed(failure),
    };
    let mut deleted = 0;
    let mut failures = Vec::new();
    for rule in foxsecura_rules(&existing) {
        match client
            .delete_rule(guild_id, rule.id, AUTOMOD_CLEANUP_REASON)
            .await
        {
            Ok(()) => deleted += 1,
            Err(failure) => failures.push((rule.name.clone(), failure)),
        }
    }
    CleanupOutcome::Done { deleted, failures }
}

/// Copie des règles où la règle `rule_id` porte le nom de la spécification.
fn adopt(existing: &[ExistingAutoModRule], rule_id: u64, name: &str) -> Vec<ExistingAutoModRule> {
    existing
        .iter()
        .cloned()
        .map(|mut rule| {
            if rule.id == rule_id {
                rule.name = name.to_owned();
            }
            rule
        })
        .collect()
}

/// Exécute le plan d'une règle, dans l'ordre.
///
/// Doublons supprimés d'abord (un échec n'empêche pas la suite) ; migration
/// de déclencheur = suppression puis création (si la suppression échoue, la
/// création n'est pas tentée : elle ferait un doublon ou un conflit).
async fn execute_rule<C: AutoModRuleClient>(
    client: &C,
    guild_id: u64,
    spec: &AutoModRuleSpec,
    plan: &SyncPlan,
    limits: KeywordLimitReport,
) -> RuleSyncReport {
    let no_keywords = plan.skipped_reason == Some(AutoModRuleSkipReason::NoKeywords);
    let migration_at = match plan.mutations.as_slice() {
        [.., RuleMutation::Delete { .. }, RuleMutation::Create { .. }] if !no_keywords => {
            Some(plan.mutations.len() - 2)
        }
        _ => None,
    };
    let mut report = RuleSyncReport {
        key: spec.key,
        status: RuleSyncStatus::Missing,
        removed: 0,
        failures: Vec::new(),
        limits,
    };
    let mut status = None;

    for (index, mutation) in plan.mutations.iter().enumerate() {
        match *mutation {
            RuleMutation::Delete { rule_id } => {
                let migrating = migration_at == Some(index);
                let reason = if no_keywords {
                    AUTOMOD_NO_KEYWORDS_REASON
                } else if migrating {
                    AUTOMOD_MIGRATE_REASON
                } else {
                    AUTOMOD_DUPLICATE_CLEANUP_REASON
                };
                match client.delete_rule(guild_id, rule_id, reason).await {
                    Ok(()) => report.removed += 1,
                    Err(failure) if migrating => {
                        status = Some(RuleSyncStatus::Failed(failure));
                        break;
                    }
                    Err(failure) => report.failures.push(failure),
                }
            }
            RuleMutation::Create { enabled } => {
                let reason = if migration_at.is_some() {
                    AUTOMOD_MIGRATE_REASON
                } else {
                    AUTOMOD_SETUP_REASON
                };
                status = Some(
                    match client
                        .create_rule(guild_id, &create_payload(spec, enabled), reason)
                        .await
                    {
                        Ok(_) => RuleSyncStatus::Created { enabled },
                        Err(failure) => RuleSyncStatus::Failed(failure),
                    },
                );
            }
            RuleMutation::Update {
                rule_id,
                enabled,
                mode,
            } => {
                status = Some(
                    match client
                        .edit_rule(
                            guild_id,
                            rule_id,
                            &update_payload(spec, enabled, mode),
                            AUTOMOD_SETUP_REASON,
                        )
                        .await
                    {
                        Ok(()) => RuleSyncStatus::Updated {
                            enabled: enabled && mode == UpdateMode::FullSpec,
                        },
                        Err(failure) => RuleSyncStatus::Failed(failure),
                    },
                );
            }
        }
    }

    report.status = match (status, plan.skipped_reason) {
        (Some(status), _) => status,
        // Liste vide dont une suppression a échoué : la règle reste en place.
        (None, Some(AutoModRuleSkipReason::NoKeywords)) if !report.failures.is_empty() => {
            RuleSyncStatus::Failed(report.failures.remove(0))
        }
        (None, Some(reason)) => RuleSyncStatus::Skipped(reason),
        (None, None) => RuleSyncStatus::Missing,
    };
    report
}
