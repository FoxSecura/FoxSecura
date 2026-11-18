// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Règles AutoMod natives au runtime : client serenity, lecture de la
//! configuration et réconciliation sous le verrou de la guilde.
//!
//! Quand réconcilier (V1) — **jamais** au démarrage ni à l'arrivée sur une
//! guilde : aucune règle Discord n'est créée sans action humaine, sauf la
//! restauration par la garde d'une règle existante.
//!
//! 1. basculement d'un interrupteur lié dans `/config` : cette règle,
//!    `create_when_disabled = false` ;
//! 2. changement de la liste de mots (mots perso, langue) : la règle des mots
//!    interdits, `create_when_disabled = true` ;
//! 3. bouton « Synchroniser AutoMod » : les six règles,
//!    `create_when_disabled = true` ;
//! 4. bouton « Supprimer les règles FoxSecura » (propriétaire) ;
//! 5. garde des règles ([`guard`], module `automod_rule_guard`).
//!
//! Permission : `MANAGE_GUILD`. Les décisions sont dans
//! `foxsecura::protection::automod::native_rules` ; ce module ne fait que
//! lire la base et le cache et appeler l'API. Les erreurs sont journalisées et
//! jamais propagées.

use foxsecura::protection::anti_nuke::audit::{AuditAction, AuditEntry};
use foxsecura::protection::anti_nuke::server_integrity::automod_rule_guard::{
    GuardInput, GuardPlan, RuleGuardIncidentInput, considered_rule_name, detect_alteration,
    plan_rule_guard, restore_result, rule_guard_incident,
};
use foxsecura::protection::automod::bad_words::resolve_blocked_words;
use foxsecura::protection::automod::native_rules::{
    AutoModRuleClient, AutoModRuleKey, CleanupOutcome, ExistingAutoModRule, ReconcileOutcome,
    ReconcileRequest, RuleRequest, build_rule_specs, delete_foxsecura_rules, existing_rule,
    reconcile_guild,
};
use foxsecura::protection::quarantine::DiscordFailure;
use foxsecura::protection::shared::ProtectionModule;
use poise::serenity_prelude as serenity;
use serde_json::Value;

use super::anti_nuke::{is_author_exempt, language, read_context};
use super::quarantine::discord_failure;
use super::server_integrity::publish_critical;
use crate::app::{AppData, Error, run_database};

/// Client HTTP serenity, charge JSON brute.
pub struct DiscordAutoModClient<'a> {
    http: &'a serenity::Http,
}

impl<'a> DiscordAutoModClient<'a> {
    pub fn new(http: &'a serenity::Http) -> Self {
        Self { http }
    }
}

impl AutoModRuleClient for DiscordAutoModClient<'_> {
    async fn list_rules(&self, guild_id: u64) -> Result<Vec<ExistingAutoModRule>, DiscordFailure> {
        self.http
            .get_automod_rules(serenity::GuildId::new(guild_id))
            .await
            .map(|rules| rules.iter().map(existing_rule).collect())
            .map_err(discord_failure)
    }

    async fn create_rule(
        &self,
        guild_id: u64,
        payload: &Value,
        reason: &str,
    ) -> Result<u64, DiscordFailure> {
        self.http
            .create_automod_rule(serenity::GuildId::new(guild_id), payload, Some(reason))
            .await
            .map(|rule| rule.id.get())
            .map_err(discord_failure)
    }

    async fn edit_rule(
        &self,
        guild_id: u64,
        rule_id: u64,
        payload: &Value,
        reason: &str,
    ) -> Result<(), DiscordFailure> {
        self.http
            .edit_automod_rule(
                serenity::GuildId::new(guild_id),
                serenity::RuleId::new(rule_id),
                payload,
                Some(reason),
            )
            .await
            .map(|_| ())
            .map_err(discord_failure)
    }

    async fn delete_rule(
        &self,
        guild_id: u64,
        rule_id: u64,
        reason: &str,
    ) -> Result<(), DiscordFailure> {
        self.http
            .delete_automod_rule(
                serenity::GuildId::new(guild_id),
                serenity::RuleId::new(rule_id),
                Some(reason),
            )
            .await
            .map_err(discord_failure)
    }
}

/// `MANAGE_GUILD` du bot d'après le cache ; `None` si la guilde ou le membre
/// du bot n'y est pas.
pub fn bot_manage_guild(ctx: &serenity::Context, guild_id: u64) -> Option<bool> {
    let bot_id = ctx.cache.current_user().id;
    ctx.cache
        .guild(serenity::GuildId::new(guild_id))
        .and_then(|guild| {
            guild.members.get(&bot_id).map(|member| {
                let permissions = guild.member_permissions(member);
                permissions.administrator() || permissions.manage_guild()
            })
        })
}

/// Règles demandées, avec leur état voulu d'après la configuration.
async fn rule_requests(
    data: &AppData,
    guild_id: u64,
    keys: &[AutoModRuleKey],
) -> Result<Vec<RuleRequest>, Error> {
    let (modules, config, bad_words) = run_database(&data.database, move |database| {
        Ok((
            database.enabled_modules(guild_id)?,
            database.find_guild_config(guild_id)?,
            database.bad_words_settings(guild_id)?,
        ))
    })
    .await?;
    let anti_spam = config.is_some_and(|config| config.anti_spam.enabled);
    let words = resolve_blocked_words(bad_words.language, &bad_words.custom_words);
    Ok(build_rule_specs(words)
        .into_iter()
        .filter(|spec| keys.contains(&spec.key))
        .map(|spec| {
            let enabled = spec.key.is_switched_on(modules, anti_spam);
            RuleRequest::new(spec, enabled)
        })
        .collect())
}

/// Réconcilie les règles demandées, sous le verrou de la guilde ; `None` si
/// la configuration est illisible (rien n'est touché).
///
/// `adopt_rule_id` (garde, une seule règle) : règle altérée à reprendre
/// quel que soit son nom actuel.
pub async fn reconcile(
    ctx: &serenity::Context,
    data: &AppData,
    guild_id: u64,
    keys: &[AutoModRuleKey],
    create_when_disabled: bool,
    adopt_rule_id: Option<u64>,
) -> Option<ReconcileOutcome> {
    let mut rules = match rule_requests(data, guild_id, keys).await {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("[automod] configuration illisible pour la guilde {guild_id} : {error}");
            return None;
        }
    };
    if let [rule] = rules.as_mut_slice() {
        rule.adopt_rule_id = adopt_rule_id;
    }
    let request = ReconcileRequest {
        guild_id,
        rules,
        create_when_disabled,
        manage_guild: bot_manage_guild(ctx, guild_id),
    };
    let outcome = reconcile_guild(
        data.protection.automod_locks(),
        &DiscordAutoModClient::new(&ctx.http),
        request,
    )
    .await;
    println!("[automod] réconciliation de la guilde {guild_id} ({keys:?}) : {outcome:?}");
    Some(outcome)
}

/// Lit les règles de la guilde (affichage de `/config`), sans verrou.
pub async fn read_rules(
    ctx: &serenity::Context,
    guild_id: u64,
) -> Result<Vec<ExistingAutoModRule>, DiscordFailure> {
    DiscordAutoModClient::new(&ctx.http)
        .list_rules(guild_id)
        .await
}

/// Supprime toutes les règles FoxSecura (préfixe), sous le verrou de la
/// guilde.
pub async fn delete_all(ctx: &serenity::Context, data: &AppData, guild_id: u64) -> CleanupOutcome {
    let outcome = delete_foxsecura_rules(
        data.protection.automod_locks(),
        &DiscordAutoModClient::new(&ctx.http),
        guild_id,
        bot_manage_guild(ctx, guild_id),
    )
    .await;
    println!("[automod] suppression des règles FoxSecura de la guilde {guild_id} : {outcome:?}");
    outcome
}

/// Garde des règles : entrée `AutoModRuleUpdate` / `AutoModRuleDelete` déjà
/// retenue par le socle (propriétaire et FoxSecura lui-même exclus : nos
/// propres réconciliations ne reviennent jamais ici).
///
/// Restaure la seule règle altérée, sans sanctionner l'auteur, même s'il
/// est sur la liste blanche.
pub async fn guard(ctx: &serenity::Context, data: &AppData, entry: &AuditEntry, author_id: u64) {
    // Modification qui laisse la règle active : aucune lecture.
    if detect_alteration(entry.action, entry.enabled_after).is_none() {
        return;
    }
    let guild_id = entry.guild_id;
    let Some(context) = read_context(data, guild_id, author_id).await else {
        return;
    };
    if !context
        .enabled_modules
        .contains(ProtectionModule::AutoModRuleGuard)
    {
        return;
    }

    // Nom actuel relu seulement s'il manque l'ancien (modification sans
    // renommage) ; une règle supprimée porte toujours son ancien nom.
    let current_name = match (&entry.previous_name, entry.action, entry.target_id) {
        (None, AuditAction::AutoModRuleUpdate, Some(rule_id)) => match ctx
            .http
            .get_automod_rule(
                serenity::GuildId::new(guild_id),
                serenity::RuleId::new(rule_id),
            )
            .await
        {
            Ok(rule) => Some(rule.name),
            Err(error) => {
                eprintln!(
                    "[automod-rule-guard] règle {rule_id} de la guilde {guild_id} illisible : {}",
                    discord_failure(error).details
                );
                None
            }
        },
        _ => None,
    };
    let rule_name = considered_rule_name(entry.previous_name.as_deref(), current_name.as_deref());
    let author_exempt = is_author_exempt(ctx, &context, guild_id, author_id).await;
    let plan = plan_rule_guard(GuardInput {
        action: entry.action,
        enabled_after: entry.enabled_after,
        rule_name,
        modules: context.enabled_modules,
        anti_spam_enabled: context
            .guild_config
            .as_ref()
            .is_some_and(|config| config.anti_spam.enabled),
        author_exempt,
    });
    let GuardPlan::Restore {
        key,
        alteration,
        author_exempt,
    } = plan
    else {
        println!(
            "[automod-rule-guard] entrée {} de la guilde {guild_id} ignorée : {plan:?}",
            entry.entry_id
        );
        return;
    };

    // La règle modifiée existe encore : elle est reprise telle quelle
    // (renommée et réactivée) plutôt que dupliquée.
    let adopt = (entry.action == AuditAction::AutoModRuleUpdate)
        .then_some(entry.target_id)
        .flatten();
    let restore = match reconcile(ctx, data, guild_id, &[key], false, adopt).await {
        Some(outcome) => restore_result(&outcome),
        None => return,
    };
    println!(
        "[automod-rule-guard] {key:?} {} par {author_id} sur la guilde {guild_id} : {restore:?}",
        alteration.evidence()
    );
    let incident = rule_guard_incident(
        language(&context),
        RuleGuardIncidentInput {
            author_id,
            rule_name: rule_name.unwrap_or(key.rule_name()),
            alteration,
            author_exempt,
        },
        &restore,
    );
    publish_critical(
        ctx,
        data,
        &context,
        guild_id,
        ProtectionModule::AutoModRuleGuard,
        &incident,
    )
    .await;
}
