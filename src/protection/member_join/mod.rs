// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Protections des arrivées de membres : ordre de la chaîne, décisions,
//! résultats et incidents, sans effet Discord.
//!
//! Chaque module renvoie un [`ModuleResult`] (`detected`, `action_applied`,
//! `terminal`) et l'incident à publier. Les effets Discord (ban, expulsion,
//! renommage) sont exécutés par le runtime avec le socle des sanctions
//! (`protection::shared::sanction`).
//!
//! # Chaîne des arrivées
//!
//! Ordre de la V1 ([`JOIN_ORDER`]) : liste noire → anti-raid → anti-bot →
//! nouveaux comptes → doubles comptes → usurpation → pseudos hoistés.
//! L'anti-raid et les doubles comptes (tranche 7) ne sont pas encore portés.
//!
//! Un résultat `terminal` (membre banni, expulsé ou mis en quarantaine, ou
//! liste noire) arrête la chaîne ; les résultats non terminaux se cumulent
//! ([`JoinChain`]).
//!
//! Une mise à jour de membre n'exécute que l'anti-pseudo hoisté, et
//! seulement si le nom affiché a changé ([`display_name_changed`]).

pub mod anti_bot;
pub mod blacklist;
pub mod hoisting;
pub mod impersonation;
pub mod new_account;

use std::time::UNIX_EPOCH;

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityActionOutcome,
    SecurityActor, SecurityEvidence, SecurityIncident,
};
use crate::protection::quarantine::QuarantineOutcome;
use crate::protection::shared::{ModuleSet, ProtectionModule, snowflake_timestamp};

/// Membre visé par un module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberRef {
    pub guild_id: u64,
    pub user_id: u64,
}

/// Résultat d'un module, pour la chaîne des arrivées.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModuleResult {
    /// Le module a relevé quelque chose (et publié un incident).
    pub detected: bool,
    /// Une action Discord a réellement été appliquée.
    pub action_applied: bool,
    /// Le membre a été banni, expulsé ou mis en quarantaine (ou doit l'être,
    /// pour la liste noire) : aucun module suivant ne s'exécute.
    pub terminal: bool,
}

impl ModuleResult {
    /// Rien relevé : la chaîne continue.
    pub const NOT_DETECTED: Self = Self {
        detected: false,
        action_applied: false,
        terminal: false,
    };
}

/// Étape de la chaîne des arrivées.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinStep {
    Blacklist,
    AntiBot,
    AntiNewAccount,
    AntiImpersonation,
    AntiNicknameHoisting,
}

/// Ordre de la V1, restreint aux modules portés.
pub const JOIN_ORDER: [JoinStep; 5] = [
    JoinStep::Blacklist,
    // Anti-raid (rafales d'arrivées) : tranche 7.
    JoinStep::AntiBot,
    JoinStep::AntiNewAccount,
    // Doubles comptes : tranche 7, entre les nouveaux comptes et
    // l'usurpation.
    JoinStep::AntiImpersonation,
    JoinStep::AntiNicknameHoisting,
];

impl JoinStep {
    /// Module activable par `/config` ; `None` pour la liste noire, toujours
    /// active (vide par défaut).
    pub const fn module(self) -> Option<ProtectionModule> {
        match self {
            Self::Blacklist => None,
            Self::AntiBot => Some(ProtectionModule::AntiBot),
            Self::AntiNewAccount => Some(ProtectionModule::AntiNewAccount),
            Self::AntiImpersonation => Some(ProtectionModule::AntiImpersonation),
            Self::AntiNicknameHoisting => Some(ProtectionModule::AntiNicknameHoisting),
        }
    }

    const fn enabled(self, modules: ModuleSet) -> bool {
        match self.module() {
            Some(module) => modules.contains(module),
            None => true,
        }
    }
}

/// Parcours de la chaîne pour une arrivée.
///
/// Le runtime demande l'étape suivante, l'exécute puis enregistre son
/// résultat :
///
/// ```text
/// while let Some(step) = chain.next_step() {
///     let result = run(step).await;
///     chain.record(step, result);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinChain {
    enabled: ModuleSet,
    position: usize,
    results: Vec<(JoinStep, ModuleResult)>,
    stopped_by: Option<JoinStep>,
}

impl JoinChain {
    pub fn new(enabled: ModuleSet) -> Self {
        Self {
            enabled,
            position: 0,
            results: Vec::with_capacity(JOIN_ORDER.len()),
            stopped_by: None,
        }
    }

    /// Prochaine étape activée ; `None` à la fin ou après un résultat
    /// terminal.
    pub fn next_step(&mut self) -> Option<JoinStep> {
        if self.stopped_by.is_some() {
            return None;
        }
        while let Some(&step) = JOIN_ORDER.get(self.position) {
            self.position += 1;
            if step.enabled(self.enabled) {
                return Some(step);
            }
        }
        None
    }

    /// Enregistre le résultat d'une étape ; un résultat terminal arrête la
    /// chaîne.
    pub fn record(&mut self, step: JoinStep, result: ModuleResult) {
        self.results.push((step, result));
        if result.terminal {
            self.stopped_by = Some(step);
        }
    }

    /// Résultats cumulés, dans l'ordre d'exécution.
    pub fn results(&self) -> &[(JoinStep, ModuleResult)] {
        &self.results
    }

    /// Étape dont le résultat terminal a arrêté la chaîne.
    pub const fn stopped_by(&self) -> Option<JoinStep> {
        self.stopped_by
    }
}

/// Une mise à jour de membre n'est analysée que si le nom affiché a changé.
///
/// Ancien nom inconnu (membre absent du cache) : analysé, faute de pouvoir
/// prouver qu'il n'a pas changé. L'analyse est idempotente : un nom déjà
/// corrigé n'est plus hoisté, rien ne boucle.
pub fn display_name_changed(previous: Option<&str>, current: &str) -> bool {
    previous != Some(current)
}

/// Résultat et incident d'un module qui a relevé quelque chose.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleResponse {
    pub result: ModuleResult,
    pub incident: SecurityIncident,
}

/// Incident de type `member` : membre visé comme acteur et ressource.
fn member_incident(
    module: &str,
    severity: LogSeverity,
    summary: &str,
    member: MemberRef,
    action: SecurityActionOutcome,
) -> SecurityIncident {
    let mut incident =
        SecurityIncident::new(module, LogType::Member, severity, summary, vec![action]);
    incident.actor = Some(SecurityActor {
        user_id: member.user_id.to_string(),
        tag: None,
        account_created_at: Some(UNIX_EPOCH + snowflake_timestamp(member.user_id)),
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Member,
        id: Some(member.user_id.to_string()),
        name: None,
    });
    incident
}

/// Rôles dangereux retirés par une quarantaine, listés pour l'équipe : ils ne
/// sont pas rendus à la libération (V1). `None` si aucun n'a été retiré.
fn removed_roles_evidence(
    language: Language,
    outcome: &QuarantineOutcome,
) -> Option<SecurityEvidence> {
    let removed = outcome.removed_roles();
    (!removed.is_empty()).then(|| SecurityEvidence::Text {
        label: text(language, TextKey::QuarantineEvidenceRemovedRoles).to_owned(),
        value: removed
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    })
}
