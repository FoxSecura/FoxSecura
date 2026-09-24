// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Protections des arrivées de membres : décisions, résultats et incidents,
//! sans effet Discord.
//!
//! Chaque module renvoie un [`ModuleResult`] (`detected`, `action_applied`,
//! `terminal`) et l'incident à publier. Les effets Discord (ban, expulsion,
//! renommage) sont exécutés par le runtime avec le socle des sanctions
//! (`protection::shared::sanction`).

pub mod anti_bot;
pub mod blacklist;
pub mod new_account;

use std::time::UNIX_EPOCH;

use crate::logs::{
    AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityActionOutcome,
    SecurityActor, SecurityIncident,
};
use crate::protection::shared::snowflake_timestamp;

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
    /// Le membre a été banni ou expulsé (ou doit l'être, pour la liste
    /// noire) : aucun module suivant ne s'exécute.
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
