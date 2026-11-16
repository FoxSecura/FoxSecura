// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Rôle plafonné (V1, `limit_role`) : nombre maximal de membres qui portent
//! un rôle sensible, sans effet Discord.
//!
//! Configuration par guilde (migration 10) : le rôle et son plafond (1 à
//! 1000), réglés dans `/config` avec le droit `Right::Whitelist` (accorder ou
//! retirer des rôles est sensible). Le rôle choisi est refusé s'il est
//! `@everyone`, géré par une intégration, non gérable par le bot ou porteur
//! d'une permission dangereuse ([`validate_limit_role`]).
//!
//! Sur `GuildMemberUpdate` : si le rôle plafonné vient d'être **ajouté** à un
//! membre (ancien état connu par le cache) et que le nombre de membres qui le
//! portent **dépasse** le plafond, le rôle est retiré **au membre qui vient de
//! le recevoir** (raison [`LIMIT_ROLE_REASON`]). Jamais au propriétaire.
//!
//! # Comptage et cache
//!
//! Le nombre de porteurs vient du cache des membres. Si le cache est
//! incomplet, le runtime l'hydrate par l'API (pages de 1000 membres, au plus
//! [`MAX_HYDRATION_PAGES`] appels), seulement au moment rare où le rôle
//! plafonné vient d'être ajouté. Si le comptage reste incomplet (serveur trop
//! grand, appel échoué), **rien n'est retiré** : sûr par défaut, un retrait
//! sur un comptage partiel pourrait viser un membre légitime.
//!
//! # Anti-boucle
//!
//! Le retrait est lui-même un `GuildMemberUpdate` où le rôle **disparaît** :
//! il n'est jamais un ajout, donc jamais re-traité. Côté journal d'audit, le
//! `MemberRoleUpdate` correspondant est une action du bot, écartée par le
//! socle.

use std::ops::RangeInclusive;

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, AffectedResource, AffectedResourceType, FailureCode, LogSeverity, LogType,
    SecurityActor, SecurityEvidence, SecurityIncident, ThresholdUnit,
};
use crate::protection::quarantine::{
    BotRoleStanding, QuarantineRoleRefusal, RoleFacts, validate_quarantine_role,
};
use crate::protection::shared::ProtectionModule;

use super::server_integrity::outcome::IntegrityActionResult;

/// Raison d'audit log du retrait (V1).
pub const LIMIT_ROLE_REASON: &str = "FoxSecura Limit Role: cap exceeded";

/// Bornes du plafond.
pub const LIMIT_ROLE_MAX_RANGE: RangeInclusive<u16> = 1..=1000;

/// Plafond par défaut d'une guilde qui n'en a pas réglé.
pub const DEFAULT_LIMIT_ROLE_MAX: u16 = 5;

/// Pages de membres (1000 par page) lues au plus pour hydrater le cache :
/// au-delà de 25 000 membres non en cache, le comptage reste incomplet.
pub const MAX_HYDRATION_PAGES: usize = 25;

/// Réglages persistés (migration 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRoleSettings {
    /// `None` : non configuré.
    pub role_id: Option<u64>,
    pub max_members: u16,
}

impl Default for LimitRoleSettings {
    fn default() -> Self {
        Self {
            role_id: None,
            max_members: DEFAULT_LIMIT_ROLE_MAX,
        }
    }
}

/// Refuse un plafond hors bornes (1 à 1000).
pub fn validate_limit_role_max(value: u16) -> Result<u16, crate::database::DatabaseError> {
    if LIMIT_ROLE_MAX_RANGE.contains(&value) {
        Ok(value)
    } else {
        Err(crate::database::DatabaseError::InvalidLimitRoleMax(value))
    }
}

/// Valide un rôle existant choisi comme rôle plafonné : mêmes règles que le
/// rôle de quarantaine (`@everyone`, rôle géré, rôle non gérable, permission
/// dangereuse).
pub fn validate_limit_role(
    guild_id: u64,
    role: &RoleFacts,
    bot: BotRoleStanding,
) -> Result<(), QuarantineRoleRefusal> {
    validate_quarantine_role(guild_id, role, bot)
}

/// Compte des porteurs du rôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleCount {
    /// Comptage sur la liste complète des membres.
    Complete(usize),
    /// Cache incomplet malgré l'hydratation : rien n'est retiré.
    Incomplete,
}

/// Ce que le runtime sait au moment de la mise à jour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRoleFacts {
    pub settings: LimitRoleSettings,
    /// Rôles du membre avant la mise à jour ; `None` si l'ancien état n'est
    /// pas en cache (aucun ajout prouvé : rien n'est fait).
    pub had_role_before: Option<bool>,
    pub has_role_now: bool,
    pub is_guild_owner: bool,
}

/// Décision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitRolePlan {
    /// Pas un ajout du rôle plafonné (cas courant, et le retrait lui-même).
    NotAnAddition,
    /// Ajout au propriétaire : jamais retiré.
    GuildOwner,
    /// Le comptage est nécessaire pour décider.
    CountNeeded,
}

/// Première étape, sans comptage : ne compte que pour un ajout du rôle
/// plafonné à un autre membre que le propriétaire.
pub const fn plan_limit_role(facts: LimitRoleFacts) -> LimitRolePlan {
    if facts.settings.role_id.is_none() {
        return LimitRolePlan::NotAnAddition;
    }
    match facts.had_role_before {
        Some(false) if facts.has_role_now => {
            if facts.is_guild_owner {
                LimitRolePlan::GuildOwner
            } else {
                LimitRolePlan::CountNeeded
            }
        }
        _ => LimitRolePlan::NotAnAddition,
    }
}

/// Verdict après comptage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitRoleVerdict {
    /// Au plafond ou en dessous : rien.
    WithinCap { observed: usize },
    /// Au-delà : retirer le rôle au membre qui vient de le recevoir.
    Remove { observed: usize },
    /// Comptage incomplet : rien n'est retiré.
    CountIncomplete,
}

/// Compare le nombre de porteurs (le membre compris) au plafond.
pub const fn limit_role_verdict(count: RoleCount, max_members: u16) -> LimitRoleVerdict {
    match count {
        RoleCount::Incomplete => LimitRoleVerdict::CountIncomplete,
        RoleCount::Complete(observed) if observed > max_members as usize => {
            LimitRoleVerdict::Remove { observed }
        }
        RoleCount::Complete(observed) => LimitRoleVerdict::WithinCap { observed },
    }
}

/// Le cache des membres est-il complet ? `member_count` vient de Discord,
/// `cached` du cache.
pub const fn is_member_cache_complete(member_count: u64, cached: usize) -> bool {
    cached as u64 >= member_count
}

/// Retrait non tenté d'après le cache (rôle non gérable par le bot).
pub fn removal_precheck(
    role: Option<&RoleFacts>,
    bot: Option<BotRoleStanding>,
) -> Option<IntegrityActionResult> {
    let role = role?;
    let bot = bot?;
    if !bot.manage_roles {
        return Some(IntegrityActionResult::Skipped {
            failure_code: Some(FailureCode::MissingPermission),
            details: "MANAGE_ROLES".to_owned(),
        });
    }
    if !bot.can_manage(role) {
        return Some(IntegrityActionResult::Skipped {
            failure_code: Some(FailureCode::RoleHierarchy),
            details: format!(
                "role_position={} bot_top_role={}",
                role.position, bot.top_role_position
            ),
        });
    }
    None
}

/// Retrait à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRoleIncidentInput {
    pub role_id: u64,
    pub member_id: u64,
    pub observed: usize,
    pub max_members: u16,
}

/// Incident `warning` si le rôle a été retiré, `critical` sinon (le plafond
/// reste dépassé). Preuve : porteurs observés / plafond.
pub fn limit_role_incident(
    language: Language,
    input: LimitRoleIncidentInput,
    removal: &IntegrityActionResult,
) -> SecurityIncident {
    let removed = removal.applied();
    let mut incident = SecurityIncident::new(
        ProtectionModule::LimitRole.key(),
        LogType::Role,
        if removed {
            LogSeverity::Warning
        } else {
            LogSeverity::Critical
        },
        text(
            language,
            if removed {
                TextKey::LimitRoleSummary
            } else {
                TextKey::LimitRoleFailedSummary
            },
        ),
        vec![removal.action_outcome(ActionCode::RemoveLimitedRole)],
    );
    incident.actor = Some(SecurityActor {
        user_id: input.member_id.to_string(),
        tag: None,
        account_created_at: None,
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Role,
        id: Some(input.role_id.to_string()),
        name: None,
    });
    incident.evidence.push(SecurityEvidence::Threshold {
        observed: input.observed as u64,
        threshold: u64::from(input.max_members),
        window_seconds: None,
        unit: ThresholdUnit::Members,
    });
    incident.recommendation = Some(
        text(
            language,
            if removed {
                TextKey::LimitRoleRecommendation
            } else {
                TextKey::LimitRoleRecommendationFailed
            },
        )
        .to_owned(),
    );
    incident
}

/// Décision héritée de l'archive, conservée pour compatibilité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRoleInput {
    pub enabled: bool,
    pub role_configured: bool,
    pub max_members: Option<usize>,
    pub had_role_before: bool,
    pub has_role_now: bool,
    pub current_role_member_count: usize,
}

pub fn should_enforce_limit_role(input: LimitRoleInput) -> bool {
    if !input.enabled || !input.role_configured || input.max_members.is_none() {
        return false;
    }

    if input.had_role_before || !input.has_role_now {
        return false;
    }

    input.current_role_member_count > input.max_members.unwrap_or(usize::MAX)
}
