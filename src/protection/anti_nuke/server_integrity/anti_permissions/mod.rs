// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-permissions (V1) : retour en arrière d'un rôle qui reçoit une
//! permission dangereuse, sans effet Discord.
//!
//! Sur une entrée d'audit `RoleUpdate` qui change `permissions` : si le
//! nouveau bitfield **ajoute** une permission dangereuse
//! ([`DANGEROUS_PERMISSIONS`], liste de la tranche 4 ;
//! `ajoutées = nouveau & !ancien`), l'ancien bitfield est rétabli (raison
//! [`ANTI_PERMISSIONS_ROLLBACK_REASON`]) puis l'auteur non exempté est mis en
//! quarantaine (retrait des rôles dangereux, sans repli timeout). Retirer une
//! permission, ou en ré-ajouter une déjà présente, ne déclenche rien.
//!
//! # Rôles jamais touchés
//!
//! `@everyone`, un rôle géré par une intégration et **le rôle géré du bot
//! lui-même** (ses scopes changent quand un administrateur réinstalle le
//! bot). Un rôle absent du cache est ignoré : rien ne prouve qu'il n'est pas
//! géré (sûr par défaut).
//!
//! # Anti-boucle
//!
//! Le retour en arrière est lui-même un `RoleUpdate`, dont l'auteur est le
//! bot : le socle l'écarte (`AuditIgnoreReason::FoxSecuraAction`), il ne se
//! re-déclenche jamais. Aucun compteur supplémentaire n'est nécessaire.
//!
//! # Faux positif
//!
//! Une modification légitime par un administrateur non exempté est annulée
//! et son auteur confiné : l'équipe met ses administrateurs sur la liste
//! blanche, ou libère l'auteur et refait la modification. Un auteur exempté
//! n'est ni annulé ni confiné ; l'incident garde la visibilité.

use poise::serenity_prelude::Permissions;

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, AffectedResource, AffectedResourceType, FailureCode, LogSeverity, LogType,
    SecurityActor, SecurityEvidence, SecurityIncident,
};
use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};
use crate::protection::quarantine::{BotRoleStanding, DANGEROUS_PERMISSIONS};
use crate::protection::shared::{ProtectionModule, exempt_member_action, is_everyone_role};

use super::super::response::Containment;
use super::outcome::IntegrityActionResult;
use super::server_guard::detect_dangerous_permission_change;

/// Raison d'audit log du retour en arrière (V1).
pub const ANTI_PERMISSIONS_ROLLBACK_REASON: &str = "FoxSecura Anti-Permissions rollback";

/// Décision héritée de l'archive, conservée pour compatibilité.
pub fn detect_permission_escalation(
    enabled: bool,
    old_permissions: Permissions,
    new_permissions: Permissions,
    role_is_everyone: bool,
    role_is_managed: bool,
    executor_resolved: bool,
    executor_exempt: bool,
) -> ExecutorDecision {
    if role_is_everyone
        || role_is_managed
        || !detect_dangerous_permission_change(old_permissions, new_permissions)
    {
        return ExecutorDecision::Ignore;
    }

    evaluate_executor_action(enabled, executor_resolved, executor_exempt)
}

/// Permissions dangereuses **ajoutées** : `nouveau & !ancien`, restreint à
/// [`DANGEROUS_PERMISSIONS`].
pub fn added_dangerous_permissions(old: Permissions, new: Permissions) -> Permissions {
    (new & !old) & DANGEROUS_PERMISSIONS
}

/// Rôle modifié, d'après le cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdatedRole {
    pub id: u64,
    pub position: u16,
    pub managed: bool,
    /// Rôle géré du bot lui-même (`tags.bot_id`).
    pub bot_role: bool,
}

/// Raison pour laquelle une modification n'est pas traitée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionIgnore {
    /// Aucune permission dangereuse ajoutée.
    NoDangerousAddition,
    Everyone,
    Managed,
    /// Rôle géré du bot : ses scopes changent à la réinstallation.
    BotRole,
    /// Rôle absent du cache : rien ne prouve qu'il n'est pas géré.
    RoleUnknown,
}

/// Décision avant tout appel Discord.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionPlan {
    Ignore(PermissionIgnore),
    /// Traiter : `added` = permissions dangereuses ajoutées. `precheck` :
    /// `Some` si le retour en arrière ne peut pas être tenté d'après le cache
    /// (l'auteur est tout de même confiné).
    Respond {
        added: Permissions,
        precheck: Option<IntegrityActionResult>,
    },
}

/// Décide de la réponse d'après le cache.
///
/// Ordre : permissions ajoutées → `@everyone` → rôle du bot → rôle géré →
/// rôle absent du cache → `MANAGE_ROLES` → hiérarchie (le rôle doit être
/// strictement sous le rôle le plus haut du bot). Bot absent du cache : le
/// retour en arrière est tenté et un refus classé d'après la réponse HTTP.
pub fn plan_permission_rollback(
    guild_id: u64,
    role_id: u64,
    role: Option<UpdatedRole>,
    bot: Option<BotRoleStanding>,
    old: Permissions,
    new: Permissions,
) -> PermissionPlan {
    let added = added_dangerous_permissions(old, new);
    if added.is_empty() {
        return PermissionPlan::Ignore(PermissionIgnore::NoDangerousAddition);
    }
    if is_everyone_role(guild_id, role_id) {
        return PermissionPlan::Ignore(PermissionIgnore::Everyone);
    }
    let Some(role) = role else {
        return PermissionPlan::Ignore(PermissionIgnore::RoleUnknown);
    };
    if role.bot_role {
        return PermissionPlan::Ignore(PermissionIgnore::BotRole);
    }
    if role.managed {
        return PermissionPlan::Ignore(PermissionIgnore::Managed);
    }

    let precheck = bot.and_then(|bot| {
        if !bot.manage_roles {
            Some(IntegrityActionResult::Skipped {
                failure_code: Some(FailureCode::MissingPermission),
                details: "MANAGE_ROLES".to_owned(),
            })
        } else if role.position >= bot.top_role_position {
            Some(IntegrityActionResult::Skipped {
                failure_code: Some(FailureCode::RoleHierarchy),
                details: format!(
                    "role_position={} bot_top_role={}",
                    role.position, bot.top_role_position
                ),
            })
        } else {
            None
        }
    });
    PermissionPlan::Respond { added, precheck }
}

/// Résultat du retour en arrière pour un auteur exempté : non tenté.
pub fn exempt_rollback_result() -> IntegrityActionResult {
    IntegrityActionResult::Skipped {
        failure_code: None,
        details: "whitelist".to_owned(),
    }
}

/// Modification à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionIncidentInput<'a> {
    pub role_id: u64,
    /// Nom du rôle ; valeur non fiable, rendue par `inline_literal`.
    pub role_name: Option<&'a str>,
    pub author_id: u64,
    pub old: Permissions,
    pub new: Permissions,
    pub added: Permissions,
}

/// Incident `critical` (signal au mode panique), sauf pour un auteur exempté
/// (`warning`).
///
/// Preuves : ancien et nouveau bitfields (valeurs numériques), permissions
/// ajoutées. Le résultat du retour en arrière est distinct de celui de la
/// quarantaine ; un retour en arrière non appliqué laisse les permissions
/// dangereuses en place, ce que la recommandation signale.
pub fn permission_incident(
    language: Language,
    input: PermissionIncidentInput<'_>,
    rollback: &IntegrityActionResult,
    containment: &Containment,
) -> SecurityIncident {
    let exempt = matches!(containment, Containment::Exempt);
    let mut actions = vec![rollback.action_outcome(ActionCode::RollbackPermissions)];
    match containment {
        Containment::Exempt => actions.push(exempt_member_action()),
        other => actions.extend(other.action_outcomes()),
    }

    let mut incident = SecurityIncident::new(
        ProtectionModule::AntiPermissions.key(),
        LogType::Role,
        if exempt {
            LogSeverity::Warning
        } else {
            LogSeverity::Critical
        },
        text(
            language,
            if exempt {
                TextKey::AntiPermissionsExemptSummary
            } else {
                TextKey::AntiPermissionsSummary
            },
        ),
        actions,
    );
    incident.actor = Some(SecurityActor {
        user_id: input.author_id.to_string(),
        tag: None,
        account_created_at: None,
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Role,
        id: Some(input.role_id.to_string()),
        name: input.role_name.map(str::to_owned),
    });
    incident.evidence.extend([
        SecurityEvidence::Text {
            label: text(language, TextKey::AntiPermissionsEvidenceBitfields).to_owned(),
            value: format!("{}->{}", input.old.bits(), input.new.bits()),
        },
        SecurityEvidence::Text {
            label: text(language, TextKey::AntiPermissionsEvidenceAdded).to_owned(),
            value: input.added.get_permission_names().join(", "),
        },
    ]);
    incident.recommendation = Some(
        text(
            language,
            if exempt {
                TextKey::AntiPermissionsRecommendationExempt
            } else if rollback.applied() {
                TextKey::AntiPermissionsRecommendation
            } else {
                TextKey::AntiPermissionsRecommendationFailed
            },
        )
        .to_owned(),
    );
    incident
}
