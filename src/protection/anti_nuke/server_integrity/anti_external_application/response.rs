// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-applications externes (V1) : retrait du seul bit `USE_EXTERNAL_APPS`
//! ajouté à un rôle, combiné avec l'anti-permissions, sans effet Discord.
//!
//! Sur une entrée d'audit `RoleUpdate` : si `USE_EXTERNAL_APPS` vient d'être
//! **ajouté** (absent de l'ancien bitfield, présent dans le nouveau) à un
//! rôle qui n'est ni `@everyone`, ni géré, ni celui du bot, et que l'auteur
//! n'est ni le propriétaire (garde du socle) ni sur la liste blanche, **seul
//! ce bit** est retiré (raison [`ANTI_EXTERNAL_APPLICATION_REVERT_REASON`]) ;
//! l'auteur est ensuite mis en quarantaine (retrait des rôles dangereux, sans
//! repli timeout). Mêmes pré-vérifications que l'anti-permissions
//! ([`role_revert_precheck`]).
//!
//! # Combinaison avec l'anti-permissions
//!
//! Si le même `RoleUpdate` ajoute aussi une permission dangereuse et que
//! l'anti-permissions est activé, un seul retour en arrière est fait : l'ancien
//! bitfield, qui ne contient pas le bit non plus. Un seul incident, celui de
//! l'anti-permissions, qui cite le bit parmi les permissions ajoutées.
//!
//! # Anti-boucle
//!
//! Le retrait est un `RoleUpdate` dont l'auteur est le bot, avec une raison
//! « FoxSecura » : le socle l'écarte (`AuditIgnoreReason::FoxSecuraAction`).

use poise::serenity_prelude::Permissions;

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityActor,
    SecurityEvidence, SecurityIncident,
};
use crate::protection::anti_nuke::response::Containment;
use crate::protection::anti_nuke::server_integrity::anti_permissions::{
    PermissionIgnore, UpdatedRole, added_dangerous_permissions, role_revert_precheck,
};
use crate::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use crate::protection::quarantine::BotRoleStanding;
use crate::protection::shared::ProtectionModule;

/// Raison d'audit log du retrait (V1).
pub const ANTI_EXTERNAL_APPLICATION_REVERT_REASON: &str =
    "FoxSecura Anti-External Application revert";

/// Permission surveillée.
pub const EXTERNAL_APPS_PERMISSION: Permissions = Permissions::USE_EXTERNAL_APPS;

/// `USE_EXTERNAL_APPS` vient d'être ajouté.
pub fn external_apps_added(old: Permissions, new: Permissions) -> bool {
    !old.contains(EXTERNAL_APPS_PERMISSION) && new.contains(EXTERNAL_APPS_PERMISSION)
}

/// Modules activés concernés par un `RoleUpdate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleUpdateModules {
    pub anti_permissions: bool,
    pub external_application: bool,
}

/// Réponse unique à un `RoleUpdate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleUpdateResponse {
    Ignore(PermissionIgnore),
    /// Anti-permissions (seul ou combiné) : rétablir `target` (l'ancien
    /// bitfield). `added` : permissions dangereuses ajoutées, plus
    /// `USE_EXTERNAL_APPS` si `external` ; un seul incident anti-permissions.
    Rollback {
        target: Permissions,
        added: Permissions,
        external: bool,
        precheck: Option<IntegrityActionResult>,
    },
    /// Applications externes seules : `target` = nouveau bitfield sans le bit.
    RevertExternal {
        target: Permissions,
        precheck: Option<IntegrityActionResult>,
    },
}

impl RoleUpdateResponse {
    /// Module qui signe l'incident.
    pub const fn module(&self) -> Option<ProtectionModule> {
        match self {
            Self::Ignore(_) => None,
            Self::Rollback { .. } => Some(ProtectionModule::AntiPermissions),
            Self::RevertExternal { .. } => Some(ProtectionModule::AntiExternalApplication),
        }
    }
}

/// Décide de la réponse d'après les modules activés et le cache.
pub fn plan_role_update(
    guild_id: u64,
    role_id: u64,
    role: Option<UpdatedRole>,
    bot: Option<BotRoleStanding>,
    (old, new): (Permissions, Permissions),
    modules: RoleUpdateModules,
) -> RoleUpdateResponse {
    let dangerous = modules
        .anti_permissions
        .then(|| added_dangerous_permissions(old, new))
        .filter(|added| !added.is_empty());
    let external = modules.external_application && external_apps_added(old, new);
    if dangerous.is_none() && !external {
        return RoleUpdateResponse::Ignore(PermissionIgnore::NoDangerousAddition);
    }

    let precheck = match role_revert_precheck(guild_id, role_id, role, bot) {
        Ok(precheck) => precheck,
        Err(reason) => return RoleUpdateResponse::Ignore(reason),
    };
    match dangerous {
        Some(added) => RoleUpdateResponse::Rollback {
            target: old,
            added: if external {
                added | EXTERNAL_APPS_PERMISSION
            } else {
                added
            },
            external,
            precheck,
        },
        None => RoleUpdateResponse::RevertExternal {
            target: new - EXTERNAL_APPS_PERMISSION,
            precheck,
        },
    }
}

/// Retrait à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalApplicationIncidentInput<'a> {
    pub role_id: u64,
    /// Nom du rôle ; valeur non fiable, rendue par `inline_literal`.
    pub role_name: Option<&'a str>,
    pub author_id: u64,
    pub old: Permissions,
    pub new: Permissions,
}

/// Incident `critical` (signal au mode panique) : bitfields, bit retiré,
/// résultat du retrait et de la quarantaine.
pub fn external_application_incident(
    language: Language,
    input: ExternalApplicationIncidentInput<'_>,
    revert: &IntegrityActionResult,
    containment: &Containment,
) -> SecurityIncident {
    let mut actions = vec![revert.action_outcome(ActionCode::RollbackPermissions)];
    actions.extend(containment.action_outcomes());
    let mut incident = SecurityIncident::new(
        ProtectionModule::AntiExternalApplication.key(),
        LogType::Role,
        LogSeverity::Critical,
        text(language, TextKey::AntiExternalApplicationSummary),
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
            value: EXTERNAL_APPS_PERMISSION.get_permission_names().join(", "),
        },
    ]);
    incident.recommendation = Some(
        text(
            language,
            if revert.applied() {
                TextKey::AntiExternalApplicationRecommendation
            } else {
                TextKey::AntiPermissionsRecommendationFailed
            },
        )
        .to_owned(),
    );
    incident
}
