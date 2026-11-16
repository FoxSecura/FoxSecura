// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Restauration des salons et des rôles supprimés (V1), sans effet Discord.
//!
//! La source des données est l'objet supprimé fourni par l'événement Gateway
//! (`ChannelDelete`, `RoleDelete`), jamais un système de sauvegarde. L'auteur
//! vient de l'entrée d'audit correspondante reçue par le socle, corrélée par
//! cible et fraîcheur ([`RecentAuditAuthors`](super::super::audit)) ; un
//! auteur non résolu n'empêche jamais la restauration, mais ne déclenche
//! **aucune** sanction. Une suppression par le propriétaire ou par FoxSecura
//! lui-même n'est jamais restaurée : la restauration combattrait un ménage
//! légitime.
//!
//! Deux modes par ressource, comme la V1 (quatre interrupteurs de la table
//! générique) :
//!
//! - `anti_channel_delete` / `anti_role_delete` : restauration **et
//!   quarantaine** de l'auteur non exempté (retrait des rôles dangereux, sans
//!   repli timeout). Incident `warning` si la restauration a réussi, sinon
//!   `critical` ; l'incident pointe le **nouvel** identifiant de la ressource
//!   restaurée. Un auteur exempté est tout de même restauré, avec
//!   `ignore_exempt_member`.
//! - `auto_channel_restore` / `auto_role_restore` (appliqués seulement quand
//!   le mode anti correspondant est coupé) : restauration seule, incident
//!   `info` **uniquement en cas de succès**. Un échec ou « rien à restaurer »
//!   reste dans les logs locaux, pour ne pas noyer le salon de logs pendant un
//!   ménage légitime.
//!
//! Les suppressions ne nourrissent aucun compteur de rafale (V1) : la réponse
//! est la restauration et la sanction unitaire.
//!
//! # Ce qui n'est pas restauré
//!
//! Les messages, webhooks et fils d'un salon supprimé, et les membres d'un
//! rôle supprimé : Discord ne les fournit pas avec l'événement. La position
//! d'un rôle est remise au mieux (échec ignoré). Jamais `@everyone` ni un
//! rôle géré.

use poise::serenity_prelude::{ChannelType, Permissions};

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, ActionStatus, AffectedResource, AffectedResourceType, FailureCode, LogSeverity,
    LogType, SecurityActionOutcome, SecurityEvidence, SecurityIncident,
};
use crate::protection::quarantine::Overwrite;
use crate::protection::shared::{ModuleSet, ProtectionModule, is_everyone_role};

use super::super::response::Containment;

/// Raison d'audit log d'un salon restauré (V1), quel que soit le mode.
pub const CHANNEL_RESTORE_REASON: &str = "FoxSecura auto channel restore";

/// Raison d'audit log d'un rôle restauré (V1), quel que soit le mode.
pub const ROLE_RESTORE_REASON: &str = "FoxSecura auto role restore";

/// Mode de réponse à une suppression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMode {
    /// Restauration et quarantaine de l'auteur non exempté.
    Anti,
    /// Restauration seule, silencieuse hors succès.
    Auto,
}

/// Mode appliqué aux suppressions de salons ; le mode anti l'emporte.
pub fn channel_restore_mode(modules: ModuleSet) -> Option<RestoreMode> {
    restore_mode(
        modules,
        ProtectionModule::AntiChannelDelete,
        ProtectionModule::AutoChannelRestore,
    )
}

/// Mode appliqué aux suppressions de rôles ; le mode anti l'emporte.
pub fn role_restore_mode(modules: ModuleSet) -> Option<RestoreMode> {
    restore_mode(
        modules,
        ProtectionModule::AntiRoleDelete,
        ProtectionModule::AutoRoleRestore,
    )
}

fn restore_mode(
    modules: ModuleSet,
    anti: ProtectionModule,
    auto: ProtectionModule,
) -> Option<RestoreMode> {
    if modules.contains(anti) {
        Some(RestoreMode::Anti)
    } else if modules.contains(auto) {
        Some(RestoreMode::Auto)
    } else {
        None
    }
}

/// Types de salons restaurés (V1) ; les autres ne le sont pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorableChannelKind {
    Category,
    Text,
    News,
    Voice,
    Stage,
}

impl RestorableChannelKind {
    /// Type Discord du salon recréé.
    pub const fn discord_kind(self) -> ChannelType {
        match self {
            Self::Category => ChannelType::Category,
            Self::Text => ChannelType::Text,
            Self::News => ChannelType::News,
            Self::Voice => ChannelType::Voice,
            Self::Stage => ChannelType::Stage,
        }
    }
}

/// Type restaurable d'un salon supprimé ; `None` pour les autres types
/// (fils, forums, annuaires…), qui ne sont pas restaurés.
pub const fn restorable_channel_kind(kind: ChannelType) -> Option<RestorableChannelKind> {
    match kind {
        ChannelType::Category => Some(RestorableChannelKind::Category),
        ChannelType::Text => Some(RestorableChannelKind::Text),
        ChannelType::News => Some(RestorableChannelKind::News),
        ChannelType::Voice => Some(RestorableChannelKind::Voice),
        ChannelType::Stage => Some(RestorableChannelKind::Stage),
        _ => None,
    }
}

/// Plan de recréation d'un salon supprimé : nom, type, catégorie parente,
/// sujet, NSFW et permission overwrites clonés.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRestorePlan {
    pub name: String,
    pub kind: RestorableChannelKind,
    pub parent_id: Option<u64>,
    pub topic: Option<String>,
    pub nsfw: bool,
    pub overwrites: Vec<Overwrite>,
}

/// Rôle supprimé, d'après l'événement Gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedRole {
    pub id: u64,
    pub name: String,
    /// Couleur brute (`0` : aucune).
    pub colour: u32,
    pub hoist: bool,
    pub mentionable: bool,
    pub permissions: Permissions,
    pub position: u16,
    pub managed: bool,
}

/// Plan de recréation d'un rôle supprimé ; la position est remise au mieux
/// (échec ignoré).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRestorePlan {
    pub name: String,
    pub colour: u32,
    pub hoist: bool,
    pub mentionable: bool,
    pub permissions: Permissions,
    pub position: u16,
}

/// Rôle jamais restauré.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleRestoreRefusal {
    /// `@everyone` ne peut pas être supprimé ni recréé.
    Everyone,
    /// Rôle géré par une intégration : seule l'intégration peut le recréer.
    Managed,
}

/// Plan de recréation d'un rôle ; jamais `@everyone` ni un rôle géré.
pub fn plan_role_restore(
    guild_id: u64,
    role: &DeletedRole,
) -> Result<RoleRestorePlan, RoleRestoreRefusal> {
    if is_everyone_role(guild_id, role.id) {
        return Err(RoleRestoreRefusal::Everyone);
    }
    if role.managed {
        return Err(RoleRestoreRefusal::Managed);
    }
    Ok(RoleRestorePlan {
        name: role.name.clone(),
        colour: role.colour,
        hoist: role.hoist,
        mentionable: role.mentionable,
        permissions: role.permissions,
        position: role.position,
    })
}

/// Issue de la restauration côté Discord.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Ressource recréée, sous un nouvel identifiant.
    Restored { new_id: u64 },
    /// Recréation refusée ou échouée côté Discord.
    Failed {
        failure_code: FailureCode,
        details: String,
    },
    /// Rien à restaurer (type non restauré, données absentes, rôle géré…).
    NothingToRestore { details: String },
}

impl RestoreOutcome {
    pub const fn restored(&self) -> bool {
        matches!(self, Self::Restored { .. })
    }
}

/// Classe l'échec HTTP d'une recréation tentée.
pub const fn classify_restore_failure(status: Option<u16>) -> FailureCode {
    match status {
        Some(403) => FailureCode::MissingPermission,
        Some(404) => FailureCode::ResourceMissing,
        Some(429) | Some(500..=599) | None => FailureCode::DiscordUnavailable,
        Some(_) => FailureCode::Unknown,
    }
}

/// L'incident est-il envoyé dans le salon de logs ?
///
/// Mode auto : seulement en cas de succès ; un échec ou « rien à restaurer »
/// reste dans les logs locaux, pour ne pas noyer les logs pendant un ménage
/// légitime. Mode anti : toujours.
pub const fn should_publish_restore(mode: RestoreMode, outcome: &RestoreOutcome) -> bool {
    match mode {
        RestoreMode::Anti => true,
        RestoreMode::Auto => outcome.restored(),
    }
}

/// Ressource restaurée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoredResource {
    Channel,
    Role,
}

impl RestoredResource {
    /// Module du mode appliqué.
    pub const fn module(self, mode: RestoreMode) -> ProtectionModule {
        match (self, mode) {
            (Self::Channel, RestoreMode::Anti) => ProtectionModule::AntiChannelDelete,
            (Self::Channel, RestoreMode::Auto) => ProtectionModule::AutoChannelRestore,
            (Self::Role, RestoreMode::Anti) => ProtectionModule::AntiRoleDelete,
            (Self::Role, RestoreMode::Auto) => ProtectionModule::AutoRoleRestore,
        }
    }

    const fn action_code(self) -> ActionCode {
        match self {
            Self::Channel => ActionCode::RestoreChannel,
            Self::Role => ActionCode::RestoreRole,
        }
    }

    const fn log_type(self) -> LogType {
        match self {
            Self::Channel => LogType::Channel,
            Self::Role => LogType::Role,
        }
    }

    const fn resource_type(self) -> AffectedResourceType {
        match self {
            Self::Channel => AffectedResourceType::Channel,
            Self::Role => AffectedResourceType::Role,
        }
    }
}

/// Suppression à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreIncidentInput<'a> {
    pub guild_id: u64,
    pub resource: RestoredResource,
    pub mode: RestoreMode,
    /// Identifiant de la ressource supprimée.
    pub deleted_id: u64,
    /// Nom supprimé ; valeur non fiable, rendue par `inline_literal`.
    pub name: &'a str,
    /// Auteur corrélé ; `None` s'il n'est pas résolu.
    pub author_id: Option<u64>,
    pub outcome: &'a RestoreOutcome,
}

/// Sévérité : mode auto → `info` (publié seulement en cas de succès) ; mode
/// anti → `warning` si la restauration a réussi, `critical` sinon.
const fn restore_severity(mode: RestoreMode, outcome: &RestoreOutcome) -> LogSeverity {
    match mode {
        RestoreMode::Auto => LogSeverity::Info,
        RestoreMode::Anti => {
            if outcome.restored() {
                LogSeverity::Warning
            } else {
                LogSeverity::Critical
            }
        }
    }
}

fn restore_action_outcome(
    resource: RestoredResource,
    outcome: &RestoreOutcome,
) -> SecurityActionOutcome {
    let (status, details, failure_code) = match outcome {
        RestoreOutcome::Restored { new_id } => {
            (ActionStatus::Success, Some(new_id.to_string()), None)
        }
        RestoreOutcome::Failed {
            failure_code,
            details,
        } => (
            ActionStatus::Failed,
            Some(details.clone()),
            Some(*failure_code),
        ),
        RestoreOutcome::NothingToRestore { details } => (
            ActionStatus::Skipped,
            Some(details.clone()),
            Some(FailureCode::ResourceMissing),
        ),
    };
    SecurityActionOutcome {
        action: resource.action_code(),
        status,
        details,
        failure_code,
    }
}

const fn restore_summary(input: &RestoreIncidentInput<'_>, exempt: bool) -> TextKey {
    if exempt {
        return TextKey::RestoreExemptSummary;
    }
    match (input.resource, input.mode) {
        (RestoredResource::Channel, RestoreMode::Anti) => TextKey::AntiChannelDeleteSummary,
        (RestoredResource::Channel, RestoreMode::Auto) => TextKey::AutoChannelRestoreSummary,
        (RestoredResource::Role, RestoreMode::Anti) => TextKey::AntiRoleDeleteSummary,
        (RestoredResource::Role, RestoreMode::Auto) => TextKey::AutoRoleRestoreSummary,
    }
}

/// Incident d'une suppression traitée.
///
/// `containment` : réponse appliquée à l'auteur (mode anti seulement).
/// L'incident pointe le **nouvel** identifiant de la ressource restaurée ;
/// la ressource supprimée (nom et ancien identifiant) reste en preuve.
pub fn restore_incident(
    language: Language,
    input: RestoreIncidentInput<'_>,
    containment: Option<&Containment>,
) -> SecurityIncident {
    let exempt = matches!(containment, Some(Containment::Exempt));
    let mut actions = vec![restore_action_outcome(input.resource, input.outcome)];
    if let Some(containment) = containment {
        actions.extend(containment.action_outcomes());
    }

    let mut incident = SecurityIncident::new(
        input.resource.module(input.mode).key(),
        input.resource.log_type(),
        restore_severity(input.mode, input.outcome),
        text(language, restore_summary(&input, exempt)),
        actions,
    );
    incident.actor = input.author_id.map(|author_id| crate::logs::SecurityActor {
        user_id: author_id.to_string(),
        tag: None,
        account_created_at: None,
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: input.resource.resource_type(),
        id: Some(match input.outcome {
            RestoreOutcome::Restored { new_id } => new_id.to_string(),
            _ => input.deleted_id.to_string(),
        }),
        name: Some(input.name.to_owned()),
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::RestoreEvidenceDeleted).to_owned(),
        value: format!("{} ({})", input.name, input.deleted_id),
    });
    incident.recommendation = Some(
        text(
            language,
            match input.mode {
                RestoreMode::Anti => TextKey::RestoreRecommendationAnti,
                RestoreMode::Auto => TextKey::RestoreRecommendationAuto,
            },
        )
        .to_owned(),
    );
    incident
}
