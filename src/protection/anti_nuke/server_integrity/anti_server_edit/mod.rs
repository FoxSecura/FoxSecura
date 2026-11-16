// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réglages du serveur (V1) : alerte sur un changement des champs surveillés,
//! **sans retour en arrière**, sans effet Discord.
//!
//! Champs surveillés : nom, icône, niveau de vérification, réglage des
//! notifications par défaut ([`WATCHED_SERVER_FIELDS`]). L'alerte `warning`
//! liste les champs changés (`Changed: name, icon`) ; rien si aucun champ
//! surveillé n'a changé. Revenir en arrière combattrait le propriétaire et
//! l'équipe sur des modifications banales : FoxSecura alerte seulement, et
//! n'applique aucune sanction (V1). L'alerte n'est pas un signal du mode
//! panique.
//!
//! L'ancienne version du serveur vient du cache : sans elle (serveur absent
//! du cache), aucune comparaison n'est possible et rien n'est signalé.

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityEvidence,
    SecurityIncident,
};
use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};
use crate::protection::shared::ProtectionModule;

use super::alert::AlertAuthor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerField {
    Name,
    Icon,
    Banner,
    Description,
    VerificationLevel,
    DefaultNotifications,
    ExplicitContentFilter,
    AfkChannel,
    SystemChannel,
}

impl ServerField {
    /// Clé affichée dans l'alerte.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Icon => "icon",
            Self::Banner => "banner",
            Self::Description => "description",
            Self::VerificationLevel => "verification_level",
            Self::DefaultNotifications => "default_notifications",
            Self::ExplicitContentFilter => "explicit_content_filter",
            Self::AfkChannel => "afk_channel",
            Self::SystemChannel => "system_channel",
        }
    }
}

/// Champs surveillés (V1), dans l'ordre de l'alerte.
pub const WATCHED_SERVER_FIELDS: [ServerField; 4] = [
    ServerField::Name,
    ServerField::Icon,
    ServerField::VerificationLevel,
    ServerField::DefaultNotifications,
];

/// Réglages du serveur comparés, d'après le cache et l'événement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSettings {
    pub name: String,
    /// Hash de l'icône ; `None` sans icône.
    pub icon: Option<String>,
    pub verification_level: u8,
    pub default_notifications: u8,
    /// URL personnalisée (vanity) ; `None` sans URL.
    pub vanity_url_code: Option<String>,
}

/// Champs surveillés qui ont changé, dans l'ordre de [`WATCHED_SERVER_FIELDS`].
pub fn changed_server_fields(old: &ServerSettings, new: &ServerSettings) -> Vec<ServerField> {
    WATCHED_SERVER_FIELDS
        .into_iter()
        .filter(|field| match field {
            ServerField::Name => old.name != new.name,
            ServerField::Icon => old.icon != new.icon,
            ServerField::VerificationLevel => old.verification_level != new.verification_level,
            ServerField::DefaultNotifications => {
                old.default_notifications != new.default_notifications
            }
            _ => false,
        })
        .collect()
}

/// Liste lisible des champs : `name, icon`.
pub fn changed_fields_label(fields: &[ServerField]) -> String {
    fields
        .iter()
        .map(|field| field.key())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Alerte `warning` d'un changement des réglages ; `None` si aucun champ
/// surveillé n'a changé. Aucune sanction, aucun signal au mode panique.
pub fn server_edit_incident(
    language: Language,
    guild_id: u64,
    fields: &[ServerField],
    author: AlertAuthor,
) -> Option<SecurityIncident> {
    if fields.is_empty() {
        return None;
    }
    let mut incident = SecurityIncident::new(
        ProtectionModule::AntiServerEdit.key(),
        LogType::Server,
        LogSeverity::Warning,
        text(language, TextKey::AntiServerEditSummary),
        author.alert_actions(),
    );
    incident.actor = author.actor();
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Server,
        id: Some(guild_id.to_string()),
        name: None,
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: "Changed".to_owned(),
        value: changed_fields_label(fields),
    });
    incident.recommendation =
        Some(text(language, TextKey::AntiServerEditRecommendation).to_owned());
    Some(incident)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerEditResult {
    pub decision: ExecutorDecision,
    pub changed_fields: usize,
}

/// Décision héritée de l'archive, conservée pour compatibilité.
pub fn detect_server_edit(
    enabled: bool,
    changed_fields: &[ServerField],
    executor_resolved: bool,
    executor_exempt: bool,
) -> ServerEditResult {
    if changed_fields.is_empty() {
        return ServerEditResult {
            decision: ExecutorDecision::Ignore,
            changed_fields: 0,
        };
    }

    ServerEditResult {
        decision: evaluate_executor_action(enabled, executor_resolved, executor_exempt),
        changed_fields: changed_fields.len(),
    }
}
