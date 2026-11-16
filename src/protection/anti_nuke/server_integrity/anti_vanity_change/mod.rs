// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! URL personnalisée (V1) : alerte `critical` sur un changement de vanity,
//! **alerte seule**, sans effet Discord.
//!
//! # Limite
//!
//! L'API de Discord ne permet pas de reprendre une URL personnalisée volée :
//! une fois libérée, n'importe quel serveur éligible peut la réclamer, et un
//! bot ne peut pas la réattribuer de façon fiable. FoxSecura n'essaie donc
//! aucun retour en arrière ni aucune sanction (V1) : il signale
//! `ancien->nouveau` pour que l'équipe réagisse vite (support Discord, retrait
//! des droits de l'auteur).
//!
//! L'alerte d'un auteur non exempté est critique et envoie un signal au mode
//! panique, comme les autres incidents critiques de l'anti-nuke ; celle d'un
//! auteur de la liste blanche reste `warning`.

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityEvidence,
    SecurityIncident, defang,
};
use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};
use crate::protection::shared::ProtectionModule;

use super::alert::AlertAuthor;

/// Décision héritée de l'archive, conservée pour compatibilité.
pub fn detect_vanity_change(
    enabled: bool,
    old_code: Option<&str>,
    new_code: Option<&str>,
    executor_resolved: bool,
    executor_exempt: bool,
) -> ExecutorDecision {
    if old_code == new_code {
        return ExecutorDecision::Ignore;
    }

    evaluate_executor_action(enabled, executor_resolved, executor_exempt)
}

/// L'URL personnalisée a changé (ajout, retrait ou remplacement).
pub fn vanity_changed(old: Option<&str>, new: Option<&str>) -> bool {
    old != new
}

/// `ancien->nouveau`, défangué (`discord[.]gg/code`) ; `none` pour une URL
/// absente. Rendu ensuite par `inline_literal` dans le log.
pub fn vanity_change_label(old: Option<&str>, new: Option<&str>) -> String {
    let render = |code: Option<&str>| {
        code.map_or_else(
            || "none".to_owned(),
            |code| defang(&format!("discord.gg/{code}")),
        )
    };
    format!("{}->{}", render(old), render(new))
}

/// Alerte d'un changement de vanity ; `None` si elle n'a pas changé.
pub fn vanity_incident(
    language: Language,
    guild_id: u64,
    old: Option<&str>,
    new: Option<&str>,
    author: AlertAuthor,
) -> Option<SecurityIncident> {
    if !vanity_changed(old, new) {
        return None;
    }
    let mut incident = SecurityIncident::new(
        ProtectionModule::AntiVanityChange.key(),
        LogType::Server,
        if author.is_exempt() {
            LogSeverity::Warning
        } else {
            LogSeverity::Critical
        },
        text(language, TextKey::AntiVanityChangeSummary),
        author.alert_actions(),
    );
    incident.actor = author.actor();
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Server,
        id: Some(guild_id.to_string()),
        name: None,
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::AntiVanityChangeEvidence).to_owned(),
        value: vanity_change_label(old, new),
    });
    incident.recommendation =
        Some(text(language, TextKey::AntiVanityChangeRecommendation).to_owned());
    Some(incident)
}
