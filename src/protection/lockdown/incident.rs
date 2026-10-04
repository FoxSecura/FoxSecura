// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Incident publié à la levée d'un verrouillage.
//!
//! Publié seulement quand la levée change quelque chose pour l'équipe : levée
//! achevée, ou premier échec. Les nouvelles tentatives qui échouent encore ne
//! republient rien (une par minute), elles sont seulement journalisées.

use crate::i18n::{Language, TextKey, text};
use crate::logs::{AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityIncident};

use super::engine::LiftOutcome;
use super::schedule::LockdownStatus;

/// Clé du sous-système dans les incidents.
pub const LOCKDOWN_MODULE: &str = "lockdown";

/// Origine d'une levée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftTrigger {
    /// Échéance ou nouvelle tentative.
    Timer,
    /// Action « Lever le verrouillage » de `/config`.
    Staff,
}

/// Faut-il publier l'incident de cette levée ?
///
/// `previous` : état de la ligne avant la levée (`None` sans ligne).
pub fn should_publish_lift(outcome: &LiftOutcome, previous: Option<LockdownStatus>) -> bool {
    if outcome.nothing_to_do() || outcome.unresolved {
        return false;
    }
    !outcome.pending || previous != Some(LockdownStatus::Retry)
}

/// Incident de type `server` : `info` si tout est restauré, `warning` si des
/// salons restent verrouillés.
pub fn lift_incident(
    language: Language,
    guild_id: u64,
    outcome: &LiftOutcome,
    trigger: LiftTrigger,
) -> SecurityIncident {
    let mut incident = SecurityIncident::new(
        LOCKDOWN_MODULE,
        LogType::Server,
        if outcome.pending {
            LogSeverity::Warning
        } else {
            LogSeverity::Info
        },
        text(
            language,
            match trigger {
                LiftTrigger::Timer => TextKey::LockdownLiftSummary,
                LiftTrigger::Staff => TextKey::LockdownLiftStaffSummary,
            },
        ),
        vec![outcome.action_outcome()],
    );
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Server,
        id: Some(guild_id.to_string()),
        name: None,
    });
    incident.recommendation = Some(
        text(
            language,
            if outcome.pending {
                TextKey::LockdownLiftRecommendationPending
            } else {
                TextKey::LockdownLiftRecommendationDone
            },
        )
        .to_owned(),
    );
    incident
}
