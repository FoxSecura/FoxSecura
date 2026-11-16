// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-ghost-ping (V1) : un message récent qui mentionne au moins 5
//! utilisateurs ou rôles, puis disparaît (suppression) ou perd ses mentions
//! (modification) dans les 5 minutes, est un ghost ping de masse.
//!
//! - [`AntiGhostPingDetector`] : suivi borné (5 000 messages, 5 000 auteurs,
//!   5 minutes) et récidive (2 en 10 minutes) ; un message produit au plus un
//!   incident (il quitte le suivi au premier déclenchement).
//! - [`BotDeletionMarks`] : les suppressions de FoxSecura ne comptent jamais.
//! - [`plan_ghost_ping_follow_up`] et [`ghost_ping_incident`] : réponse.
//!
//! Salon ignoré, bots, webhooks et auteurs de la liste blanche ne sont jamais
//! suivis. État mono-instance, perdu au redémarrage.

mod detector;
mod marks;
mod response;

pub use detector::{
    AntiGhostPingDetector, AntiGhostPingDetectorConfig, GhostPingDetectionResult, GhostPingMessage,
};
pub use marks::{BOT_DELETION_MARK_TTL, BotDeletionMarks, MAX_BOT_DELETION_MARKS};
pub use response::{
    ANTI_GHOST_PING_REPEAT_REASON, GHOST_PING_MEMORY, GHOST_PING_MENTION_THRESHOLD,
    GHOST_PING_REPEAT_THRESHOLD, GHOST_PING_REPEAT_TIMEOUT, GHOST_PING_REPEAT_WINDOW,
    GhostPingEvent, GhostPingFollowUp, GhostPingIncidentInput, GhostPingOutcome,
    MAX_GHOST_PING_TARGETS, ghost_ping_incident, plan_ghost_ping_follow_up,
};
