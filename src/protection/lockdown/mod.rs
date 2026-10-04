// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Verrouillage temporaire du serveur (spécification de la V1) : décisions,
//! enchaînement des étapes et échéances, sans effet Discord.
//!
//! Sous-système partagé : l'anti-raid (10 minutes, mode lent de 10 s) et le
//! mode panique de l'anti-nuke (15 minutes, mode lent de 30 s) le posent. La
//! durée et le mode lent sont portés par la requête ([`LockdownRequest`]) ;
//! le mode lent posé est enregistré avec la ligne de verrouillage, et la
//! levée ne rend l'ancien mode lent que si le salon porte encore celui-là. Il suit le modèle de la quarantaine : cœur pur
//! derrière un trait d'effets ([`LockdownEffects`]), état d'origine à trois
//! états enregistré **avant** chaque modification, opérations sérialisées
//! par guilde ([`GuildLocks`]).
//!
//! - [`plan`] : salons verrouillés, état d'origine, restauration exacte ;
//! - [`engine`] : pose et levée, étape par étape ;
//! - [`schedule`] : échéance, reprise au démarrage, minuteries ;
//! - [`incident`] : incident publié à la levée ;
//! - [`locks`] : sérialisation des opérations par guilde.
//!
//! # Coût en appels API
//!
//! Tous les salons portant des overwrites (tous sauf les fils) sont
//! candidats : une lecture de la liste des salons, puis jusqu'à **deux
//! appels par salon** à la pose (refus d'écrire, puis mode lent) et autant à
//! la levée, faits un par un. Un serveur de
//! 500 salons demande donc jusqu'à 1 000 appels dans chaque sens ; pendant
//! une limitation de débit, serenity attend la fin de la fenêtre avant de
//! reprendre, la pose est plus lente mais n'est pas abandonnée.
//!
//! # Limites
//!
//! Les minuteries et les verrous vivent dans le processus (mono-instance) ;
//! l'état d'origine, lui, est en base et survit à un redémarrage.

pub mod engine;
pub mod incident;
pub mod locks;
pub mod plan;
pub mod schedule;

pub use engine::{
    ChannelLockResult, CurrentChannel, DEFAULT_LOCKDOWN_DURATION, LOCKDOWN_RETRY_INTERVAL,
    LiftFacts, LiftOutcome, LockdownEffects, LockdownFacts, LockdownOutcome, LockdownReason,
    LockdownRequest, LockdownStart, PANIC_LOCKDOWN_DURATION, PANIC_LOCKDOWN_SLOWMODE_SECONDS,
    SlowmodeResult, apply_lockdown, lift_lockdown, lock_channel,
};
pub use incident::{LOCKDOWN_MODULE, LiftTrigger, lift_incident, should_publish_lift};
pub use locks::{GuildLockGuard, GuildLocks};
pub use plan::{
    ChannelLockPlan, LOCKDOWN_DENY, LOCKDOWN_SLOWMODE_SECONDS, LockdownChannel,
    MAX_SLOWMODE_SECONDS, RecordedChannel, lock_slowmode, plan_channel_lock, plan_send_restore,
    plan_slowmode_restore,
};
pub use schedule::{
    LockdownState, LockdownStatus, LockdownTimers, WakeAction, resume_plan, wake_action,
};

/// Raison d'audit log de la pose (`FoxSecura Anti-Raid: temporary lockdown`,
/// `FoxSecura Panic Mode: correlated nuke signals detected`).
pub fn lockdown_audit_reason(reason: LockdownReason) -> String {
    let detail = match reason {
        LockdownReason::AntiRaid => "temporary lockdown",
        LockdownReason::PanicMode => "correlated nuke signals detected",
    };
    crate::protection::shared::audit_reason(reason.audit_label(), detail)
}

/// Raison d'audit log de la levée (`FoxSecura Anti-Raid: lockdown restore`).
pub fn lockdown_restore_audit_reason(reason: Option<LockdownReason>) -> String {
    crate::protection::shared::audit_reason(
        reason.unwrap_or(LockdownReason::AntiRaid).audit_label(),
        "lockdown restore",
    )
}
