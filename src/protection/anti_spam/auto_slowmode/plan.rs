// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Pose et levée du mode lent automatique, sans effet Discord.
//!
//! - Pose ([`plan_slowmode`]) : jamais pendant un verrouillage de la guilde
//!   (le verrouillage gère déjà le mode lent de tous les salons), jamais si
//!   le salon a déjà un mode lent d'au moins [`AUTO_SLOWMODE_SECONDS`] (on ne
//!   réduit jamais). L'ancien mode lent est enregistré **avant** la pose.
//! - Rafale qui continue : la levée est repoussée à
//!   `dernier déclenchement + `[`AUTO_SLOWMODE_LIFT_DELAY`] ([`lift_deadline`]).
//! - Levée ([`plan_slowmode_lift`]) : à l'échéance, l'ancien mode lent n'est
//!   rendu que si le salon porte encore celui posé ; un verrouillage actif
//!   repousse la levée de [`AUTO_SLOWMODE_RETRY_INTERVAL`], comme un échec.

use std::time::Duration;

use crate::protection::lockdown::MAX_SLOWMODE_SECONDS;

/// Rafale par salon, tous auteurs confondus : 12 messages…
pub const AUTO_SLOWMODE_THRESHOLD: usize = 12;
/// … en 7 secondes.
pub const AUTO_SLOWMODE_WINDOW: Duration = Duration::from_secs(7);
/// Mode lent posé.
pub const AUTO_SLOWMODE_SECONDS: u16 = 10;
/// Levée 90 s après le dernier déclenchement.
pub const AUTO_SLOWMODE_LIFT_DELAY: Duration = Duration::from_secs(90);
/// Nouvelle tentative de levée après un échec (ou pendant un verrouillage).
pub const AUTO_SLOWMODE_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Mode lent posé par FoxSecura sur un salon, persisté (migration 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoSlowmode {
    pub guild_id: u64,
    pub channel_id: u64,
    /// Mode lent d'origine, en secondes (0 : aucun).
    pub previous_seconds: u16,
    /// Mode lent posé, en secondes.
    pub applied_seconds: u16,
    /// Levée prévue (ou prochaine tentative), en secondes Unix.
    pub lift_at: u64,
}

/// Raison pour laquelle rien n'est posé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowmodeSkip {
    /// Un verrouillage est actif dans la guilde.
    LockdownActive,
    /// Le salon a déjà un mode lent au moins aussi long.
    AlreadySlow { current: u16 },
}

/// Décision de pose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowmodePlan {
    Skip(SlowmodeSkip),
    /// Enregistrer `previous`, puis poser `applied`.
    Apply {
        previous: u16,
        applied: u16,
    },
}

/// Décide de la pose d'après le mode lent actuel du salon (lu par l'API).
pub fn plan_slowmode(current_seconds: u16, lockdown_active: bool) -> SlowmodePlan {
    if lockdown_active {
        return SlowmodePlan::Skip(SlowmodeSkip::LockdownActive);
    }
    if current_seconds >= AUTO_SLOWMODE_SECONDS {
        return SlowmodePlan::Skip(SlowmodeSkip::AlreadySlow {
            current: current_seconds,
        });
    }
    SlowmodePlan::Apply {
        previous: current_seconds.min(MAX_SLOWMODE_SECONDS),
        applied: AUTO_SLOWMODE_SECONDS,
    }
}

/// Échéance de levée pour un déclenchement à `now` (secondes Unix).
pub const fn lift_deadline(now: u64) -> u64 {
    now.saturating_add(AUTO_SLOWMODE_LIFT_DELAY.as_secs())
}

/// Prochaine tentative après un échec ou pendant un verrouillage.
pub const fn retry_deadline(now: u64) -> u64 {
    now.saturating_add(AUTO_SLOWMODE_RETRY_INTERVAL.as_secs())
}

/// État du salon au moment de la levée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowmodeChannel {
    /// Mode lent actuel, en secondes.
    Current(u16),
    /// Le salon n'existe plus.
    Missing,
    /// Lecture impossible (Discord indisponible, permission).
    Unavailable,
}

/// Décision de levée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowmodeLift {
    /// Pas encore échu : rien.
    NotDue,
    /// Repousser à `lift_at` (verrouillage actif, salon illisible).
    Postpone { lift_at: u64 },
    /// Rendre l'ancien mode lent, puis oublier la ligne.
    Restore { seconds: u16 },
    /// L'équipe a changé le mode lent (ou la pose n'a jamais abouti) : ne
    /// rien toucher, oublier la ligne.
    LeaveChanged { current: u16 },
    /// Le salon a disparu : oublier la ligne.
    ChannelMissing,
}

/// Décide de la levée d'une ligne.
pub fn plan_slowmode_lift(
    row: &AutoSlowmode,
    now: u64,
    channel: SlowmodeChannel,
    lockdown_active: bool,
) -> SlowmodeLift {
    if row.lift_at > now {
        return SlowmodeLift::NotDue;
    }
    if lockdown_active {
        return SlowmodeLift::Postpone {
            lift_at: retry_deadline(now),
        };
    }
    match channel {
        SlowmodeChannel::Missing => SlowmodeLift::ChannelMissing,
        SlowmodeChannel::Unavailable => SlowmodeLift::Postpone {
            lift_at: retry_deadline(now),
        },
        SlowmodeChannel::Current(current) if current == row.applied_seconds => {
            SlowmodeLift::Restore {
                seconds: row.previous_seconds,
            }
        }
        SlowmodeChannel::Current(current) => SlowmodeLift::LeaveChanged { current },
    }
}

/// Lignes échues au démarrage ou à un tour de maintenance, par échéance.
pub fn due_rows(rows: &[AutoSlowmode], now: u64) -> Vec<AutoSlowmode> {
    let mut due: Vec<AutoSlowmode> = rows
        .iter()
        .copied()
        .filter(|row| row.lift_at <= now)
        .collect();
    due.sort_unstable_by_key(|row| (row.lift_at, row.guild_id, row.channel_id));
    due
}
