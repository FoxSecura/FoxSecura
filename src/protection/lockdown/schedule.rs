// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Échéance, reprise et minuteries d'un verrouillage.
//!
//! Une ligne de verrouillage porte son état ([`LockdownStatus`]) et sa date
//! de levée (secondes Unix, horloge murale). La minuterie d'une guilde se
//! réveille au plus tard toutes les [`LOCKDOWN_RETRY_INTERVAL`] et relit la
//! ligne ([`wake_action`]) : une levée manuelle, une nouvelle tentative
//! repoussée ou un changement d'horloge (mise en veille, NTP) sont ainsi pris
//! en compte sans état supplémentaire.
//!
//! Au démarrage, les verrouillages persistés sont relus ([`resume_plan`]) :
//! ceux qui ont expiré (ou dont la levée a été interrompue) sont levés tout
//! de suite, les autres sont réarmés.
//!
//! [`LockdownTimers`] garantit au plus une minuterie par guilde.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::engine::{LOCKDOWN_RETRY_INTERVAL, LockdownReason};

/// État d'une ligne de verrouillage, persisté (`guild_lockdowns.status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownStatus {
    /// Posé, levée prévue à `lift_at`.
    Active,
    /// Levée en cours (ou interrompue par un arrêt du bot).
    Lifting,
    /// Levée inachevée, nouvelle tentative à `lift_at`.
    Retry,
}

impl LockdownStatus {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Lifting => "lifting",
            Self::Retry => "retry",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "active" => Some(Self::Active),
            "lifting" => Some(Self::Lifting),
            "retry" => Some(Self::Retry),
            _ => None,
        }
    }
}

/// Verrouillage persisté d'une guilde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockdownState {
    pub guild_id: u64,
    /// `None` : raison écrite par une version plus récente.
    pub reason: Option<LockdownReason>,
    pub status: LockdownStatus,
    /// Levée prévue, ou prochaine tentative, en secondes Unix.
    pub lift_at: u64,
}

/// Suite donnée au réveil d'une minuterie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeAction {
    /// Plus de verrouillage : la minuterie s'arrête.
    Stop,
    /// Échéance atteinte (ou levée interrompue) : lever maintenant.
    Lift,
    /// Attendre, puis relire la ligne.
    Sleep(Duration),
}

/// Décide du réveil d'une minuterie d'après la ligne relue.
///
/// L'attente est bornée à [`LOCKDOWN_RETRY_INTERVAL`] : une ligne modifiée
/// entre-temps est relue au plus tard une minute après.
pub fn wake_action(now: u64, state: Option<&LockdownState>) -> WakeAction {
    match state {
        None => WakeAction::Stop,
        // Levée interrompue par un arrêt : reprise immédiate.
        Some(state) if state.status == LockdownStatus::Lifting || state.lift_at <= now => {
            WakeAction::Lift
        }
        Some(state) => {
            WakeAction::Sleep(Duration::from_secs(state.lift_at - now).min(LOCKDOWN_RETRY_INTERVAL))
        }
    }
}

/// Reprise au démarrage : levée immédiate des verrouillages expirés,
/// réarmement des autres.
pub fn resume_plan(now: u64, states: &[LockdownState]) -> Vec<(u64, WakeAction)> {
    states
        .iter()
        .map(|state| (state.guild_id, wake_action(now, Some(state))))
        .collect()
}

/// Guildes dont la minuterie tourne : au plus une par guilde.
///
/// Protocole (sans perte de réveil) : la pose écrit sa ligne **puis** appelle
/// [`try_arm`](Self::try_arm) ; une minuterie qui s'arrête appelle
/// [`disarm`](Self::disarm) **puis** relit la ligne une dernière fois et, si
/// elle existe encore, se réarme avec `try_arm`. Une pose concurrente
/// démarre donc toujours une minuterie, ou est vue par celle qui s'arrête.
#[derive(Debug, Default)]
pub struct LockdownTimers {
    armed: Mutex<HashSet<u64>>,
}

impl LockdownTimers {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` si aucune minuterie ne tournait : l'appelant doit en démarrer
    /// une.
    pub fn try_arm(&self, guild_id: u64) -> bool {
        self.armed().insert(guild_id)
    }

    pub fn disarm(&self, guild_id: u64) {
        self.armed().remove(&guild_id);
    }

    pub fn is_armed(&self, guild_id: u64) -> bool {
        self.armed().contains(&guild_id)
    }

    /// Un verrou empoisonné est récupéré : l'ensemble ne contient que des
    /// identifiants.
    fn armed(&self) -> MutexGuard<'_, HashSet<u64>> {
        self.armed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
