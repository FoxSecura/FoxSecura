// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Seuil minimal accepté : une seule arrivée ne fait pas une rafale.
pub const MIN_JOIN_THRESHOLD: u32 = 2;
/// Seuil maximal accepté.
pub const MAX_JOIN_THRESHOLD: u32 = 50;
/// Fenêtre minimale acceptée, en secondes.
pub const MIN_JOIN_WINDOW_SECONDS: u32 = 5;
/// Fenêtre maximale acceptée, en secondes.
pub const MAX_JOIN_WINDOW_SECONDS: u32 = 120;

/// Seuil par défaut (V1) : 5 arrivées…
pub const DEFAULT_JOIN_THRESHOLD: u32 = 5;
/// … en 20 secondes.
pub const DEFAULT_JOIN_WINDOW_SECONDS: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinBurstConfig {
    pub enabled: bool,
    pub threshold: usize,
    pub window: Duration,
}

impl JoinBurstConfig {
    pub const fn new(enabled: bool, threshold: usize, window: Duration) -> Self {
        Self {
            enabled,
            threshold: if threshold == 0 { 1 } else { threshold },
            window,
        }
    }
}

impl Default for JoinBurstConfig {
    fn default() -> Self {
        Self::new(
            false,
            DEFAULT_JOIN_THRESHOLD as usize,
            Duration::from_secs(DEFAULT_JOIN_WINDOW_SECONDS as u64),
        )
    }
}

/// Réglages persistés de l'anti-raid d'une guilde (migration 8).
///
/// Déclenchement quand le nombre d'arrivées dans la fenêtre atteint le seuil
/// (`count >= threshold`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinBurstLimits {
    pub threshold: u32,
    pub window_seconds: u32,
}

impl JoinBurstLimits {
    /// Refuse les valeurs hors bornes (2 à 50 arrivées, 5 à 120 secondes).
    pub fn validated(threshold: u32, window_seconds: u32) -> Result<Self, JoinBurstLimitsError> {
        if !(MIN_JOIN_THRESHOLD..=MAX_JOIN_THRESHOLD).contains(&threshold) {
            return Err(JoinBurstLimitsError::ThresholdOutOfRange(threshold));
        }
        if !(MIN_JOIN_WINDOW_SECONDS..=MAX_JOIN_WINDOW_SECONDS).contains(&window_seconds) {
            return Err(JoinBurstLimitsError::WindowOutOfRange(window_seconds));
        }
        Ok(Self {
            threshold,
            window_seconds,
        })
    }

    pub const fn window(self) -> Duration {
        Duration::from_secs(self.window_seconds as u64)
    }

    /// Configuration du détecteur.
    pub const fn config(self, enabled: bool) -> JoinBurstConfig {
        JoinBurstConfig::new(enabled, self.threshold as usize, self.window())
    }
}

impl Default for JoinBurstLimits {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_JOIN_THRESHOLD,
            window_seconds: DEFAULT_JOIN_WINDOW_SECONDS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinBurstLimitsError {
    ThresholdOutOfRange(u32),
    WindowOutOfRange(u32),
}

impl fmt::Display for JoinBurstLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThresholdOutOfRange(value) => write!(
                formatter,
                "seuil anti-raid invalide : {value} (attendu entre {MIN_JOIN_THRESHOLD} et {MAX_JOIN_THRESHOLD})"
            ),
            Self::WindowOutOfRange(value) => write!(
                formatter,
                "fenêtre anti-raid invalide : {value} s (attendu entre {MIN_JOIN_WINDOW_SECONDS} et {MAX_JOIN_WINDOW_SECONDS})"
            ),
        }
    }
}

impl Error for JoinBurstLimitsError {}
