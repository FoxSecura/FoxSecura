// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Seuil minimal accepté : un seul message ne peut pas constituer une rafale.
pub const MIN_MESSAGE_THRESHOLD: u32 = 2;
/// Seuil maximal accepté.
pub const MAX_MESSAGE_THRESHOLD: u32 = 50;
/// Fenêtre minimale acceptée, en secondes.
pub const MIN_WINDOW_SECONDS: u32 = 1;
/// Fenêtre maximale acceptée, en secondes.
pub const MAX_WINDOW_SECONDS: u32 = 60;

pub const DEFAULT_MESSAGE_THRESHOLD: u32 = 5;
pub const DEFAULT_WINDOW_SECONDS: u32 = 5;

/// Configuration anti-spam d'une guilde.
///
/// La protection se déclenche lorsque le nombre de messages d'un membre dans
/// la fenêtre atteint le seuil (`count >= message_threshold`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageFloodConfig {
    pub enabled: bool,
    pub message_threshold: u32,
    pub window_seconds: u32,
}

impl MessageFloodConfig {
    /// Construit une configuration sans valider les bornes.
    pub const fn new(enabled: bool, message_threshold: u32, window_seconds: u32) -> Self {
        Self {
            enabled,
            message_threshold,
            window_seconds,
        }
    }

    /// Construit une configuration en refusant les valeurs hors bornes.
    pub fn validated(
        enabled: bool,
        message_threshold: u32,
        window_seconds: u32,
    ) -> Result<Self, MessageFloodConfigError> {
        let config = Self::new(enabled, message_threshold, window_seconds);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), MessageFloodConfigError> {
        if !(MIN_MESSAGE_THRESHOLD..=MAX_MESSAGE_THRESHOLD).contains(&self.message_threshold) {
            return Err(MessageFloodConfigError::MessageThresholdOutOfRange(
                self.message_threshold,
            ));
        }

        if !(MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&self.window_seconds) {
            return Err(MessageFloodConfigError::WindowOutOfRange(
                self.window_seconds,
            ));
        }

        Ok(())
    }

    pub const fn window(&self) -> Duration {
        Duration::from_secs(self.window_seconds as u64)
    }
}

impl Default for MessageFloodConfig {
    fn default() -> Self {
        Self::new(false, DEFAULT_MESSAGE_THRESHOLD, DEFAULT_WINDOW_SECONDS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageFloodConfigError {
    MessageThresholdOutOfRange(u32),
    WindowOutOfRange(u32),
}

impl fmt::Display for MessageFloodConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageThresholdOutOfRange(value) => write!(
                formatter,
                "seuil anti-spam invalide : {value} (attendu entre {MIN_MESSAGE_THRESHOLD} et {MAX_MESSAGE_THRESHOLD})"
            ),
            Self::WindowOutOfRange(value) => write!(
                formatter,
                "fenêtre anti-spam invalide : {value} s (attendu entre {MIN_WINDOW_SECONDS} et {MAX_WINDOW_SECONDS})"
            ),
        }
    }
}

impl Error for MessageFloodConfigError {}
