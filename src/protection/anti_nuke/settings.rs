// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Seuils de l'anti-nuke et du mode panique, persistés par guilde
//! (migration 9).
//!
//! Valeurs de la V1 :
//!
//! | Module | Seuil par défaut | Bornes | Fenêtre |
//! |---|---|---|---|
//! | `anti_mass_ban` | 3 | 2 à 20 | 20 s |
//! | `anti_mass_kick` | 3 | fixe | 30 s |
//! | `anti_mass_timeout` | 3 | fixe | 30 s |
//! | `anti_mass_unban` | 5 | 2 à 20 | 20 s |
//! | `anti_mass_channel_create` / `anti_mass_role_create` | 5 (partagé) | 2 à 20 | 20 s |
//! | `anti_emoji_sticker_nuke` | 5 | 2 à 20 | 20 s |
//! | `anti_mass_role_grant` | 5 | 2 à 20 | 20 s |
//! | mode panique (types distincts) | 3 | 2 à 10 | 30 s |

use std::error::Error;
use std::fmt;
use std::ops::RangeInclusive;

use super::audit::NukeAction;

/// Bornes d'un seuil de rafale réglable.
pub const NUKE_THRESHOLD_RANGE: RangeInclusive<u8> = 2..=20;
/// Bornes du seuil du mode panique (types de modules distincts).
pub const PANIC_THRESHOLD_RANGE: RangeInclusive<u8> = 2..=10;

/// Seuil fixe des expulsions et des exclusions temporaires (V1).
pub const FIXED_MEMBER_ACTION_THRESHOLD: u8 = 3;
pub const DEFAULT_BAN_THRESHOLD: u8 = 3;
pub const DEFAULT_UNBAN_THRESHOLD: u8 = 5;
pub const DEFAULT_CREATE_THRESHOLD: u8 = 5;
pub const DEFAULT_EMOJI_STICKER_THRESHOLD: u8 = 5;
pub const DEFAULT_ROLE_GRANT_THRESHOLD: u8 = 5;
pub const DEFAULT_PANIC_THRESHOLD: u8 = 3;

/// Seuils réglables des rafales.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiNukeThresholds {
    pub ban: u8,
    pub unban: u8,
    /// Partagé par les créations de salons et de rôles (V1).
    pub create: u8,
    pub emoji_sticker: u8,
    pub role_grant: u8,
}

impl Default for AntiNukeThresholds {
    fn default() -> Self {
        Self {
            ban: DEFAULT_BAN_THRESHOLD,
            unban: DEFAULT_UNBAN_THRESHOLD,
            create: DEFAULT_CREATE_THRESHOLD,
            emoji_sticker: DEFAULT_EMOJI_STICKER_THRESHOLD,
            role_grant: DEFAULT_ROLE_GRANT_THRESHOLD,
        }
    }
}

impl AntiNukeThresholds {
    /// Refuse un seuil hors bornes (2 à 20).
    pub fn validated(self) -> Result<Self, AntiNukeSettingsError> {
        for value in [
            self.ban,
            self.unban,
            self.create,
            self.emoji_sticker,
            self.role_grant,
        ] {
            if !NUKE_THRESHOLD_RANGE.contains(&value) {
                return Err(AntiNukeSettingsError::ThresholdOutOfRange(value));
            }
        }
        Ok(self)
    }

    /// Seuil appliqué à une action ; fixe pour les expulsions et les
    /// exclusions temporaires.
    pub const fn for_action(self, action: NukeAction) -> u8 {
        match action {
            NukeAction::Ban => self.ban,
            NukeAction::Kick | NukeAction::Timeout => FIXED_MEMBER_ACTION_THRESHOLD,
            NukeAction::Unban => self.unban,
            NukeAction::ChannelCreate | NukeAction::RoleCreate => self.create,
            NukeAction::EmojiSticker => self.emoji_sticker,
            NukeAction::RoleGrant => self.role_grant,
        }
    }
}

/// Réglages persistés de l'anti-nuke d'une guilde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiNukeSettings {
    pub thresholds: AntiNukeThresholds,
    /// Types de modules distincts qui déclenchent le mode panique.
    pub panic_threshold: u8,
}

impl Default for AntiNukeSettings {
    fn default() -> Self {
        Self {
            thresholds: AntiNukeThresholds::default(),
            panic_threshold: DEFAULT_PANIC_THRESHOLD,
        }
    }
}

impl AntiNukeSettings {
    /// Refuse toute valeur hors bornes.
    pub fn validated(self) -> Result<Self, AntiNukeSettingsError> {
        self.thresholds.validated()?;
        validate_panic_threshold(self.panic_threshold)?;
        Ok(self)
    }
}

/// Refuse un seuil de mode panique hors bornes (2 à 10).
pub fn validate_panic_threshold(value: u8) -> Result<u8, AntiNukeSettingsError> {
    if PANIC_THRESHOLD_RANGE.contains(&value) {
        Ok(value)
    } else {
        Err(AntiNukeSettingsError::PanicThresholdOutOfRange(value))
    }
}

/// Valeur hors bornes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiNukeSettingsError {
    ThresholdOutOfRange(u8),
    PanicThresholdOutOfRange(u8),
}

impl fmt::Display for AntiNukeSettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThresholdOutOfRange(value) => write!(
                formatter,
                "seuil de l'anti-nuke invalide : {value} (attendu : {} à {})",
                NUKE_THRESHOLD_RANGE.start(),
                NUKE_THRESHOLD_RANGE.end()
            ),
            Self::PanicThresholdOutOfRange(value) => write!(
                formatter,
                "seuil du mode panique invalide : {value} (attendu : {} à {})",
                PANIC_THRESHOLD_RANGE.start(),
                PANIC_THRESHOLD_RANGE.end()
            ),
        }
    }
}

impl Error for AntiNukeSettingsError {}
