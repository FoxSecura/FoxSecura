// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Clés des modules de protection activables par guilde.
//!
//! La clé est persistée telle quelle (`guild_protection_modules.module_key`) :
//! elle ne doit jamais changer une fois publiée. Seuls les modules réellement
//! branchés au runtime figurent dans l'énumération, pour que `/config` ne
//! puisse pas afficher « actif » un module que le moteur n'applique pas.
//!
//! L'anti-spam par rafales n'y figure pas : son interrupteur et ses seuils
//! restent dans les colonnes `anti_spam_*` de `guild_configs` (migration 2).

use std::error::Error;
use std::fmt;
use std::str::FromStr;

/// Module de protection activable individuellement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectionModule {
    InvisibleCharFilter,
    MaliciousLink,
    AdultLink,
    AntiInvite,
    AntiEveryone,
    AntiMassMention,
}

impl ProtectionModule {
    /// Tous les modules connus.
    pub const ALL: [Self; 6] = [
        Self::InvisibleCharFilter,
        Self::MaliciousLink,
        Self::AdultLink,
        Self::AntiInvite,
        Self::AntiEveryone,
        Self::AntiMassMention,
    ];

    /// Clé stable, persistée en base et utilisée dans les incidents.
    pub const fn key(self) -> &'static str {
        match self {
            Self::InvisibleCharFilter => "invisible_char_filter",
            Self::MaliciousLink => "malicious_link",
            Self::AdultLink => "adult_link",
            Self::AntiInvite => "anti_invite",
            Self::AntiEveryone => "anti_everyone",
            Self::AntiMassMention => "anti_mass_mention",
        }
    }

    /// Retrouve un module à partir de sa clé exacte (sensible à la casse).
    pub fn from_key(key: &str) -> Result<Self, UnknownModuleKey> {
        Self::ALL
            .into_iter()
            .find(|module| module.key() == key)
            .ok_or_else(|| UnknownModuleKey(key.to_owned()))
    }

    const fn bit(self) -> u64 {
        1 << self as u8
    }
}

impl fmt::Display for ProtectionModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.key())
    }
}

impl FromStr for ProtectionModule {
    type Err = UnknownModuleKey;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        Self::from_key(key)
    }
}

/// Clé de module absente de [`ProtectionModule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownModuleKey(pub String);

impl fmt::Display for UnknownModuleKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "module de protection inconnu : {:?}", self.0)
    }
}

impl Error for UnknownModuleKey {}

// Chaque module occupe un bit de `ModuleSet`.
const _: () = assert!(ProtectionModule::ALL.len() <= u64::BITS as usize);

/// Ensemble des modules activés d'une guilde. Vide par défaut : tous les
/// modules sont désactivés tant qu'ils n'ont pas été activés explicitement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ModuleSet(u64);

impl ModuleSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, module: ProtectionModule) -> bool {
        self.0 & module.bit() != 0
    }

    pub fn set(&mut self, module: ProtectionModule, enabled: bool) {
        if enabled {
            self.0 |= module.bit();
        } else {
            self.0 &= !module.bit();
        }
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl FromIterator<ProtectionModule> for ModuleSet {
    fn from_iter<I: IntoIterator<Item = ProtectionModule>>(modules: I) -> Self {
        let mut set = Self::empty();
        for module in modules {
            set.set(module, true);
        }
        set
    }
}
