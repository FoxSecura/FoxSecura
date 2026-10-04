// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Famille des protections contre les actions destructrices et les nukes serveur.
//!
//! - [`audit`] : socle des journaux d'audit (gardes, dédoublonnage,
//!   classement des entrées).
//!
//! Les modules de détection hérités de l'archive (`server_integrity`,
//! suppressions de salons et de rôles, `limit_role`) ne sont pas branchés :
//! ils restent un socle pour la tranche suivante.

mod action_guard;

pub mod audit;

pub mod limit_role;
pub mod member_actions;
pub mod panic_mode;
pub mod resource_actions;
pub mod server_integrity;

pub use action_guard::{
    ExecutorDecision, NukeActionInput, NukeActionSpec, detect_nuke_action, evaluate_executor_action,
};

use crate::protection::shared::{ModuleSet, ProtectionModule};

use audit::NukeAction;

/// Modules de rafales de l'anti-nuke (hors mode panique).
pub const NUKE_MODULES: [ProtectionModule; 8] = [
    ProtectionModule::AntiMassBan,
    ProtectionModule::AntiMassKick,
    ProtectionModule::AntiMassTimeout,
    ProtectionModule::AntiMassUnban,
    ProtectionModule::AntiMassChannelCreate,
    ProtectionModule::AntiMassRoleCreate,
    ProtectionModule::AntiEmojiStickerNuke,
    ProtectionModule::AntiMassRoleGrant,
];

impl NukeAction {
    /// Module qui compte cette action.
    pub const fn module(self) -> ProtectionModule {
        match self {
            Self::Ban => ProtectionModule::AntiMassBan,
            Self::Kick => ProtectionModule::AntiMassKick,
            Self::Timeout => ProtectionModule::AntiMassTimeout,
            Self::Unban => ProtectionModule::AntiMassUnban,
            Self::ChannelCreate => ProtectionModule::AntiMassChannelCreate,
            Self::RoleCreate => ProtectionModule::AntiMassRoleCreate,
            Self::EmojiSticker => ProtectionModule::AntiEmojiStickerNuke,
            Self::RoleGrant => ProtectionModule::AntiMassRoleGrant,
        }
    }
}

/// Au moins un module de rafales de l'anti-nuke est actif.
pub fn is_anti_nuke_enabled(modules: ModuleSet) -> bool {
    NUKE_MODULES.iter().any(|module| modules.contains(*module))
}
