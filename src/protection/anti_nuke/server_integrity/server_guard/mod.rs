// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Primitives de détection utilisées par les protections Anti-Nuke liées à un exécuteur.

use poise::serenity_prelude::Permissions;

pub use crate::protection::shared::{
    ActionBurstDetector, ActionBurstDetectorConfig, ActionBurstInput, ActionBurstResult,
};

pub fn detect_dangerous_permission_change(
    old_permissions: Permissions,
    new_permissions: Permissions,
) -> bool {
    let added = new_permissions & !old_permissions;
    let dangerous = Permissions::ADMINISTRATOR
        | Permissions::MANAGE_GUILD
        | Permissions::MANAGE_ROLES
        | Permissions::MANAGE_CHANNELS
        | Permissions::MANAGE_WEBHOOKS
        | Permissions::BAN_MEMBERS
        | Permissions::KICK_MEMBERS
        | Permissions::MODERATE_MEMBERS
        | Permissions::MENTION_EVERYONE;

    !(added & dangerous).is_empty()
}
