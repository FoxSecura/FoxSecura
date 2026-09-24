// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Quarantaine d'un membre (spécification de la V1) : décisions et
//! enchaînement des étapes, sans effet Discord.
//!
//! - [`role`] : rôle de quarantaine (création, sélection, permissions
//!   dangereuses) ;
//! - [`channels`] : salons verrouillés et verrou du rôle ;
//! - [`failure`] : échecs des appels Discord.

pub mod channels;
pub mod failure;
pub mod role;

pub use channels::{
    ChannelFacts, Overwrite, OverwriteBits, OverwriteTarget, ROLE_LOCK_DENY, is_lockable,
    is_synced_with, lockable_channels, role_lock_overwrite,
};
pub use failure::{DiscordFailure, UNKNOWN_CHANNEL, UNKNOWN_MEMBER, UNKNOWN_ROLE};
pub use role::{
    BotRoleStanding, DANGEROUS_PERMISSIONS, QUARANTINE_AUDIT_LABEL, QUARANTINE_ROLE_NAME,
    QuarantineRoleRefusal, RoleFacts, bot_assigned_roles, quarantine_role_position,
    validate_quarantine_role,
};
