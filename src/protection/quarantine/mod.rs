// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Quarantaine d'un membre (spécification de la V1) : décisions et
//! enchaînement des étapes, sans effet Discord.
//!
//! - [`role`] : rôle de quarantaine (création, sélection, permissions
//!   dangereuses) ;
//! - [`channels`] : salons verrouillés et verrou du rôle ;
//! - [`overwrite`] : verrou au niveau du membre, état d'origine à trois états ;
//! - [`engine`] : mise en quarantaine, étape par étape ;
//! - [`locks`] : sérialisation des opérations par membre ;
//! - [`failure`] : échecs des appels Discord.

pub mod channels;
pub mod engine;
pub mod failure;
pub mod locks;
pub mod overwrite;
pub mod role;

pub use channels::{
    ChannelFacts, Overwrite, OverwriteBits, OverwriteTarget, ROLE_LOCK_DENY, is_lockable,
    is_synced_with, lockable_channels, role_lock_overwrite,
};
pub use engine::{
    ChannelLockResult, ChannelLockSummary, DEFAULT_QUARANTINE_TIMEOUT, DangerousRoleRemoval,
    MemberChannel, QuarantineEffects, QuarantineFacts, QuarantineOutcome, QuarantineRequest,
    QuarantineRoleLookup, QuarantineSkip, RoleBlock, RoleStatus, StoreError, classify_role_failure,
    lock_member_channel, plan_dangerous_role_removal, precheck_quarantine_role, quarantine_guard,
    quarantine_member,
};
pub use failure::{DiscordFailure, UNKNOWN_CHANNEL, UNKNOWN_MEMBER, UNKNOWN_ROLE};
pub use locks::{MemberLockGuard, MemberLocks};
pub use overwrite::{
    MEMBER_LOCK_DENY, MemberLockPlan, PermissionState, RecordedOverwrite, RestorePlan,
    plan_member_lock, plan_restore,
};
pub use role::{
    BotRoleStanding, DANGEROUS_PERMISSIONS, QUARANTINE_AUDIT_LABEL, QUARANTINE_ROLE_NAME,
    QuarantineRoleRefusal, RoleFacts, bot_assigned_roles, quarantine_role_position,
    validate_quarantine_role,
};
