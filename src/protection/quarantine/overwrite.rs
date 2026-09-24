// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Verrou au niveau du membre : refus de `VIEW_CHANNEL` et `CONNECT` dans
//! l'overwrite du membre, sur chaque salon verrouillable.
//!
//! Un refus au niveau du membre l'emporte sur les autorisations de tous ses
//! rôles, contrairement au refus du rôle de quarantaine. L'état d'origine des
//! deux bits est enregistré **avant** chaque modification, à trois états
//! (autorisé, refusé, absent), puis restauré exactement à la libération.
//! Les autres bits de l'overwrite ne sont jamais écrits.

use poise::serenity_prelude::Permissions;

use super::channels::OverwriteBits;

/// Bits refusés au membre mis en quarantaine.
pub const MEMBER_LOCK_DENY: Permissions = Permissions::VIEW_CHANNEL.union(Permissions::CONNECT);

/// État d'un bit dans un overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionState {
    Allow,
    Deny,
    Unset,
}

impl PermissionState {
    /// État d'un bit ; `Unset` sans overwrite.
    pub fn of(overwrite: Option<OverwriteBits>, permission: Permissions) -> Self {
        let bits = overwrite.unwrap_or_default();
        if bits.deny.contains(permission) {
            Self::Deny
        } else if bits.allow.contains(permission) {
            Self::Allow
        } else {
            Self::Unset
        }
    }

    /// Valeur persistée (`guild_quarantine_overwrites`).
    pub const fn key(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Unset => "unset",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "unset" => Some(Self::Unset),
            _ => None,
        }
    }

    /// Applique cet état à un bit, sans toucher aux autres.
    fn apply(self, bits: OverwriteBits, permission: Permissions) -> OverwriteBits {
        let (allow, deny) = (bits.allow - permission, bits.deny - permission);
        match self {
            Self::Allow => OverwriteBits {
                allow: allow | permission,
                deny,
            },
            Self::Deny => OverwriteBits {
                allow,
                deny: deny | permission,
            },
            Self::Unset => OverwriteBits { allow, deny },
        }
    }
}

/// État d'origine des deux bits verrouillés, enregistré avant la
/// modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedOverwrite {
    pub view: PermissionState,
    pub connect: PermissionState,
}

impl RecordedOverwrite {
    /// Relève l'état actuel ; sans overwrite, les deux bits sont absents.
    pub fn capture(current: Option<OverwriteBits>) -> Self {
        Self {
            view: PermissionState::of(current, Permissions::VIEW_CHANNEL),
            connect: PermissionState::of(current, Permissions::CONNECT),
        }
    }
}

/// Suite donnée à un salon verrouillable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberLockPlan {
    /// Les deux bits sont déjà refusés et aucune ligne n'existe : ce refus
    /// existait avant la quarantaine. Rien n'est modifié ni enregistré, il
    /// survivra à la libération.
    PreexistingDeny,
    /// Une ligne existe (libération inachevée) et les deux bits sont
    /// refusés : déjà verrouillé, la ligne d'origine est conservée.
    AlreadyLocked,
    /// Enregistrer `record` (`None` : garder la ligne existante, qui porte le
    /// vrai état d'origine), puis écrire `overwrite`.
    Lock {
        record: Option<RecordedOverwrite>,
        overwrite: OverwriteBits,
    },
}

/// Décide du verrou d'un salon d'après l'overwrite actuel du membre et la
/// ligne éventuellement enregistrée.
pub fn plan_member_lock(
    current: Option<OverwriteBits>,
    recorded: Option<RecordedOverwrite>,
) -> MemberLockPlan {
    let bits = current.unwrap_or_default();
    let denied = bits.deny.contains(MEMBER_LOCK_DENY);
    match (recorded, denied) {
        (None, true) => MemberLockPlan::PreexistingDeny,
        (Some(_), true) => MemberLockPlan::AlreadyLocked,
        (recorded, false) => MemberLockPlan::Lock {
            record: recorded
                .is_none()
                .then(|| RecordedOverwrite::capture(current)),
            overwrite: OverwriteBits {
                allow: bits.allow - MEMBER_LOCK_DENY,
                deny: bits.deny | MEMBER_LOCK_DENY,
            },
        },
    }
}

/// Suite donnée à un salon enregistré, à la libération.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePlan {
    /// L'overwrite est déjà dans l'état d'origine : aucun appel API.
    Unchanged,
    /// Écrire l'overwrite restauré.
    Write(OverwriteBits),
    /// L'overwrite restauré est vide : le supprimer (« absent redevient
    /// absent »).
    Delete,
}

/// Restaure exactement les deux bits enregistrés sur l'overwrite actuel ;
/// les autres bits sont conservés tels quels.
pub fn plan_restore(current: Option<OverwriteBits>, recorded: RecordedOverwrite) -> RestorePlan {
    let bits = current.unwrap_or_default();
    let restored = recorded.connect.apply(
        recorded.view.apply(bits, Permissions::VIEW_CHANNEL),
        Permissions::CONNECT,
    );

    match current {
        Some(current) if current == restored => RestorePlan::Unchanged,
        None if restored.is_empty() => RestorePlan::Unchanged,
        _ if restored.is_empty() => RestorePlan::Delete,
        _ => RestorePlan::Write(restored),
    }
}
