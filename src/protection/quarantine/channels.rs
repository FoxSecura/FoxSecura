// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Salons verrouillés par la quarantaine (V1).
//!
//! Un overwrite est posé sur les **catégories**, les **salons sans
//! catégorie** et les salons **désynchronisés** de leur catégorie. Un salon
//! synchronisé (mêmes overwrites que sa catégorie) hérite de la modification
//! de sa catégorie : Discord la propage lui-même, ce qui économise un appel
//! API par salon.
//!
//! Le verrou du rôle refuse [`ROLE_LOCK_DENY`] ; il est posé à la
//! configuration du rôle, puis sur chaque salon créé. Il ne suffit pas seul :
//! une autorisation d'un autre rôle l'emporte sur le refus d'un rôle, d'où le
//! verrou au niveau du membre (voir `overwrite`).

use poise::serenity_prelude::Permissions;

/// Refus posés pour le rôle de quarantaine (V1).
pub const ROLE_LOCK_DENY: Permissions = Permissions::VIEW_CHANNEL
    .union(Permissions::SEND_MESSAGES)
    .union(Permissions::SEND_MESSAGES_IN_THREADS)
    .union(Permissions::CREATE_PUBLIC_THREADS)
    .union(Permissions::CREATE_PRIVATE_THREADS)
    .union(Permissions::ADD_REACTIONS)
    .union(Permissions::CONNECT)
    .union(Permissions::SPEAK);

/// Cible d'un overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OverwriteTarget {
    Role(u64),
    Member(u64),
}

/// Overwrite d'un salon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overwrite {
    pub target: OverwriteTarget,
    pub allow: Permissions,
    pub deny: Permissions,
}

/// Autorisations et refus d'une cible ; `Permissions::empty()` des deux côtés
/// quand elle n'a pas d'overwrite.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OverwriteBits {
    pub allow: Permissions,
    pub deny: Permissions,
}

impl OverwriteBits {
    pub const fn is_empty(self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// Salon du serveur, d'après le cache (hors fils, qui héritent de leur
/// salon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelFacts {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub is_category: bool,
    pub overwrites: Vec<Overwrite>,
}

impl ChannelFacts {
    /// Overwrite d'une cible dans ce salon.
    pub fn overwrite(&self, target: OverwriteTarget) -> Option<OverwriteBits> {
        self.overwrites
            .iter()
            .find(|overwrite| overwrite.target == target)
            .map(|overwrite| OverwriteBits {
                allow: overwrite.allow,
                deny: overwrite.deny,
            })
    }
}

/// Un salon est synchronisé s'il a exactement les overwrites de sa
/// catégorie, dans n'importe quel ordre.
pub fn is_synced_with(channel: &ChannelFacts, parent: &ChannelFacts) -> bool {
    let mut own = channel.overwrites.clone();
    let mut inherited = parent.overwrites.clone();
    own.sort_by_key(|overwrite| overwrite.target);
    inherited.sort_by_key(|overwrite| overwrite.target);
    own == inherited
}

/// Le salon doit-il recevoir son propre overwrite ?
///
/// Catégorie ou salon sans catégorie : oui. Catégorie inconnue du cache :
/// oui, faute de pouvoir prouver qu'il hérite. Sinon, seulement s'il est
/// désynchronisé.
pub fn is_lockable(channel: &ChannelFacts, parent: Option<&ChannelFacts>) -> bool {
    if channel.is_category || channel.parent_id.is_none() {
        return true;
    }
    parent.is_none_or(|parent| !is_synced_with(channel, parent))
}

/// Salons verrouillables : les catégories d'abord, puis les autres salons
/// verrouillables, par identifiant.
pub fn lockable_channels(channels: &[ChannelFacts]) -> Vec<u64> {
    let parent = |id: u64| channels.iter().find(|channel| channel.id == id);

    let mut lockable: Vec<(bool, u64)> = channels
        .iter()
        .filter(|channel| is_lockable(channel, channel.parent_id.and_then(parent)))
        .map(|channel| (!channel.is_category, channel.id))
        .collect();
    lockable.sort_unstable();
    lockable.into_iter().map(|(_, id)| id).collect()
}

/// Overwrite à poser pour le rôle de quarantaine ; `None` s'il refuse déjà
/// tout [`ROLE_LOCK_DENY`] sans en autoriser une partie (idempotent : aucun
/// appel API).
///
/// Les autres bits de l'overwrite existant sont conservés.
pub fn role_lock_overwrite(current: Option<OverwriteBits>) -> Option<OverwriteBits> {
    let current = current.unwrap_or_default();
    if current.deny.contains(ROLE_LOCK_DENY) && (current.allow & ROLE_LOCK_DENY).is_empty() {
        return None;
    }
    Some(OverwriteBits {
        allow: current.allow - ROLE_LOCK_DENY,
        deny: current.deny | ROLE_LOCK_DENY,
    })
}
