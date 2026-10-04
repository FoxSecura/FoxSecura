// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Socle des journaux d'audit : entrées poussées par Discord
//! (`GUILD_AUDIT_LOG_ENTRY_CREATE`), gardes et classement, sans effet
//! Discord.
//!
//! La V1 interrogeait le journal d'audit après coup pour retrouver l'auteur
//! d'une action. La V2 consomme l'événement poussé, qui porte directement
//! l'auteur, l'action, la cible, les changements et la raison : aucune
//! corrélation approximative, aucun appel à l'API.
//!
//! # Prérequis
//!
//! L'intent `GUILD_MODERATION` et la permission `VIEW_AUDIT_LOG`. Sans cette
//! permission, Discord n'envoie **aucune** entrée : l'anti-nuke est aveugle
//! sans erreur visible. Le runtime le signale une fois par guilde dans les
//! logs locaux ([`should_warn_missing_audit_permission`]).
//!
//! # Gardes ([`screen_entry`])
//!
//! Dans l'ordre : entrée de plus de [`MAX_AUDIT_ENTRY_AGE`] (rejeu après une
//! reconnexion, l'âge se déduit du snowflake) → entrée déjà traitée
//! ([`AuditEntryDedup`], bornée) → sans auteur → propriétaire du serveur →
//! bot lui-même.
//!
//! Ignorer le bot couvre toutes ses propres sanctions (quarantaines, bans de
//! la liste noire, verrouillages). Défense en profondeur : une entrée du bot
//! dont la raison suit la convention de FoxSecura
//! ([`is_foxsecura_audit_reason`]) est classée à part
//! ([`AuditIgnoreReason::FoxSecuraAction`]) et n'est jamais comptée. La
//! raison seule ne prouve rien (n'importe quel modérateur peut l'écrire) :
//! elle ne sert qu'avec l'auteur.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use crate::protection::shared::{is_foxsecura_audit_reason, snowflake_timestamp};

/// Âge maximal d'une entrée traitée : au-delà, c'est un rejeu après une
/// reconnexion, l'attaque éventuelle est déjà passée.
pub const MAX_AUDIT_ENTRY_AGE: Duration = Duration::from_secs(5 * 60);

/// Identifiants d'entrées retenus par défaut pour le dédoublonnage.
pub const DEFAULT_AUDIT_DEDUP_CAPACITY: usize = 10_000;

/// Type d'entrée du journal d'audit utile à l'anti-nuke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    MemberBanAdd,
    MemberBanRemove,
    MemberKick,
    MemberUpdate,
    MemberRoleUpdate,
    ChannelCreate,
    RoleCreate,
    EmojiCreate,
    EmojiDelete,
    StickerCreate,
    StickerDelete,
    /// Tout autre type d'entrée : jamais compté par cette tranche.
    Other,
}

/// Entrée du journal d'audit, convertie depuis l'événement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Snowflake de l'entrée : identifiant et date de création.
    pub entry_id: u64,
    pub guild_id: u64,
    /// Auteur de l'action ; `None` si Discord n'en donne pas.
    pub author_id: Option<u64>,
    pub action: AuditAction,
    pub target_id: Option<u64>,
    /// Nom de la cible créée (salon, rôle), d'après les changements. Valeur
    /// non fiable : rendue par `inline_literal` dans les logs.
    pub target_name: Option<String>,
    pub reason: Option<String>,
    /// Changement de `communication_disabled_until` : `None` si la clé est
    /// absente, `Some(None)` si le timeout est levé, `Some(Some(t))` pour un
    /// timeout jusqu'à `t` (durée depuis l'époque Unix).
    pub timeout_until: Option<Option<Duration>>,
    /// Rôles ajoutés (clé de changement `$add`).
    pub roles_added: usize,
}

impl AuditEntry {
    /// Entrée sans changement, pour une action donnée.
    pub fn new(entry_id: u64, guild_id: u64, author_id: Option<u64>, action: AuditAction) -> Self {
        Self {
            entry_id,
            guild_id,
            author_id,
            action,
            target_id: None,
            target_name: None,
            reason: None,
            timeout_until: None,
            roles_added: 0,
        }
    }

    /// Date de création de l'entrée, d'après son snowflake.
    pub fn created_at(&self) -> Duration {
        snowflake_timestamp(self.entry_id)
    }
}

/// Action destructrice comptée par l'anti-nuke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NukeAction {
    Ban,
    Kick,
    Timeout,
    Unban,
    ChannelCreate,
    RoleCreate,
    /// Création ou suppression d'un emoji ou d'un sticker (une seule clé).
    EmojiSticker,
    RoleGrant,
}

impl NukeAction {
    pub const ALL: [Self; 8] = [
        Self::Ban,
        Self::Kick,
        Self::Timeout,
        Self::Unban,
        Self::ChannelCreate,
        Self::RoleCreate,
        Self::EmojiSticker,
        Self::RoleGrant,
    ];
}

/// Classe une entrée ; `None` si elle n'est pas comptée.
///
/// - `MemberUpdate` : seulement si `communication_disabled_until` passe à une
///   date postérieure à l'entrée (pose d'un timeout). La levée d'un timeout
///   ne compte pas.
/// - `MemberRoleUpdate` : seulement si au moins un rôle est **ajouté** ; les
///   retraits ne comptent pas.
pub fn classify_entry(entry: &AuditEntry) -> Option<NukeAction> {
    match entry.action {
        AuditAction::MemberBanAdd => Some(NukeAction::Ban),
        AuditAction::MemberKick => Some(NukeAction::Kick),
        AuditAction::MemberBanRemove => Some(NukeAction::Unban),
        AuditAction::MemberUpdate => match entry.timeout_until {
            Some(Some(until)) if until > entry.created_at() => Some(NukeAction::Timeout),
            _ => None,
        },
        AuditAction::MemberRoleUpdate => (entry.roles_added > 0).then_some(NukeAction::RoleGrant),
        AuditAction::ChannelCreate => Some(NukeAction::ChannelCreate),
        AuditAction::RoleCreate => Some(NukeAction::RoleCreate),
        AuditAction::EmojiCreate
        | AuditAction::EmojiDelete
        | AuditAction::StickerCreate
        | AuditAction::StickerDelete => Some(NukeAction::EmojiSticker),
        AuditAction::Other => None,
    }
}

/// Raison pour laquelle une entrée n'est pas traitée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditIgnoreReason {
    /// Plus de [`MAX_AUDIT_ENTRY_AGE`] : rejeu après une reconnexion.
    TooOld,
    /// Entrée déjà traitée.
    Duplicate,
    /// Discord ne donne pas d'auteur.
    NoAuthor,
    /// Le propriétaire du serveur n'est jamais compté.
    GuildOwner,
    /// Le bot lui-même n'est jamais compté.
    BotItself,
    /// Action du bot avec une raison FoxSecura : ses propres sanctions.
    FoxSecuraAction,
}

/// Ce que le runtime sait au moment de l'entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditGuardContext {
    /// Maintenant, depuis l'époque Unix.
    pub now: Duration,
    /// Propriétaire du serveur ; `None` si le serveur n'est pas en cache.
    pub owner_id: Option<u64>,
    pub bot_id: u64,
}

/// Applique les gardes ; renvoie l'auteur à compter.
///
/// Une entrée retenue par la garde d'âge n'est pas mémorisée : elle n'est
/// jamais traitée de toute façon.
pub fn screen_entry(
    entry: &AuditEntry,
    context: AuditGuardContext,
    dedup: &mut AuditEntryDedup,
) -> Result<u64, AuditIgnoreReason> {
    if context.now.saturating_sub(entry.created_at()) > MAX_AUDIT_ENTRY_AGE {
        return Err(AuditIgnoreReason::TooOld);
    }
    if !dedup.first_seen(entry.entry_id) {
        return Err(AuditIgnoreReason::Duplicate);
    }
    let Some(author_id) = entry.author_id else {
        return Err(AuditIgnoreReason::NoAuthor);
    };
    if context.owner_id == Some(author_id) {
        return Err(AuditIgnoreReason::GuildOwner);
    }
    if author_id == context.bot_id {
        return Err(
            if entry
                .reason
                .as_deref()
                .is_some_and(is_foxsecura_audit_reason)
            {
                AuditIgnoreReason::FoxSecuraAction
            } else {
                AuditIgnoreReason::BotItself
            },
        );
    }
    Ok(author_id)
}

/// Identifiants d'entrées déjà traitées, bornés en mémoire : au-delà de la
/// capacité, les plus anciens sont oubliés. Une entrée oubliée a de toute
/// façon dépassé la garde d'âge bien avant d'être rejouée, tant que la
/// capacité couvre le volume d'entrées de cinq minutes.
#[derive(Debug)]
pub struct AuditEntryDedup {
    capacity: usize,
    seen: HashSet<u64>,
    order: VecDeque<u64>,
}

impl Default for AuditEntryDedup {
    fn default() -> Self {
        Self::new(DEFAULT_AUDIT_DEDUP_CAPACITY)
    }
}

impl AuditEntryDedup {
    /// `capacity` vaut au moins 1.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// `true` à la première rencontre de l'identifiant, qui est mémorisé.
    pub fn first_seen(&mut self, entry_id: u64) -> bool {
        if !self.seen.insert(entry_id) {
            return false;
        }
        self.order.push_back(entry_id);
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Faut-il signaler l'absence de `VIEW_AUDIT_LOG` dans les logs locaux ?
///
/// Seulement si un module de l'anti-nuke est actif, si le cache prouve que
/// la permission manque (`Some(false)`) et si la guilde n'a pas déjà été
/// signalée depuis le démarrage.
pub const fn should_warn_missing_audit_permission(
    view_audit_log: Option<bool>,
    anti_nuke_enabled: bool,
    already_warned: bool,
) -> bool {
    anti_nuke_enabled && !already_warned && matches!(view_audit_log, Some(false))
}
