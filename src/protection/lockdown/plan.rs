// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Salons verrouillés, état d'origine et restauration exacte (V1).
//!
//! Sur chaque salon candidat, `SEND_MESSAGES` est refusé à `@everyone`
//! (identifiant de la guilde), puis le mode lent demandé par le verrouillage
//! est posé si le salon l'accepte ([`LOCKDOWN_SLOWMODE_SECONDS`] pour
//! l'anti-raid, 30 s pour le mode panique). Seul le refus
//! d'écrire compte pour dire qu'un salon est verrouillé ; le mode lent est un
//! confort, il n'est jamais réduit.
//!
//! L'état d'origine est relevé **avant** la modification : le bit
//! `SEND_MESSAGES` de `@everyone` à trois états (le refus prime si les deux
//! bits sont présents) et le mode lent (`None` sans mode lent).

use poise::serenity_prelude::Permissions;

use crate::protection::quarantine::{OverwriteBits, PermissionState, RestorePlan};

/// Mode lent posé par un verrouillage de l'anti-raid, en secondes (V1).
///
/// Valeur aussi prise par les lignes de verrouillage antérieures à la
/// migration 9, qui n'enregistraient pas le mode lent posé.
pub const LOCKDOWN_SLOWMODE_SECONDS: u16 = 10;

/// Mode lent maximal accepté par Discord, en secondes (6 heures).
pub const MAX_SLOWMODE_SECONDS: u16 = 21_600;

/// Bit refusé à `@everyone` pendant un verrouillage.
pub const LOCKDOWN_DENY: Permissions = Permissions::SEND_MESSAGES;

/// Salon candidat (hors fils), d'après le cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockdownChannel {
    pub channel_id: u64,
    /// Overwrite de `@everyone` ; `None` s'il est absent.
    pub everyone: Option<OverwriteBits>,
    /// Mode lent actuel, en secondes (0 : aucun).
    pub slowmode: u16,
    /// Le type de salon accepte un mode lent (texte, vocal, conférence,
    /// forum).
    pub supports_slowmode: bool,
}

/// État d'origine d'un salon, enregistré avant sa modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedChannel {
    /// `SEND_MESSAGES` de `@everyone` : autorisé, refusé ou absent.
    pub send_messages: PermissionState,
    /// Ancien mode lent ; `None` pour un salon sans mode lent.
    pub slowmode: Option<u16>,
}

impl RecordedChannel {
    /// Relève l'état actuel du salon.
    pub fn capture(channel: &LockdownChannel) -> Self {
        Self {
            send_messages: PermissionState::of(channel.everyone, LOCKDOWN_DENY),
            slowmode: (channel.slowmode > 0).then_some(channel.slowmode),
        }
    }

    /// Relit une ligne persistée.
    ///
    /// Une valeur illisible (base écrite hors de FoxSecura ou par une version
    /// plus récente) se restaure en **absent**, jamais en « autorisé » : le
    /// salon retombe sur les permissions des rôles au lieu d'accorder
    /// explicitement l'écriture. Un mode lent illisible redevient « aucun ».
    pub fn from_stored(send_messages: &str, slowmode: Option<i64>) -> Self {
        Self {
            send_messages: PermissionState::from_key(send_messages)
                .unwrap_or(PermissionState::Unset),
            slowmode: slowmode
                .and_then(|seconds| u16::try_from(seconds).ok())
                .filter(|seconds| (1..=MAX_SLOWMODE_SECONDS).contains(seconds)),
        }
    }
}

/// Ce qu'il faut faire sur un salon pour le verrouiller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelLockPlan {
    /// État d'origine à enregistrer avant tout appel.
    pub record: RecordedChannel,
    /// Overwrite de `@everyone` à écrire ; `None` si `SEND_MESSAGES` est déjà
    /// refusé sans être autorisé (aucun appel, le salon compte comme
    /// verrouillé).
    pub overwrite: Option<OverwriteBits>,
    /// Mode lent à poser ; `None` si le salon ne l'accepte pas ou en a déjà
    /// un au moins aussi strict.
    pub slowmode: Option<u16>,
}

/// Décide du verrouillage d'un salon avec le mode lent `slowmode` (en
/// secondes). Les autres bits de l'overwrite de `@everyone` sont conservés
/// tels quels.
pub fn plan_channel_lock(channel: &LockdownChannel, slowmode: u16) -> ChannelLockPlan {
    let bits = channel.everyone.unwrap_or_default();
    let already_denied = bits.deny.contains(LOCKDOWN_DENY) && !bits.allow.contains(LOCKDOWN_DENY);
    ChannelLockPlan {
        record: RecordedChannel::capture(channel),
        overwrite: (!already_denied).then(|| PermissionState::Deny.apply(bits, LOCKDOWN_DENY)),
        slowmode: lock_slowmode(channel.slowmode, channel.supports_slowmode, slowmode),
    }
}

/// Mode lent à poser (`target`, en secondes) : jamais sur un salon qui ne
/// l'accepte pas, et jamais en réduisant un mode lent déjà plus strict (ou
/// égal).
pub const fn lock_slowmode(current: u16, supports_slowmode: bool, target: u16) -> Option<u16> {
    if supports_slowmode && current < target {
        Some(target)
    } else {
        None
    }
}

/// Restaure exactement `SEND_MESSAGES` de `@everyone` : autorisé reste
/// autorisé, refusé reste refusé, absent redevient absent. Un overwrite
/// restauré vide est supprimé.
pub fn plan_send_restore(current: Option<OverwriteBits>, recorded: PermissionState) -> RestorePlan {
    let restored = recorded.apply(current.unwrap_or_default(), LOCKDOWN_DENY);
    match current {
        Some(current) if current == restored => RestorePlan::Unchanged,
        None if restored.is_empty() => RestorePlan::Unchanged,
        _ if restored.is_empty() => RestorePlan::Delete,
        _ => RestorePlan::Write(restored),
    }
}

/// Mode lent à réécrire à la levée ; `None` : rien à faire.
///
/// `applied` : mode lent posé par ce verrouillage, enregistré avec la ligne
/// de verrouillage (migration 9). Seul ce mode lent est rendu : si l'équipe
/// l'a modifié entre-temps, ou s'il n'avait pas été touché (déjà plus
/// strict), il est conservé.
pub fn plan_slowmode_restore(current: u16, recorded: Option<u16>, applied: u16) -> Option<u16> {
    let previous = recorded.unwrap_or(0);
    (applied > 0 && current == applied && previous != current).then_some(previous)
}
