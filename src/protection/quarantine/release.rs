// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Libération d'un membre (V1).
//!
//! 1. Retrait du rôle de quarantaine.
//! 2. **Restauration exacte** de chaque salon enregistré : autorisé reste
//!    autorisé, refusé reste refusé, absent redevient absent. Seuls les bits
//!    `VIEW_CHANNEL` et `CONNECT` sont écrits. Un salon disparu n'a plus rien
//!    à restaurer.
//! 3. Les lignes restaurées sont supprimées, celles en échec conservées.
//!    Si quelque chose reste inachevé, une **libération en attente** est
//!    enregistrée ; elle est reprise par la maintenance périodique et à la
//!    libération suivante.
//!
//! Idempotent : sans ligne ni rôle, aucune modification Discord.
//!
//! Les rôles dangereux retirés à la mise en quarantaine ne sont **pas**
//! rendus (V1). Un membre qui part puis revient **garde ses refus** au niveau
//! du membre : Discord conserve ses overwrites, les lignes restent en place
//! jusqu'à sa libération.

use std::collections::BTreeMap;
use std::future::Future;

use super::channels::OverwriteBits;
use super::engine::{QuarantineEffects, StoreError};
use super::failure::{DiscordFailure, UNKNOWN_CHANNEL, UNKNOWN_MEMBER, UNKNOWN_ROLE};
use super::overwrite::{RecordedOverwrite, RestorePlan, plan_restore};

/// Présence du membre, d'après le cache puis l'API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberPresence {
    Present {
        has_quarantine_role: bool,
    },
    /// Le membre a quitté le serveur (`404 Unknown Member`).
    Absent,
    /// La lecture a échoué : le rôle n'est pas retiré, la libération reste
    /// en attente.
    Unknown,
}

/// Tout ce que le runtime sait avant la libération.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFacts {
    pub quarantine_role_id: Option<u64>,
    pub member: MemberPresence,
    /// Overwrite actuel du membre dans chaque salon existant ; un salon
    /// absent de la table a disparu. `None` : serveur absent du cache, aucun
    /// salon n'est restauré (les lignes sont gardées).
    pub channels: Option<BTreeMap<u64, Option<OverwriteBits>>>,
}

/// Retrait du rôle de quarantaine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleRelease {
    /// Le membre n'a pas le rôle, est parti, ou aucun rôle n'est configuré.
    NotNeeded,
    Removed,
    Failed(DiscordFailure),
    /// Présence du membre inconnue : rien n'est tenté.
    MemberUnknown,
}

/// Résultat de la libération.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseOutcome {
    pub role: RoleRelease,
    /// Salons réécrits ou dont l'overwrite a été supprimé.
    pub restored: usize,
    /// Salons déjà dans leur état d'origine : aucun appel.
    pub unchanged: usize,
    /// Salons disparus : plus rien à restaurer.
    pub missing_channels: usize,
    /// Salons en échec : lignes conservées.
    pub failed: usize,
    pub store_errors: Vec<String>,
    /// Une libération en attente reste enregistrée.
    pub pending: bool,
}

impl ReleaseOutcome {
    /// Rien n'était à faire : ni rôle, ni ligne.
    pub fn nothing_to_do(&self) -> bool {
        self.role == RoleRelease::NotNeeded
            && self.restored + self.unchanged + self.missing_channels + self.failed == 0
            && self.store_errors.is_empty()
    }

    /// Tout est libéré : aucune libération en attente.
    pub fn is_complete(&self) -> bool {
        !self.pending
    }
}

/// Effets propres à la libération.
pub trait ReleaseEffects: QuarantineEffects {
    /// Lignes enregistrées du membre.
    fn recorded_overwrites(
        &mut self,
    ) -> impl Future<Output = Result<Vec<(u64, RecordedOverwrite)>, StoreError>> + Send;

    /// Supprime l'overwrite du membre dans un salon.
    fn delete_member_overwrite(
        &mut self,
        channel_id: u64,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;
}

/// Une libération en attente n'est reprise par la maintenance que si le
/// membre est présent : un membre parti garde ses refus (V1) jusqu'à son
/// retour ou une libération explicite.
pub fn should_resume_pending(member: &MemberPresence) -> bool {
    !matches!(member, MemberPresence::Absent)
}

/// Le rôle de quarantaine a été retiré à la main : il était connu avant la
/// mise à jour et ne l'est plus. Ancien état inconnu : `false`, un membre
/// revenu sans le rôle ne doit pas perdre ses refus.
pub fn quarantine_role_removed(old_roles: Option<&[u64]>, new_roles: &[u64], role_id: u64) -> bool {
    old_roles.is_some_and(|old| old.contains(&role_id)) && !new_roles.contains(&role_id)
}

/// Libère le membre. L'appelant tient le verrou du membre.
pub async fn release_member<E: ReleaseEffects>(
    effects: &mut E,
    facts: &ReleaseFacts,
) -> ReleaseOutcome {
    let mut outcome = ReleaseOutcome {
        role: RoleRelease::NotNeeded,
        restored: 0,
        unchanged: 0,
        missing_channels: 0,
        failed: 0,
        store_errors: Vec::new(),
        pending: false,
    };

    outcome.role = match (facts.quarantine_role_id, &facts.member) {
        (_, MemberPresence::Unknown) => RoleRelease::MemberUnknown,
        (
            Some(role_id),
            MemberPresence::Present {
                has_quarantine_role: true,
            },
        ) => match effects.remove_role(role_id).await {
            Ok(()) => RoleRelease::Removed,
            // Rôle supprimé ou membre parti entre-temps : plus rien à retirer.
            Err(failure)
                if failure.is_unknown(UNKNOWN_ROLE) || failure.is_unknown(UNKNOWN_MEMBER) =>
            {
                RoleRelease::NotNeeded
            }
            Err(failure) => RoleRelease::Failed(failure),
        },
        _ => RoleRelease::NotNeeded,
    };

    match effects.recorded_overwrites().await {
        Ok(rows) => {
            for (channel_id, recorded) in rows {
                restore_channel(effects, facts, channel_id, recorded, &mut outcome).await;
            }
        }
        Err(StoreError(error)) => outcome.store_errors.push(error),
    }

    let role_done = matches!(outcome.role, RoleRelease::NotNeeded | RoleRelease::Removed);
    outcome.pending = !role_done || outcome.failed > 0 || !outcome.store_errors.is_empty();
    if let Err(StoreError(error)) = effects.set_pending_release(outcome.pending).await {
        outcome.store_errors.push(error);
    }
    outcome
}

async fn restore_channel<E: ReleaseEffects>(
    effects: &mut E,
    facts: &ReleaseFacts,
    channel_id: u64,
    recorded: RecordedOverwrite,
    outcome: &mut ReleaseOutcome,
) {
    let Some(channels) = &facts.channels else {
        outcome.failed += 1;
        return;
    };
    let Some(&current) = channels.get(&channel_id) else {
        outcome.missing_channels += 1;
        forget(effects, channel_id, outcome).await;
        return;
    };

    let result = match plan_restore(current, recorded) {
        RestorePlan::Unchanged => {
            outcome.unchanged += 1;
            forget(effects, channel_id, outcome).await;
            return;
        }
        RestorePlan::Write(overwrite) => {
            effects.write_member_overwrite(channel_id, overwrite).await
        }
        RestorePlan::Delete => effects.delete_member_overwrite(channel_id).await,
    };

    match result {
        Ok(()) => {
            outcome.restored += 1;
            forget(effects, channel_id, outcome).await;
        }
        // Salon supprimé entre le cache et l'appel.
        Err(failure) if failure.is_unknown(UNKNOWN_CHANNEL) => {
            outcome.missing_channels += 1;
            forget(effects, channel_id, outcome).await;
        }
        Err(_) => outcome.failed += 1,
    }
}

/// Supprime une ligne restaurée. En cas d'échec, la ligne reste : la
/// prochaine libération la trouvera déjà restaurée (aucun appel) et la
/// supprimera.
async fn forget<E: ReleaseEffects>(effects: &mut E, channel_id: u64, outcome: &mut ReleaseOutcome) {
    if let Err(StoreError(error)) = effects.forget_overwrite(channel_id).await {
        outcome.store_errors.push(error);
    }
}
