// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Pose et levée d'un verrouillage, étape par étape, sans effet Discord.
//!
//! # Pose
//!
//! 1. Sans `MANAGE_CHANNELS` (d'après le cache) : `failed` /
//!    `missing_permission`, **rien n'est enregistré**.
//! 2. La ligne de verrouillage de la guilde est insérée si elle n'existe
//!    pas. Un verrouillage actif, en cours de levée ou en attente de nouvelle
//!    tentative n'est **jamais** relancé (`skipped` / déjà actif) : il
//!    écraserait les états d'origine encore attendus.
//! 3. Chaque salon : état d'origine enregistré **avant** toute modification,
//!    puis refus de `SEND_MESSAGES` à `@everyone`, puis mode lent. Un salon
//!    dont le refus échoue perd sa ligne ; un échec du mode lent ne le
//!    déverrouille pas.
//! 4. Aucun salon verrouillé : la ligne de guilde est supprimée et le
//!    résultat est `failed`.
//!
//! # Levée
//!
//! Restauration exacte de `SEND_MESSAGES` puis de l'ancien mode lent ; les
//! salons restaurés perdent leur ligne. Les salons en échec **restent
//! verrouillés** et la levée passe en attente de nouvelle tentative
//! ([`LOCKDOWN_RETRY_INTERVAL`]). Un salon disparu n'a plus rien à restaurer,
//! ce qui n'est pas un échec. Une levée est idempotente : sans ligne, aucun
//! appel Discord.
//!
//! L'appelant tient le verrou de la guilde (`GuildLocks`) pendant toute
//! l'opération.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use crate::logs::{ActionCode, ActionStatus, FailureCode, SecurityActionOutcome};
use crate::protection::quarantine::{
    DiscordFailure, OverwriteBits, RestorePlan, StoreError, UNKNOWN_CHANNEL,
};

use super::plan::{
    LockdownChannel, RecordedChannel, plan_channel_lock, plan_send_restore, plan_slowmode_restore,
};
use super::schedule::LockdownStatus;

/// Durée par défaut d'un verrouillage (V1).
pub const DEFAULT_LOCKDOWN_DURATION: Duration = Duration::from_secs(10 * 60);

/// Délai entre deux tentatives de levée (V1).
pub const LOCKDOWN_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Origine d'un verrouillage, persistée (`guild_lockdowns.reason`).
///
/// Le sous-système est réutilisable : le futur mode panique y ajoutera sa
/// propre raison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownReason {
    /// Rafale d'arrivées (anti-raid).
    AntiRaid,
}

impl LockdownReason {
    pub const fn key(self) -> &'static str {
        match self {
            Self::AntiRaid => "anti_raid",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "anti_raid" => Some(Self::AntiRaid),
            _ => None,
        }
    }

    /// Nom du module dans les raisons d'audit log
    /// (`FoxSecura Anti-Raid: temporary lockdown`).
    pub const fn audit_label(self) -> &'static str {
        match self {
            Self::AntiRaid => "Anti-Raid",
        }
    }
}

/// Ce que le module demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockdownRequest {
    pub reason: LockdownReason,
    /// Levée prévue, en secondes Unix (horloge murale).
    pub lift_at: u64,
}

/// Tout ce que le runtime sait avant de verrouiller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockdownFacts {
    /// `MANAGE_CHANNELS` du bot ; `None` si le cache ne permet pas de
    /// conclure (les appels sont tentés).
    pub manage_channels: Option<bool>,
    /// Salons candidats, hors fils.
    pub channels: Vec<LockdownChannel>,
}

/// Issue d'une pose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockdownStart {
    /// Au moins un salon refuse l'écriture à `@everyone`.
    Applied,
    /// Un verrouillage est déjà actif, en cours de levée ou en attente :
    /// rien n'est modifié.
    AlreadyActive,
    /// Pas de `MANAGE_CHANNELS` : rien n'est enregistré.
    MissingPermission,
    /// Aucun salon n'a pu être verrouillé : la ligne de guilde est supprimée.
    NoChannelLocked,
    /// La ligne de guilde n'a pas pu être écrite : rien n'est modifié.
    StoreFailed(String),
}

/// Bilan d'une pose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockdownOutcome {
    pub start: LockdownStart,
    /// Salons candidats.
    pub total: usize,
    /// Salons qui refusent l'écriture à `@everyone` grâce à cette pose (y
    /// compris ceux qui la refusaient déjà).
    pub locked: usize,
    /// Dont salons qui la refusaient déjà : aucun appel.
    pub preexisting_deny: usize,
    pub failed: usize,
    pub slowmode_applied: usize,
    pub slowmode_failed: usize,
    pub first_failure: Option<FailureCode>,
    /// Levée prévue (secondes Unix) si le verrouillage est posé.
    pub lift_at: Option<u64>,
    pub store_errors: Vec<String>,
}

impl LockdownOutcome {
    fn new(start: LockdownStart, total: usize) -> Self {
        Self {
            start,
            total,
            locked: 0,
            preexisting_deny: 0,
            failed: 0,
            slowmode_applied: 0,
            slowmode_failed: 0,
            first_failure: None,
            lift_at: None,
            store_errors: Vec::new(),
        }
    }

    /// Le verrouillage a été posé par cette opération.
    pub fn applied(&self) -> bool {
        self.start == LockdownStart::Applied
    }

    /// Résultat d'action journalisé dans l'incident.
    pub fn action_outcome(&self) -> SecurityActionOutcome {
        let counts = format!(
            "locked={} failed={} total={} slowmode={}",
            self.locked, self.failed, self.total, self.slowmode_applied
        );
        let (status, failure_code, details) = match &self.start {
            LockdownStart::Applied if self.failed == 0 => (ActionStatus::Success, None, counts),
            LockdownStart::Applied => (ActionStatus::Partial, self.first_failure, counts),
            LockdownStart::AlreadyActive => {
                (ActionStatus::Skipped, None, "already_active".to_owned())
            }
            LockdownStart::MissingPermission => (
                ActionStatus::Failed,
                Some(FailureCode::MissingPermission),
                "MANAGE_CHANNELS".to_owned(),
            ),
            LockdownStart::NoChannelLocked => (
                ActionStatus::Failed,
                Some(self.first_failure.unwrap_or(FailureCode::Unknown)),
                counts,
            ),
            LockdownStart::StoreFailed(error) => (
                ActionStatus::Failed,
                Some(FailureCode::Unknown),
                error.clone(),
            ),
        };
        SecurityActionOutcome {
            action: ActionCode::ApplyLockdown,
            status,
            details: Some(details),
            failure_code,
        }
    }

    fn record(&mut self, result: ChannelLockResult) {
        match result {
            ChannelLockResult::Locked {
                preexisting_deny,
                slowmode,
            } => {
                self.locked += 1;
                self.preexisting_deny += usize::from(preexisting_deny);
                match slowmode {
                    SlowmodeResult::NotNeeded => {}
                    SlowmodeResult::Applied => self.slowmode_applied += 1,
                    SlowmodeResult::Failed => self.slowmode_failed += 1,
                }
            }
            ChannelLockResult::Failed(code) => {
                self.failed += 1;
                self.first_failure.get_or_insert(code);
            }
        }
    }
}

/// Mode lent d'un salon verrouillé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowmodeResult {
    /// Non accepté par le salon, ou déjà au moins aussi strict.
    NotNeeded,
    Applied,
    /// Échec : le salon reste verrouillé, le mode lent est un confort.
    Failed,
}

/// Résultat du verrouillage d'un salon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLockResult {
    Locked {
        /// `SEND_MESSAGES` était déjà refusé : aucun appel.
        preexisting_deny: bool,
        slowmode: SlowmodeResult,
    },
    /// Le refus n'a pas pu être posé ni enregistré : salon non verrouillé.
    Failed(FailureCode),
}

/// Overwrite actuel de `@everyone` et mode lent d'un salon existant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CurrentChannel {
    pub everyone: Option<OverwriteBits>,
    pub slowmode: u16,
}

/// Tout ce que le runtime sait avant la levée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftFacts {
    /// Salons existants ; un salon absent de la table a disparu. `None` :
    /// guilde non résoluble (absente du cache), rien n'est tenté et la levée
    /// est reprise plus tard.
    pub channels: Option<BTreeMap<u64, CurrentChannel>>,
    /// Maintenant, en secondes Unix (horloge murale).
    pub now: u64,
}

/// Bilan d'une levée.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiftOutcome {
    /// Salons réécrits.
    pub restored: usize,
    /// Salons déjà dans leur état d'origine : aucun appel.
    pub unchanged: usize,
    /// Salons disparus : plus rien à restaurer (ce n'est pas un échec).
    pub missing_channels: usize,
    /// Salons en échec : toujours verrouillés, lignes conservées.
    pub failed: usize,
    pub store_errors: Vec<String>,
    /// Guilde absente du cache : rien n'a été tenté.
    pub unresolved: bool,
    /// Une nouvelle tentative est programmée.
    pub pending: bool,
    /// La ligne de verrouillage de la guilde a été supprimée.
    pub ended: bool,
}

impl LiftOutcome {
    /// Rien n'était à lever : ni ligne de guilde, ni salon enregistré.
    pub fn nothing_to_do(&self) -> bool {
        !self.ended
            && !self.unresolved
            && self.restored + self.unchanged + self.missing_channels + self.failed == 0
            && self.store_errors.is_empty()
    }

    /// Résultat d'action journalisé dans l'incident de levée.
    pub fn action_outcome(&self) -> SecurityActionOutcome {
        let status = match (self.pending, self.restored + self.unchanged) {
            (false, _) => ActionStatus::Success,
            (true, 0) => ActionStatus::Failed,
            (true, _) => ActionStatus::Partial,
        };
        SecurityActionOutcome {
            action: ActionCode::RestoreLockdown,
            status,
            details: Some(format!(
                "restored={} unchanged={} missing={} failed={}",
                self.restored, self.unchanged, self.missing_channels, self.failed
            )),
            failure_code: self.pending.then_some(if self.unresolved {
                FailureCode::DiscordUnavailable
            } else {
                FailureCode::Unknown
            }),
        }
    }
}

/// Effets d'un verrouillage, pour une guilde donnée.
///
/// Le runtime les exécute (Discord, SQLite) avec la raison d'audit log de
/// l'opération ; les tests les simulent.
pub trait LockdownEffects {
    /// Insère la ligne de verrouillage de la guilde ; `false` si elle existe
    /// déjà (actif, en cours de levée ou en attente), rien n'est alors
    /// modifié.
    fn begin_lockdown(
        &mut self,
        request: LockdownRequest,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Supprime la ligne de la guilde s'il ne reste aucun salon enregistré ;
    /// `true` si elle a été supprimée.
    fn end_lockdown(&mut self) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Change l'état de la ligne de guilde ; `lift_at` repousse la prochaine
    /// tentative.
    fn set_lockdown_status(
        &mut self,
        status: LockdownStatus,
        lift_at: Option<u64>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Enregistre l'état d'origine d'un salon ; `false` si une ligne existait
    /// déjà (conservée : elle porte le vrai état d'origine).
    fn record_channel(
        &mut self,
        channel_id: u64,
        state: RecordedChannel,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Supprime la ligne d'un salon.
    fn forget_channel(
        &mut self,
        channel_id: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Lignes de salon enregistrées.
    fn recorded_channels(
        &mut self,
    ) -> impl Future<Output = Result<Vec<(u64, RecordedChannel)>, StoreError>> + Send;

    /// Écrit l'overwrite de `@everyone` dans un salon.
    fn write_everyone_overwrite(
        &mut self,
        channel_id: u64,
        overwrite: OverwriteBits,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;

    /// Supprime l'overwrite de `@everyone` dans un salon.
    fn delete_everyone_overwrite(
        &mut self,
        channel_id: u64,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;

    /// Change le mode lent d'un salon (0 : aucun).
    fn set_slowmode(
        &mut self,
        channel_id: u64,
        seconds: u16,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;
}

/// Pose le verrouillage. L'appelant tient le verrou de la guilde.
pub async fn apply_lockdown<E: LockdownEffects>(
    effects: &mut E,
    facts: &LockdownFacts,
    request: LockdownRequest,
) -> LockdownOutcome {
    let total = facts.channels.len();
    if facts.manage_channels == Some(false) {
        return LockdownOutcome::new(LockdownStart::MissingPermission, total);
    }
    match effects.begin_lockdown(request).await {
        Ok(true) => {}
        Ok(false) => return LockdownOutcome::new(LockdownStart::AlreadyActive, total),
        Err(StoreError(error)) => {
            return LockdownOutcome::new(LockdownStart::StoreFailed(error), total);
        }
    }

    let mut outcome = LockdownOutcome::new(LockdownStart::Applied, total);
    for channel in &facts.channels {
        outcome.record(lock_channel(effects, channel).await);
    }

    if outcome.locked == 0 {
        outcome.start = LockdownStart::NoChannelLocked;
        if let Err(StoreError(error)) = effects.end_lockdown().await {
            outcome.store_errors.push(error);
        }
    } else {
        outcome.lift_at = Some(request.lift_at);
    }
    outcome
}

/// Verrouille un salon : enregistre l'état d'origine **avant** de le
/// modifier, et supprime la ligne tout juste créée si le refus échoue. Sans
/// enregistrement réussi, le salon n'est jamais modifié.
pub async fn lock_channel<E: LockdownEffects>(
    effects: &mut E,
    channel: &LockdownChannel,
) -> ChannelLockResult {
    let plan = plan_channel_lock(channel);
    let inserted = match effects
        .record_channel(channel.channel_id, plan.record)
        .await
    {
        Ok(inserted) => inserted,
        Err(_) => return ChannelLockResult::Failed(FailureCode::Unknown),
    };

    if let Some(overwrite) = plan.overwrite
        && let Err(failure) = effects
            .write_everyone_overwrite(channel.channel_id, overwrite)
            .await
    {
        if inserted {
            // Rien n'a été modifié : la ligne ne décrit aucun verrou. Si la
            // suppression échoue, la levée réécrira l'état d'origine à
            // l'identique (aucun appel).
            let _ = effects.forget_channel(channel.channel_id).await;
        }
        return ChannelLockResult::Failed(failure.failure_code());
    }

    let slowmode = match plan.slowmode {
        None => SlowmodeResult::NotNeeded,
        Some(seconds) => match effects.set_slowmode(channel.channel_id, seconds).await {
            Ok(()) => SlowmodeResult::Applied,
            Err(_) => SlowmodeResult::Failed,
        },
    };
    ChannelLockResult::Locked {
        preexisting_deny: plan.overwrite.is_none(),
        slowmode,
    }
}

/// Lève le verrouillage. L'appelant tient le verrou de la guilde.
pub async fn lift_lockdown<E: LockdownEffects>(effects: &mut E, facts: &LiftFacts) -> LiftOutcome {
    let mut outcome = LiftOutcome::default();
    let retry_at = facts.now.saturating_add(LOCKDOWN_RETRY_INTERVAL.as_secs());

    let Some(channels) = &facts.channels else {
        // Guilde non résoluble (démarrage, panne) : rien n'est touché.
        outcome.unresolved = true;
        outcome.pending = true;
        if let Err(StoreError(error)) = effects
            .set_lockdown_status(LockdownStatus::Retry, Some(retry_at))
            .await
        {
            outcome.store_errors.push(error);
        }
        return outcome;
    };

    if let Err(StoreError(error)) = effects
        .set_lockdown_status(LockdownStatus::Lifting, None)
        .await
    {
        outcome.store_errors.push(error);
    }

    match effects.recorded_channels().await {
        Ok(rows) => {
            for (channel_id, recorded) in rows {
                restore_channel(effects, channels, channel_id, recorded, &mut outcome).await;
            }
        }
        Err(StoreError(error)) => outcome.store_errors.push(error),
    }

    outcome.pending = outcome.failed > 0 || !outcome.store_errors.is_empty();
    if outcome.pending {
        if let Err(StoreError(error)) = effects
            .set_lockdown_status(LockdownStatus::Retry, Some(retry_at))
            .await
        {
            outcome.store_errors.push(error);
        }
    } else {
        match effects.end_lockdown().await {
            Ok(ended) => outcome.ended = ended,
            Err(StoreError(error)) => {
                outcome.store_errors.push(error);
                outcome.pending = true;
            }
        }
    }
    outcome
}

async fn restore_channel<E: LockdownEffects>(
    effects: &mut E,
    channels: &BTreeMap<u64, CurrentChannel>,
    channel_id: u64,
    recorded: RecordedChannel,
    outcome: &mut LiftOutcome,
) {
    let Some(current) = channels.get(&channel_id) else {
        outcome.missing_channels += 1;
        forget(effects, channel_id, outcome).await;
        return;
    };

    let mut changed = false;
    let send = match plan_send_restore(current.everyone, recorded.send_messages) {
        RestorePlan::Unchanged => Ok(()),
        RestorePlan::Write(overwrite) => {
            changed = true;
            effects
                .write_everyone_overwrite(channel_id, overwrite)
                .await
        }
        RestorePlan::Delete => {
            changed = true;
            effects.delete_everyone_overwrite(channel_id).await
        }
    };
    // Le refus d'écrire d'abord : tant qu'il n'est pas levé, le salon reste
    // verrouillé et sa ligne est conservée.
    let slowmode = match send {
        Ok(()) => match plan_slowmode_restore(current.slowmode, recorded.slowmode) {
            Some(seconds) => {
                changed = true;
                effects.set_slowmode(channel_id, seconds).await
            }
            None => Ok(()),
        },
        Err(failure) => Err(failure),
    };

    match slowmode {
        Ok(()) => {
            if changed {
                outcome.restored += 1;
            } else {
                outcome.unchanged += 1;
            }
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

/// Supprime une ligne restaurée. En cas d'échec, la ligne reste : la levée
/// suivante la trouvera déjà restaurée (aucun appel) et la supprimera.
async fn forget<E: LockdownEffects>(effects: &mut E, channel_id: u64, outcome: &mut LiftOutcome) {
    if let Err(StoreError(error)) = effects.forget_channel(channel_id).await {
        outcome.store_errors.push(error);
    }
}
