// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity, LogType};
use foxsecura::protection::lockdown::{
    CurrentChannel, DEFAULT_LOCKDOWN_DURATION, GuildLocks, LOCKDOWN_RETRY_INTERVAL,
    LOCKDOWN_SLOWMODE_SECONDS, LiftFacts, LiftOutcome, LiftTrigger, LockdownChannel,
    LockdownEffects, LockdownFacts, LockdownOutcome, LockdownReason, LockdownRequest,
    LockdownStart, LockdownState, LockdownStatus, LockdownTimers, RecordedChannel, WakeAction,
    apply_lockdown, lift_incident, lift_lockdown, lock_slowmode, lockdown_audit_reason,
    lockdown_restore_audit_reason, plan_channel_lock, plan_send_restore, plan_slowmode_restore,
    resume_plan, should_publish_lift, wake_action,
};
use foxsecura::protection::quarantine::{
    DiscordFailure, OverwriteBits, PermissionState, RestorePlan, StoreError, UNKNOWN_CHANNEL,
};
use foxsecura::protection::shared::is_foxsecura_audit_reason;
use poise::serenity_prelude::Permissions;

const SEND: Permissions = Permissions::SEND_MESSAGES;
const NOW: u64 = 1_700_000_000;

fn bits(allow: Permissions, deny: Permissions) -> OverwriteBits {
    OverwriteBits { allow, deny }
}

fn channel(channel_id: u64, everyone: Option<OverwriteBits>, slowmode: u16) -> LockdownChannel {
    LockdownChannel {
        channel_id,
        everyone,
        slowmode,
        supports_slowmode: true,
    }
}

// --- État d'origine à trois états ---

#[test]
fn capture_has_three_states_and_deny_wins() {
    let capture = |everyone| RecordedChannel::capture(&channel(1, everyone, 0)).send_messages;
    assert_eq!(capture(None), PermissionState::Unset);
    assert_eq!(
        capture(Some(bits(Permissions::empty(), Permissions::empty()))),
        PermissionState::Unset
    );
    assert_eq!(
        capture(Some(bits(SEND, Permissions::empty()))),
        PermissionState::Allow
    );
    assert_eq!(
        capture(Some(bits(Permissions::empty(), SEND))),
        PermissionState::Deny
    );
    // Les deux bits présents : le refus prime.
    assert_eq!(capture(Some(bits(SEND, SEND))), PermissionState::Deny);
    // Les autres bits n'entrent pas en compte.
    assert_eq!(
        capture(Some(bits(
            Permissions::VIEW_CHANNEL,
            Permissions::ADD_REACTIONS
        ))),
        PermissionState::Unset
    );
}

#[test]
fn capture_records_the_slowmode_or_nothing() {
    assert_eq!(
        RecordedChannel::capture(&channel(1, None, 0)).slowmode,
        None
    );
    assert_eq!(
        RecordedChannel::capture(&channel(1, None, 30)).slowmode,
        Some(30)
    );
}

#[test]
fn unreadable_stored_values_restore_to_unset_never_allow() {
    for key in ["", "ALLOW", "granted", "allow ", "1"] {
        assert_eq!(
            RecordedChannel::from_stored(key, None).send_messages,
            PermissionState::Unset,
            "{key:?}"
        );
    }
    assert_eq!(
        RecordedChannel::from_stored("allow", None).send_messages,
        PermissionState::Allow
    );
    assert_eq!(
        RecordedChannel::from_stored("deny", Some(5)),
        RecordedChannel {
            send_messages: PermissionState::Deny,
            slowmode: Some(5),
        }
    );
    // Mode lent illisible : aucun.
    for slowmode in [Some(0), Some(-1), Some(21_601), Some(i64::MAX)] {
        assert_eq!(
            RecordedChannel::from_stored("unset", slowmode).slowmode,
            None
        );
    }
}

#[test]
fn restore_is_exact_for_each_state() {
    let locked = Some(bits(Permissions::VIEW_CHANNEL, SEND));
    // Absent redevient absent : l'overwrite garde ses autres bits.
    assert_eq!(
        plan_send_restore(locked, PermissionState::Unset),
        RestorePlan::Write(bits(Permissions::VIEW_CHANNEL, Permissions::empty()))
    );
    assert_eq!(
        plan_send_restore(locked, PermissionState::Allow),
        RestorePlan::Write(bits(Permissions::VIEW_CHANNEL | SEND, Permissions::empty()))
    );
    assert_eq!(
        plan_send_restore(locked, PermissionState::Deny),
        RestorePlan::Unchanged
    );
    // Overwrite créé par le verrouillage : supprimé.
    assert_eq!(
        plan_send_restore(
            Some(bits(Permissions::empty(), SEND)),
            PermissionState::Unset
        ),
        RestorePlan::Delete
    );
    assert_eq!(
        plan_send_restore(None, PermissionState::Unset),
        RestorePlan::Unchanged
    );
}

// --- Plan de verrouillage ---

#[test]
fn lock_denies_send_messages_and_keeps_other_bits() {
    let plan = plan_channel_lock(
        &channel(
            1,
            Some(bits(
                SEND | Permissions::VIEW_CHANNEL,
                Permissions::ADD_REACTIONS,
            )),
            0,
        ),
        LOCKDOWN_SLOWMODE_SECONDS,
    );
    assert_eq!(
        plan.overwrite,
        Some(bits(
            Permissions::VIEW_CHANNEL,
            Permissions::ADD_REACTIONS | SEND
        ))
    );
    assert_eq!(plan.record.send_messages, PermissionState::Allow);
    assert_eq!(plan.slowmode, Some(LOCKDOWN_SLOWMODE_SECONDS));

    // Déjà refusé : aucun appel pour le refus.
    let denied = plan_channel_lock(
        &channel(2, Some(bits(Permissions::empty(), SEND)), 0),
        LOCKDOWN_SLOWMODE_SECONDS,
    );
    assert_eq!(denied.overwrite, None);
    // Refusé et autorisé à la fois : nettoyé.
    let both = plan_channel_lock(
        &channel(3, Some(bits(SEND, SEND)), 0),
        LOCKDOWN_SLOWMODE_SECONDS,
    );
    assert_eq!(both.overwrite, Some(bits(Permissions::empty(), SEND)));
}

#[test]
fn slowmode_is_never_reduced() {
    assert_eq!(lock_slowmode(0, true, 10), Some(10));
    assert_eq!(lock_slowmode(5, true, 10), Some(10));
    assert_eq!(lock_slowmode(10, true, 10), None);
    assert_eq!(lock_slowmode(30, true, 10), None);
    assert_eq!(lock_slowmode(21_600, true, 10), None);
    // Salon sans mode lent possible (catégorie, annonces).
    assert_eq!(lock_slowmode(0, false, 10), None);
}

#[test]
fn slowmode_restore_gives_back_only_the_lockdown_slowmode() {
    assert_eq!(plan_slowmode_restore(10, None, 10), Some(0));
    assert_eq!(plan_slowmode_restore(10, Some(5), 10), Some(5));
    // Déjà plus strict, jamais touché.
    assert_eq!(plan_slowmode_restore(30, Some(30), 10), None);
    assert_eq!(plan_slowmode_restore(10, Some(10), 10), None);
    // Modifié par l'équipe pendant le verrouillage : conservé.
    assert_eq!(plan_slowmode_restore(60, None, 10), None);
    assert_eq!(plan_slowmode_restore(0, None, 10), None);
}

// --- Effets simulés ---

#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    /// Ligne de guilde : état et levée prévue.
    guild: Option<(LockdownStatus, u64)>,
    rows: BTreeMap<u64, RecordedChannel>,
    everyone: BTreeMap<u64, Option<OverwriteBits>>,
    slowmode: BTreeMap<u64, u16>,
    fail_write: HashSet<u64>,
    fail_slowmode: HashSet<u64>,
    fail_record: HashSet<u64>,
    fail_begin: bool,
    /// Salons supprimés entre le cache et l'appel (`404 Unknown Channel`).
    gone: HashSet<u64>,
}

fn forbidden() -> DiscordFailure {
    DiscordFailure::new(Some(403), Some(50013), "Missing Permissions")
}

impl Fake {
    fn discord(&mut self, channel_id: u64, fail: bool) -> Result<(), DiscordFailure> {
        if self.gone.contains(&channel_id) {
            return Err(DiscordFailure::new(
                Some(404),
                Some(UNKNOWN_CHANNEL),
                "Unknown Channel",
            ));
        }
        if fail {
            return Err(forbidden());
        }
        Ok(())
    }

    fn current(&self) -> BTreeMap<u64, CurrentChannel> {
        self.everyone
            .iter()
            .map(|(id, everyone)| {
                (
                    *id,
                    CurrentChannel {
                        everyone: *everyone,
                        slowmode: self.slowmode.get(id).copied().unwrap_or(0),
                    },
                )
            })
            .collect()
    }
}

impl LockdownEffects for Fake {
    async fn begin_lockdown(&mut self, request: LockdownRequest) -> Result<bool, StoreError> {
        self.calls.push("begin".to_owned());
        if self.fail_begin {
            return Err(StoreError("disk full".to_owned()));
        }
        if self.guild.is_some() {
            return Ok(false);
        }
        self.guild = Some((LockdownStatus::Active, request.lift_at));
        Ok(true)
    }

    async fn end_lockdown(&mut self) -> Result<bool, StoreError> {
        self.calls.push("end".to_owned());
        if !self.rows.is_empty() {
            return Ok(false);
        }
        Ok(self.guild.take().is_some())
    }

    async fn set_lockdown_status(
        &mut self,
        status: LockdownStatus,
        lift_at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.calls.push(format!("status {}", status.key()));
        if let Some((current, at)) = &mut self.guild {
            *current = status;
            if let Some(lift_at) = lift_at {
                *at = lift_at;
            }
        }
        Ok(())
    }

    async fn record_channel(
        &mut self,
        channel_id: u64,
        state: RecordedChannel,
    ) -> Result<bool, StoreError> {
        self.calls.push(format!("record {channel_id}"));
        if self.fail_record.contains(&channel_id) {
            return Err(StoreError("locked".to_owned()));
        }
        if self.rows.contains_key(&channel_id) {
            return Ok(false);
        }
        self.rows.insert(channel_id, state);
        Ok(true)
    }

    async fn forget_channel(&mut self, channel_id: u64) -> Result<(), StoreError> {
        self.calls.push(format!("forget {channel_id}"));
        self.rows.remove(&channel_id);
        Ok(())
    }

    async fn recorded_channels(&mut self) -> Result<Vec<(u64, RecordedChannel)>, StoreError> {
        Ok(self.rows.iter().map(|(id, row)| (*id, *row)).collect())
    }

    async fn write_everyone_overwrite(
        &mut self,
        channel_id: u64,
        overwrite: OverwriteBits,
    ) -> Result<(), DiscordFailure> {
        // Enregistrement avant modification : jamais d'écriture sans ligne.
        assert!(
            self.rows.contains_key(&channel_id),
            "salon {channel_id} modifié sans état d'origine enregistré"
        );
        self.calls.push(format!("write {channel_id}"));
        let fail = self.fail_write.contains(&channel_id);
        self.discord(channel_id, fail)?;
        self.everyone.insert(channel_id, Some(overwrite));
        Ok(())
    }

    async fn delete_everyone_overwrite(&mut self, channel_id: u64) -> Result<(), DiscordFailure> {
        self.calls.push(format!("delete {channel_id}"));
        let fail = self.fail_write.contains(&channel_id);
        self.discord(channel_id, fail)?;
        self.everyone.insert(channel_id, None);
        Ok(())
    }

    async fn set_slowmode(&mut self, channel_id: u64, seconds: u16) -> Result<(), DiscordFailure> {
        assert!(self.rows.contains_key(&channel_id));
        self.calls.push(format!("slowmode {channel_id} {seconds}"));
        let fail = self.fail_slowmode.contains(&channel_id);
        self.discord(channel_id, fail)?;
        self.slowmode.insert(channel_id, seconds);
        Ok(())
    }
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(future)
}

fn request() -> LockdownRequest {
    LockdownRequest::for_reason(LockdownReason::AntiRaid, NOW)
}

/// Serveur de trois salons : sans overwrite, écriture autorisée avec mode
/// lent de 5 s, écriture déjà refusée avec mode lent de 30 s.
fn server() -> (Fake, LockdownFacts) {
    let channels = vec![
        channel(1, None, 0),
        channel(
            2,
            Some(bits(SEND | Permissions::VIEW_CHANNEL, Permissions::empty())),
            5,
        ),
        channel(3, Some(bits(Permissions::empty(), SEND)), 30),
    ];
    let mut fake = Fake::default();
    for channel in &channels {
        fake.everyone.insert(channel.channel_id, channel.everyone);
        fake.slowmode.insert(channel.channel_id, channel.slowmode);
    }
    (
        fake,
        LockdownFacts {
            manage_channels: Some(true),
            channels,
        },
    )
}

fn apply(fake: &mut Fake, facts: &LockdownFacts) -> LockdownOutcome {
    run(apply_lockdown(fake, facts, request()))
}

fn lift(fake: &mut Fake) -> LiftOutcome {
    let facts = LiftFacts {
        channels: Some(fake.current()),
        now: NOW,
        slowmode_seconds: LOCKDOWN_SLOWMODE_SECONDS,
    };
    run(lift_lockdown(fake, &facts))
}

// --- Pose ---

#[test]
fn default_duration_is_ten_minutes_and_retry_one_minute() {
    assert_eq!(DEFAULT_LOCKDOWN_DURATION, Duration::from_secs(600));
    assert_eq!(LOCKDOWN_RETRY_INTERVAL, Duration::from_secs(60));
    assert_eq!(LOCKDOWN_SLOWMODE_SECONDS, 10);
}

#[test]
fn lockdown_records_every_channel_before_touching_discord() {
    let (mut fake, facts) = server();
    let outcome = apply(&mut fake, &facts);

    assert_eq!(outcome.start, LockdownStart::Applied);
    assert_eq!((outcome.locked, outcome.failed, outcome.total), (3, 0, 3));
    assert_eq!(outcome.preexisting_deny, 1);
    assert_eq!(outcome.slowmode_applied, 2);
    assert_eq!(outcome.lift_at, Some(NOW + 600));
    assert_eq!(fake.guild, Some((LockdownStatus::Active, NOW + 600)));
    assert_eq!(
        fake.calls,
        [
            "begin",
            "record 1",
            "write 1",
            "slowmode 1 10",
            "record 2",
            "write 2",
            "slowmode 2 10",
            // Déjà refusé, mode lent plus strict : aucun appel.
            "record 3",
        ]
    );
    assert_eq!(
        fake.rows[&2],
        RecordedChannel {
            send_messages: PermissionState::Allow,
            slowmode: Some(5),
        }
    );
    assert_eq!(fake.rows[&1].send_messages, PermissionState::Unset);
    assert_eq!(fake.rows[&3].send_messages, PermissionState::Deny);
    assert_eq!(fake.slowmode[&3], 30, "mode lent plus strict jamais réduit");

    let action = outcome.action_outcome();
    assert_eq!(action.action, ActionCode::ApplyLockdown);
    assert_eq!(action.status, ActionStatus::Success);
    assert_eq!(
        action.details.as_deref(),
        Some("locked=3 failed=0 total=3 slowmode=2")
    );
}

#[test]
fn a_failed_channel_loses_its_row_and_the_lockdown_is_partial() {
    let (mut fake, facts) = server();
    fake.fail_write.insert(2);
    let outcome = apply(&mut fake, &facts);

    assert_eq!(outcome.start, LockdownStart::Applied);
    assert_eq!((outcome.locked, outcome.failed), (2, 1));
    assert!(!fake.rows.contains_key(&2), "ligne supprimée après l'échec");
    assert!(fake.calls.contains(&"forget 2".to_owned()));
    // Aucun mode lent sur un salon non verrouillé.
    assert!(!fake.calls.contains(&"slowmode 2 10".to_owned()));
    let action = outcome.action_outcome();
    assert_eq!(action.status, ActionStatus::Partial);
    assert_eq!(action.failure_code, Some(FailureCode::MissingPermission));
}

#[test]
fn a_slowmode_failure_does_not_unlock_the_channel() {
    let (mut fake, facts) = server();
    fake.fail_slowmode.insert(1);
    let outcome = apply(&mut fake, &facts);

    assert_eq!((outcome.locked, outcome.failed), (3, 0));
    assert_eq!(outcome.slowmode_failed, 1);
    assert!(fake.rows.contains_key(&1));
    assert_eq!(outcome.action_outcome().status, ActionStatus::Success);
}

#[test]
fn a_channel_whose_record_fails_is_never_modified() {
    let (mut fake, facts) = server();
    fake.fail_record.insert(1);
    let outcome = apply(&mut fake, &facts);

    assert_eq!((outcome.locked, outcome.failed), (2, 1));
    assert!(!fake.calls.iter().any(|call| call == "write 1"));
}

#[test]
fn no_channel_locked_deletes_the_guild_row_and_fails() {
    let (mut fake, facts) = server();
    // Le salon 3 refusait déjà : on le retire pour n'avoir que des échecs.
    let facts = LockdownFacts {
        channels: facts.channels[..2].to_vec(),
        ..facts
    };
    fake.fail_write.extend([1, 2]);
    let outcome = apply(&mut fake, &facts);

    assert_eq!(outcome.start, LockdownStart::NoChannelLocked);
    assert_eq!(fake.guild, None, "ligne de guilde supprimée");
    assert!(fake.rows.is_empty());
    assert_eq!(fake.calls.last().map(String::as_str), Some("end"));
    let action = outcome.action_outcome();
    assert_eq!(action.status, ActionStatus::Failed);
    assert_eq!(action.failure_code, Some(FailureCode::MissingPermission));

    // Serveur sans salon : même issue.
    let mut empty = Fake::default();
    let outcome = apply(
        &mut empty,
        &LockdownFacts {
            manage_channels: Some(true),
            channels: Vec::new(),
        },
    );
    assert_eq!(outcome.start, LockdownStart::NoChannelLocked);
    assert_eq!(empty.guild, None);
}

#[test]
fn missing_manage_channels_fails_without_recording_anything() {
    let (mut fake, facts) = server();
    let facts = LockdownFacts {
        manage_channels: Some(false),
        ..facts
    };
    let outcome = apply(&mut fake, &facts);

    assert_eq!(outcome.start, LockdownStart::MissingPermission);
    assert!(fake.calls.is_empty(), "{:?}", fake.calls);
    assert_eq!(fake.guild, None);
    let action = outcome.action_outcome();
    assert_eq!(action.status, ActionStatus::Failed);
    assert_eq!(action.failure_code, Some(FailureCode::MissingPermission));
    assert_eq!(action.details.as_deref(), Some("MANAGE_CHANNELS"));

    // Permission inconnue du cache : les appels sont tentés.
    let (mut fake, facts) = server();
    let facts = LockdownFacts {
        manage_channels: None,
        ..facts
    };
    assert!(apply(&mut fake, &facts).applied());
}

#[test]
fn an_active_lifting_or_retrying_lockdown_is_never_relaunched() {
    for status in [
        LockdownStatus::Active,
        LockdownStatus::Lifting,
        LockdownStatus::Retry,
    ] {
        let (mut fake, facts) = server();
        fake.guild = Some((status, NOW + 42));
        // État d'origine encore attendu d'un salon.
        let original = RecordedChannel {
            send_messages: PermissionState::Allow,
            slowmode: None,
        };
        fake.rows.insert(1, original);

        let outcome = apply(&mut fake, &facts);
        assert_eq!(outcome.start, LockdownStart::AlreadyActive, "{status:?}");
        assert_eq!(fake.calls, ["begin"], "{status:?}");
        assert_eq!(fake.rows[&1], original, "état d'origine jamais écrasé");
        assert_eq!(fake.guild, Some((status, NOW + 42)));
        let action = outcome.action_outcome();
        assert_eq!(action.status, ActionStatus::Skipped);
        assert_eq!(action.details.as_deref(), Some("already_active"));
    }
}

#[test]
fn a_store_failure_on_begin_touches_nothing() {
    let (mut fake, facts) = server();
    fake.fail_begin = true;
    let outcome = apply(&mut fake, &facts);
    assert!(matches!(outcome.start, LockdownStart::StoreFailed(_)));
    assert_eq!(fake.calls, ["begin"]);
}

// --- Levée ---

#[test]
fn lift_restores_exactly_and_ends_the_lockdown() {
    let (mut fake, facts) = server();
    let original = fake.everyone.clone();
    apply(&mut fake, &facts);
    fake.calls.clear();

    let outcome = lift(&mut fake);
    assert_eq!(outcome.restored, 2);
    assert_eq!(outcome.unchanged, 1);
    assert_eq!((outcome.failed, outcome.missing_channels), (0, 0));
    assert!(!outcome.pending && outcome.ended);
    assert!(fake.rows.is_empty());
    assert_eq!(fake.guild, None);
    // Absent redevient absent, autorisé redevient autorisé.
    assert_eq!(fake.everyone, original);
    assert_eq!(fake.slowmode[&1], 0);
    assert_eq!(fake.slowmode[&2], 5);
    assert_eq!(fake.slowmode[&3], 30);
    assert_eq!(
        fake.calls,
        [
            "status lifting",
            "delete 1",
            "slowmode 1 0",
            "forget 1",
            "write 2",
            "slowmode 2 5",
            "forget 2",
            "forget 3",
            "end",
        ]
    );
    let action = outcome.action_outcome();
    assert_eq!(action.action, ActionCode::RestoreLockdown);
    assert_eq!(action.status, ActionStatus::Success);
}

#[test]
fn a_failed_lift_keeps_the_channel_locked_then_retries() {
    let (mut fake, facts) = server();
    apply(&mut fake, &facts);
    fake.fail_write.insert(2);

    let outcome = lift(&mut fake);
    assert_eq!((outcome.restored, outcome.failed), (1, 1));
    assert!(outcome.pending && !outcome.ended);
    assert!(fake.rows.contains_key(&2), "ligne conservée");
    // Toujours verrouillé.
    assert!(fake.everyone[&2].unwrap().deny.contains(SEND));
    assert_eq!(
        fake.guild,
        Some((
            LockdownStatus::Retry,
            NOW + LOCKDOWN_RETRY_INTERVAL.as_secs()
        ))
    );
    assert_eq!(outcome.action_outcome().status, ActionStatus::Partial);

    // Nouvelle tentative : le salon est enfin restauré.
    fake.fail_write.clear();
    fake.calls.clear();
    let retry = lift(&mut fake);
    assert_eq!((retry.restored, retry.failed), (1, 0));
    assert!(!retry.pending && retry.ended);
    assert_eq!(fake.guild, None);
    assert!(fake.everyone[&2].unwrap().allow.contains(SEND));
}

#[test]
fn a_slowmode_restore_failure_keeps_the_row_for_the_next_attempt() {
    let (mut fake, facts) = server();
    apply(&mut fake, &facts);
    fake.fail_slowmode.insert(1);

    let outcome = lift(&mut fake);
    assert_eq!(outcome.failed, 1);
    assert!(fake.rows.contains_key(&1));
    // L'écriture est déjà rendue : la tentative suivante ne refait que le
    // mode lent.
    fake.fail_slowmode.clear();
    fake.calls.clear();
    let retry = lift(&mut fake);
    assert!(retry.ended);
    assert_eq!(
        fake.calls,
        ["status lifting", "slowmode 1 0", "forget 1", "end"]
    );
}

#[test]
fn a_vanished_channel_has_nothing_to_restore_and_is_not_a_failure() {
    let (mut fake, facts) = server();
    apply(&mut fake, &facts);
    // Supprimé avant la levée (absent du cache)…
    fake.everyone.remove(&1);
    // … ou entre le cache et l'appel.
    fake.gone.insert(2);

    let outcome = lift(&mut fake);
    assert_eq!(outcome.missing_channels, 2);
    assert_eq!(outcome.failed, 0);
    assert!(!outcome.pending && outcome.ended);
    assert!(fake.rows.is_empty());
}

#[test]
fn lift_is_idempotent() {
    let (mut fake, facts) = server();
    apply(&mut fake, &facts);
    assert!(lift(&mut fake).ended);

    fake.calls.clear();
    let again = lift(&mut fake);
    assert!(again.nothing_to_do());
    assert!(
        !fake.calls.iter().any(|call| call.starts_with("write")
            || call.starts_with("delete")
            || call.starts_with("slowmode")),
        "{:?}",
        fake.calls
    );
}

#[test]
fn an_unresolvable_guild_is_retried_later_without_touching_anything() {
    let (mut fake, facts) = server();
    apply(&mut fake, &facts);
    fake.calls.clear();

    let outcome = run(lift_lockdown(
        &mut fake,
        &LiftFacts {
            channels: None,
            now: NOW,
            slowmode_seconds: LOCKDOWN_SLOWMODE_SECONDS,
        },
    ));
    assert!(outcome.unresolved && outcome.pending);
    assert_eq!(fake.rows.len(), 3);
    assert_eq!(fake.calls, ["status retry"]);
    assert_eq!(fake.guild, Some((LockdownStatus::Retry, NOW + 60)));
}

#[test]
fn audit_reasons_follow_the_foxsecura_convention() {
    let apply = lockdown_audit_reason(LockdownReason::AntiRaid);
    let restore = lockdown_restore_audit_reason(Some(LockdownReason::AntiRaid));
    assert_eq!(apply, "FoxSecura Anti-Raid: temporary lockdown");
    assert_eq!(restore, "FoxSecura Anti-Raid: lockdown restore");
    assert!(is_foxsecura_audit_reason(&apply));
    assert!(is_foxsecura_audit_reason(&restore));
    // Raison illisible (version plus récente) : préfixe conservé.
    assert!(is_foxsecura_audit_reason(&lockdown_restore_audit_reason(
        None
    )));
    assert_eq!(
        LockdownReason::from_key("anti_raid"),
        Some(LockdownReason::AntiRaid)
    );
    assert_eq!(LockdownReason::from_key("panic"), None);
}

// --- Échéance et reprise ---

fn state(guild_id: u64, status: LockdownStatus, lift_at: u64) -> LockdownState {
    LockdownState {
        guild_id,
        reason: Some(LockdownReason::AntiRaid),
        status,
        lift_at,
        slowmode_seconds: LOCKDOWN_SLOWMODE_SECONDS,
    }
}

#[test]
fn wake_action_lifts_when_due_and_sleeps_at_most_a_minute() {
    assert_eq!(wake_action(NOW, None), WakeAction::Stop);
    assert_eq!(
        wake_action(NOW, Some(&state(1, LockdownStatus::Active, NOW))),
        WakeAction::Lift
    );
    assert_eq!(
        wake_action(NOW, Some(&state(1, LockdownStatus::Active, NOW - 5))),
        WakeAction::Lift
    );
    assert_eq!(
        wake_action(NOW, Some(&state(1, LockdownStatus::Active, NOW + 30))),
        WakeAction::Sleep(Duration::from_secs(30))
    );
    assert_eq!(
        wake_action(NOW, Some(&state(1, LockdownStatus::Active, NOW + 600))),
        WakeAction::Sleep(LOCKDOWN_RETRY_INTERVAL)
    );
    assert_eq!(
        wake_action(NOW, Some(&state(1, LockdownStatus::Retry, NOW + 60))),
        WakeAction::Sleep(Duration::from_secs(60))
    );
    // Levée interrompue par un arrêt : reprise immédiate.
    assert_eq!(
        wake_action(NOW, Some(&state(1, LockdownStatus::Lifting, NOW + 600))),
        WakeAction::Lift
    );
}

#[test]
fn startup_lifts_expired_lockdowns_and_rearms_future_ones() {
    let plan = resume_plan(
        NOW,
        &[
            state(1, LockdownStatus::Active, NOW - 3_600),
            state(2, LockdownStatus::Active, NOW + 300),
            state(3, LockdownStatus::Retry, NOW - 1),
            state(4, LockdownStatus::Lifting, NOW + 300),
        ],
    );
    assert_eq!(
        plan,
        [
            (1, WakeAction::Lift),
            (2, WakeAction::Sleep(LOCKDOWN_RETRY_INTERVAL)),
            (3, WakeAction::Lift),
            (4, WakeAction::Lift),
        ]
    );
    assert!(resume_plan(NOW, &[]).is_empty());
}

#[test]
fn at_most_one_timer_per_guild() {
    let timers = LockdownTimers::new();
    assert!(timers.try_arm(1));
    assert!(!timers.try_arm(1));
    assert!(timers.try_arm(2));
    assert!(timers.is_armed(1));
    timers.disarm(1);
    assert!(!timers.is_armed(1));
    assert!(timers.try_arm(1));
}

#[tokio::test]
async fn operations_on_the_same_guild_never_interleave() {
    let locks = Arc::new(GuildLocks::new());
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));

    let first = locks.lock(1).await;
    let task = {
        let locks = Arc::clone(&locks);
        let order = Arc::clone(&order);
        tokio::spawn(async move {
            let _guard = locks.lock(1).await;
            order.lock().unwrap().push("second");
        })
    };
    tokio::task::yield_now().await;
    order.lock().unwrap().push("first");
    drop(first);
    task.await.unwrap();

    assert_eq!(*order.lock().unwrap(), ["first", "second"]);
    // Une autre guilde n'attend pas.
    let _other = locks.lock(2).await;
    assert!(locks.len() <= 1);
}

// --- Incident de levée ---

#[test]
fn lift_incident_is_published_on_completion_or_first_failure_only() {
    let done = LiftOutcome {
        restored: 3,
        ended: true,
        ..LiftOutcome::default()
    };
    let failing = LiftOutcome {
        restored: 1,
        failed: 2,
        pending: true,
        ..LiftOutcome::default()
    };
    let unresolved = LiftOutcome {
        unresolved: true,
        pending: true,
        ..LiftOutcome::default()
    };

    assert!(should_publish_lift(&done, Some(LockdownStatus::Active)));
    assert!(should_publish_lift(&done, Some(LockdownStatus::Retry)));
    assert!(should_publish_lift(&failing, Some(LockdownStatus::Active)));
    // Nouvelle tentative encore en échec : aucune republication.
    assert!(!should_publish_lift(&failing, Some(LockdownStatus::Retry)));
    assert!(!should_publish_lift(
        &unresolved,
        Some(LockdownStatus::Active)
    ));
    assert!(!should_publish_lift(&LiftOutcome::default(), None));

    let incident = lift_incident(Language::French, 42, &failing, LiftTrigger::Timer);
    assert_eq!(incident.log_type, LogType::Server);
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(incident.validate(), Ok(()));
    assert_eq!(incident.actions[0].action, ActionCode::RestoreLockdown);
    assert!(
        incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("toutes les minutes")
    );
    let staff = lift_incident(Language::English, 42, &done, LiftTrigger::Staff);
    assert_eq!(staff.severity, LogSeverity::Info);
    assert!(staff.summary.contains("by staff"));
}

#[test]
fn an_already_active_lockdown_seen_on_the_fast_path_writes_nothing() {
    let outcome = LockdownOutcome::already_active(12);
    assert_eq!(outcome.start, LockdownStart::AlreadyActive);
    assert_eq!((outcome.total, outcome.locked, outcome.failed), (12, 0, 0));
    assert!(!outcome.applied());
    assert_eq!(outcome.lift_at, None);
    let action = outcome.action_outcome();
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.details.as_deref(), Some("already_active"));
}

// --- Généralisation : durée et mode lent portés par la requête ---

#[test]
fn anti_raid_lockdown_is_unchanged_ten_minutes_and_ten_seconds() {
    let request = LockdownRequest::for_reason(LockdownReason::AntiRaid, NOW);
    assert_eq!(request.lift_at, NOW + 600);
    assert_eq!(request.slowmode_seconds, 10);
    assert_eq!(
        LockdownReason::AntiRaid.duration(),
        DEFAULT_LOCKDOWN_DURATION
    );
}

#[test]
fn panic_lockdown_is_fifteen_minutes_with_a_thirty_second_slowmode() {
    let request = LockdownRequest::for_reason(LockdownReason::PanicMode, NOW);
    assert_eq!(request.lift_at, NOW + 15 * 60);
    assert_eq!(request.slowmode_seconds, 30);
    assert_eq!(
        LockdownReason::from_key("panic_mode"),
        Some(LockdownReason::PanicMode)
    );
    assert_eq!(LockdownReason::PanicMode.key(), "panic_mode");
    let apply = lockdown_audit_reason(LockdownReason::PanicMode);
    assert_eq!(
        apply,
        "FoxSecura Panic Mode: correlated nuke signals detected"
    );
    assert!(is_foxsecura_audit_reason(&apply));
    assert_eq!(
        lockdown_restore_audit_reason(Some(LockdownReason::PanicMode)),
        "FoxSecura Panic Mode: lockdown restore"
    );
}

#[test]
fn slowmode_plans_follow_the_requested_value() {
    assert_eq!(lock_slowmode(0, true, 30), Some(30));
    assert_eq!(lock_slowmode(10, true, 30), Some(30));
    assert_eq!(lock_slowmode(30, true, 30), None);
    assert_eq!(lock_slowmode(60, true, 30), None);
    assert_eq!(lock_slowmode(0, false, 30), None);

    // La levée compare au mode lent enregistré avec le verrouillage.
    assert_eq!(plan_slowmode_restore(30, None, 30), Some(0));
    assert_eq!(plan_slowmode_restore(30, Some(5), 30), Some(5));
    assert_eq!(plan_slowmode_restore(30, Some(30), 30), None);
    assert_eq!(plan_slowmode_restore(45, Some(5), 30), None);
    // Avant la généralisation, la comparaison à 10 s laissait un salon
    // bloqué à 30 s pour toujours.
    assert_eq!(plan_slowmode_restore(30, Some(5), 10), None);
    // Aucun mode lent posé : jamais touché.
    assert_eq!(plan_slowmode_restore(0, None, 0), None);
}

#[test]
fn panic_lockdown_regression_lift_gives_back_the_previous_slowmode() {
    let (mut fake, facts) = server();
    let request = LockdownRequest::for_reason(LockdownReason::PanicMode, NOW);
    let outcome = run(apply_lockdown(&mut fake, &facts, request));

    assert_eq!(outcome.start, LockdownStart::Applied);
    assert_eq!(outcome.lift_at, Some(NOW + 900));
    assert_eq!(fake.guild, Some((LockdownStatus::Active, NOW + 900)));
    // Pose à 30 s ; le salon 3 était déjà à 30 s, il n'est pas touché.
    assert_eq!(fake.slowmode[&1], 30);
    assert_eq!(fake.slowmode[&2], 30);
    assert_eq!(fake.slowmode[&3], 30);
    assert!(fake.calls.contains(&"slowmode 1 30".to_owned()));
    assert!(!fake.calls.iter().any(|call| call.starts_with("slowmode 3")));

    fake.calls.clear();
    let facts = LiftFacts {
        channels: Some(fake.current()),
        now: NOW + 900,
        slowmode_seconds: request.slowmode_seconds,
    };
    let lifted = run(lift_lockdown(&mut fake, &facts));
    assert!(lifted.ended && !lifted.pending);
    // Chaque salon retrouve son ancien mode lent.
    assert_eq!(fake.slowmode[&1], 0);
    assert_eq!(fake.slowmode[&2], 5);
    assert_eq!(fake.slowmode[&3], 30);
    assert!(fake.rows.is_empty());
}

#[test]
fn anti_raid_lift_still_restores_only_its_ten_seconds() {
    let (mut fake, facts) = server();
    apply(&mut fake, &facts);
    assert_eq!((fake.slowmode[&1], fake.slowmode[&2]), (10, 10));
    // L'équipe change le mode lent du salon 2 pendant le verrouillage.
    fake.slowmode.insert(2, 60);

    let lifted = lift(&mut fake);
    assert!(lifted.ended);
    assert_eq!(fake.slowmode[&1], 0);
    assert_eq!(fake.slowmode[&2], 60, "réglage de l'équipe conservé");
    assert_eq!(fake.slowmode[&3], 30);
}
