// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    anti_spam::anti_ghost_ping::{AntiGhostPingDetector, GhostPingMessage},
    shared::ProtectionDecision,
};

fn message(message_id: u64, timestamp: u64) -> GhostPingMessage {
    GhostPingMessage {
        guild_id: 1,
        message_id,
        channel_id: 10,
        author_id: 20,
        mention_ids: vec![1, 2, 3, 4, 5],
        role_mention_ids: Vec::new(),
        mentions_everyone: false,
        timestamp: Duration::from_secs(timestamp),
    }
}

#[test]
fn deletion_after_mass_ping_is_blocked() {
    let mut detector = AntiGhostPingDetector::default();
    assert!(detector.record(message(1, 0)));
    let result = detector.detect_deleted(1, 1, Duration::from_secs(1));
    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(result.mention_count, 5);
}

#[test]
fn edit_removing_mentions_is_detected_once() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    let mut edited = message(1, 1);
    edited.mention_ids.clear();
    let result = detector.detect_updated(edited);
    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(2))
            .decision,
        ProtectionDecision::Allow
    );
}

#[test]
fn second_incident_marks_repeat_offense() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    assert!(
        !detector
            .detect_deleted(1, 1, Duration::from_secs(1))
            .repeat_offense
    );
    detector.record(message(2, 2));
    assert!(
        detector
            .detect_deleted(1, 2, Duration::from_secs(3))
            .repeat_offense
    );
}

// --- Tranche 10 : seuils, fenêtres, marquage et réponse ---

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, LogSeverity, SecurityEvidence};
use foxsecura::protection::anti_spam::anti_ghost_ping::{
    ANTI_GHOST_PING_REPEAT_REASON, AntiGhostPingDetectorConfig, BotDeletionMarks,
    GHOST_PING_MEMORY, GHOST_PING_MENTION_THRESHOLD, GHOST_PING_REPEAT_TIMEOUT,
    GHOST_PING_REPEAT_WINDOW, GhostPingEvent, GhostPingFollowUp, GhostPingIncidentInput,
    GhostPingOutcome, ghost_ping_incident, plan_ghost_ping_follow_up,
};
use foxsecura::protection::shared::{
    BotPermissions, BotStanding, SanctionContext, SanctionKind, SanctionOutcome, SanctionSkip,
    TargetLookup, TargetStanding, is_foxsecura_audit_reason, precheck_sanction,
};

fn with_mentions(message_id: u64, timestamp: u64, users: usize, roles: usize) -> GhostPingMessage {
    GhostPingMessage {
        mention_ids: (1..=users as u64).collect(),
        role_mention_ids: (100..100 + roles as u64).collect(),
        ..message(message_id, timestamp)
    }
}

#[test]
fn only_messages_with_five_users_or_roles_are_tracked() {
    let mut detector = AntiGhostPingDetector::default();
    assert_eq!(GHOST_PING_MENTION_THRESHOLD, 5);
    assert!(!detector.record(with_mentions(1, 0, 4, 0)));
    assert!(detector.record(with_mentions(2, 0, 3, 2)));
    assert_eq!(detector.tracked_message_count(), 1);
    // Un message non suivi supprimé ne produit rien.
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(1))
            .decision,
        ProtectionDecision::Allow
    );
    assert_eq!(
        detector
            .detect_deleted(1, 2, Duration::from_secs(1))
            .decision,
        ProtectionDecision::Block
    );
}

#[test]
fn deletion_counts_only_within_the_five_minute_memory() {
    assert_eq!(GHOST_PING_MEMORY, Duration::from_secs(300));
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    detector.record(message(2, 0));
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(300))
            .decision,
        ProtectionDecision::Block
    );
    assert_eq!(
        detector
            .detect_deleted(1, 2, Duration::from_secs(301))
            .decision,
        ProtectionDecision::Allow
    );
}

#[test]
fn an_edit_never_starts_tracking_a_message() {
    let mut detector = AntiGhostPingDetector::default();
    // Message jamais suivi (moins de 5 mentions à la création).
    let result = detector.detect_updated(with_mentions(1, 1, 6, 0));
    assert_eq!(result.decision, ProtectionDecision::Allow);
    assert_eq!(detector.tracked_message_count(), 0);
}

#[test]
fn an_edit_removing_fewer_than_five_mentions_is_not_a_ghost_ping() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(with_mentions(1, 0, 7, 0));
    let result = detector.detect_updated(with_mentions(1, 10, 3, 0));
    assert_eq!(result.decision, ProtectionDecision::Allow);
    assert_eq!(result.mention_count, 4);
    // La version suivie est mise à jour : supprimer ensuite le reste (3
    // mentions) ne fait pas un ghost ping de masse.
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(20))
            .decision,
        ProtectionDecision::Allow
    );
}

#[test]
fn edits_keep_the_creation_time_for_the_memory_window() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(with_mentions(1, 0, 6, 0));
    // Modification sans retrait à 200 s : la mémoire court depuis l'envoi.
    detector.detect_updated(with_mentions(1, 200, 6, 0));
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(301))
            .decision,
        ProtectionDecision::Allow
    );
}

#[test]
fn a_message_produces_at_most_one_incident() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    let mut edited = message(1, 1);
    edited.mention_ids.clear();
    assert_eq!(
        detector.detect_updated(edited.clone()).decision,
        ProtectionDecision::Block
    );
    assert_eq!(
        detector.detect_updated(edited).decision,
        ProtectionDecision::Allow
    );
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(2))
            .decision,
        ProtectionDecision::Allow
    );
    // Suppression, puis événement rejoué : un seul déclenchement.
    detector.record(message(2, 0));
    assert_eq!(
        detector
            .detect_deleted(1, 2, Duration::from_secs(1))
            .decision,
        ProtectionDecision::Block
    );
    assert_eq!(
        detector
            .detect_deleted(1, 2, Duration::from_secs(1))
            .decision,
        ProtectionDecision::Allow
    );
}

#[test]
fn repeat_offense_needs_two_ghost_pings_of_the_same_author_within_ten_minutes() {
    assert_eq!(GHOST_PING_REPEAT_WINDOW, Duration::from_secs(600));
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    assert!(
        !detector
            .detect_deleted(1, 1, Duration::from_secs(1))
            .repeat_offense
    );
    // Un autre auteur ne compte pas.
    let mut other = message(2, 2);
    other.author_id = 21;
    detector.record(other);
    assert!(
        !detector
            .detect_deleted(1, 2, Duration::from_secs(3))
            .repeat_offense
    );
    // Même auteur, 10 min 1 s plus tard : hors fenêtre.
    detector.record(message(3, 601));
    assert!(
        !detector
            .detect_deleted(1, 3, Duration::from_secs(602))
            .repeat_offense
    );
    // Même auteur dans la fenêtre : récidive.
    detector.record(message(4, 700));
    assert!(
        detector
            .detect_deleted(1, 4, Duration::from_secs(701))
            .repeat_offense
    );
}

#[test]
fn tracking_is_bounded() {
    let mut detector = AntiGhostPingDetector::new(AntiGhostPingDetectorConfig {
        max_tracked_messages: 3,
        ..AntiGhostPingDetectorConfig::default()
    });
    for id in 1..=10 {
        detector.record(message(id, id));
    }
    assert_eq!(detector.tracked_message_count(), 3);
    // Les plus anciens sont oubliés en premier.
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(11))
            .decision,
        ProtectionDecision::Allow
    );
    assert_eq!(
        detector
            .detect_deleted(1, 10, Duration::from_secs(11))
            .decision,
        ProtectionDecision::Block
    );
    let defaults = AntiGhostPingDetectorConfig::default();
    assert_eq!(defaults.max_tracked_messages, 5_000);
    assert_eq!(defaults.max_tracked_authors, 5_000);
}

// --- Suppressions faites par FoxSecura ---

#[test]
fn a_deletion_by_foxsecura_is_consumed_and_never_counted() {
    let mut detector = AntiGhostPingDetector::default();
    let mut marks = BotDeletionMarks::default();
    detector.record(message(1, 0));

    // Le runtime marque avant l'appel de suppression…
    marks.mark(1, 1, Duration::from_secs(1));
    // … puis, à la réception de MESSAGE_DELETE, consomme la marque et oublie
    // le message au lieu de le comparer.
    assert!(marks.take(1, 1, Duration::from_secs(1)));
    assert!(detector.discard(1, 1));
    assert_eq!(
        detector
            .detect_deleted(1, 1, Duration::from_secs(1))
            .decision,
        ProtectionDecision::Allow
    );
    // La marque ne sert qu'une fois.
    assert!(!marks.take(1, 1, Duration::from_secs(1)));
}

#[test]
fn a_failed_deletion_is_unmarked_and_marks_are_bounded() {
    let mut marks = BotDeletionMarks::new(Duration::from_secs(300), 2);
    marks.mark(1, 1, Duration::ZERO);
    marks.unmark(1, 1);
    assert!(!marks.take(1, 1, Duration::ZERO));

    // Marques d'une autre guilde : distinctes.
    marks.mark(1, 5, Duration::ZERO);
    assert!(!marks.take(2, 5, Duration::ZERO));

    // Capacité : la plus ancienne est oubliée.
    marks.mark(1, 6, Duration::from_secs(1));
    marks.mark(1, 7, Duration::from_secs(2));
    assert_eq!(marks.len(), 2);
    assert!(!marks.take(1, 5, Duration::from_secs(2)));
    assert!(marks.take(1, 7, Duration::from_secs(2)));

    // Durée de vie dépassée : la marque ne vaut plus.
    marks.mark(1, 8, Duration::ZERO);
    assert!(!marks.take(1, 8, Duration::from_secs(301)));
}

// --- Réponse ---

#[test]
fn only_a_repeat_offense_of_a_non_exempt_author_is_timed_out() {
    let timeout = SanctionKind::Timeout {
        duration: GHOST_PING_REPEAT_TIMEOUT,
    };
    assert_eq!(GHOST_PING_REPEAT_TIMEOUT, Duration::from_secs(300));
    assert_eq!(
        plan_ghost_ping_follow_up(false, false),
        GhostPingFollowUp::Alert
    );
    assert_eq!(
        plan_ghost_ping_follow_up(false, true),
        GhostPingFollowUp::Alert
    );
    assert_eq!(
        plan_ghost_ping_follow_up(true, false),
        GhostPingFollowUp::Sanction(timeout)
    );
    assert_eq!(
        plan_ghost_ping_follow_up(true, true),
        GhostPingFollowUp::ExemptMember(timeout)
    );
    assert!(is_foxsecura_audit_reason(ANTI_GHOST_PING_REPEAT_REASON));
    assert_eq!(
        ANTI_GHOST_PING_REPEAT_REASON,
        "FoxSecura Anti-Ghost Ping repeat offense"
    );
}

#[test]
fn the_guild_owner_is_never_timed_out_for_a_repeat_offense() {
    let GhostPingFollowUp::Sanction(kind) = plan_ghost_ping_follow_up(true, false) else {
        panic!("récidive attendue");
    };
    let context = SanctionContext {
        target_id: 20,
        bot_id: 1,
        owner_id: Some(20),
        bot: Some(BotStanding {
            top_role_position: 10,
            permissions: BotPermissions {
                administrator: true,
                ..BotPermissions::default()
            },
        }),
        target: TargetLookup::Found(TargetStanding {
            top_role_position: Some(0),
            administrator: Some(false),
        }),
    };
    assert_eq!(
        precheck_sanction(kind, &context),
        Err(SanctionOutcome::Skipped(SanctionSkip::GuildOwner))
    );
}

#[test]
fn incidents_attribute_the_ghost_ping_to_the_author_and_escalate_on_repeat() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    let first = detector.detect_deleted(1, 1, Duration::from_secs(1));
    let alert = ghost_ping_incident(
        Language::French,
        GhostPingIncidentInput {
            guild_id: 1,
            message_id: 1,
            event: GhostPingEvent::Deleted,
            result: &first,
        },
        &GhostPingOutcome::Alert,
    );
    assert_eq!(alert.module, "anti_ghost_ping");
    assert_eq!(alert.severity, LogSeverity::Warning);
    assert_eq!(alert.actor.as_ref().unwrap().user_id, "20");
    assert_eq!(alert.actions.len(), 1);
    assert_eq!(alert.actions[0].action, ActionCode::RecordAlert);
    assert!(alert.location.as_ref().unwrap().jump_url.is_none());
    assert!(alert.evidence.iter().any(|evidence| matches!(
        evidence,
        SecurityEvidence::Text { value, .. } if value.contains("user:1") && value.contains("user:5")
    )));
    assert!(alert.validate().is_ok());

    detector.record(message(2, 2));
    let repeat = detector.detect_deleted(1, 2, Duration::from_secs(3));
    let kind = SanctionKind::Timeout {
        duration: GHOST_PING_REPEAT_TIMEOUT,
    };
    let sanctioned = ghost_ping_incident(
        Language::French,
        GhostPingIncidentInput {
            guild_id: 1,
            message_id: 2,
            event: GhostPingEvent::Deleted,
            result: &repeat,
        },
        &GhostPingOutcome::Sanction {
            kind,
            outcome: SanctionOutcome::Applied,
        },
    );
    assert_eq!(sanctioned.severity, LogSeverity::Critical);
    assert_eq!(sanctioned.actions[1].action, ActionCode::TimeoutMember);
    assert_eq!(sanctioned.actions[1].status, ActionStatus::Success);
    assert!(sanctioned.validate().is_ok());

    let exempt = ghost_ping_incident(
        Language::French,
        GhostPingIncidentInput {
            guild_id: 1,
            message_id: 2,
            event: GhostPingEvent::Edited,
            result: &repeat,
        },
        &GhostPingOutcome::ExemptMember(kind),
    );
    assert_eq!(exempt.actions[1].action, ActionCode::IgnoreExemptMember);
    assert!(exempt.location.as_ref().unwrap().jump_url.is_some());
}
