// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Étape « mentions » de la chaîne des messages : anti-ping du propriétaire,
//! anti-spam de mentions, ordre et court-circuit.

use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{LogSeverity, SecurityEvidence, ThresholdUnit};
use foxsecura::protection::content_filter::{
    AuthorContext, ContentFinding, MentionBursts, MentionFacts, MentionStage, MessageContent,
    MessageEvent, MessageRoute, OWNER_PING_THRESHOLD, OWNER_PING_WINDOW, build_incident,
    route_message_with,
};
use foxsecura::protection::shared::{
    DeleteMessageOutcome, GuildMessage, MessageScope, ModuleSet, ProtectionModule,
};

const GUILD: u64 = 1;
const OWNER: u64 = 100;
const AUTHOR: u64 = 200;

fn modules(list: &[ProtectionModule]) -> ModuleSet {
    list.iter().copied().collect()
}

fn text_message(content: &str) -> MessageContent {
    MessageContent {
        content: content.to_owned(),
        ..MessageContent::default()
    }
}

fn facts<'a>(author_id: u64, seconds: u64, users: &'a [u64], roles: &'a [u64]) -> MentionFacts<'a> {
    MentionFacts {
        guild_id: GUILD,
        author_id,
        timestamp: Duration::from_secs(seconds),
        owner_id: Some(OWNER),
        users,
        roles,
    }
}

/// Route une création ou une modification avec l'étape « mentions ».
fn route(
    bursts: &mut MentionBursts,
    enabled: ModuleSet,
    scope: MessageScope,
    event: MessageEvent,
    message: &MessageContent,
    facts: MentionFacts<'_>,
) -> MessageRoute {
    route_message_with(
        scope,
        event,
        enabled,
        message,
        AuthorContext::default(),
        None,
        Some(MentionStage { bursts, facts }),
    )
}

fn created(
    bursts: &mut MentionBursts,
    enabled: ModuleSet,
    facts: MentionFacts<'_>,
) -> MessageRoute {
    route(
        bursts,
        enabled,
        MessageScope::Enforce,
        MessageEvent::Created,
        &text_message("salut"),
        facts,
    )
}

fn module_of(route: &MessageRoute) -> Option<ProtectionModule> {
    match route {
        MessageRoute::Filter(detection) => Some(detection.module),
        _ => None,
    }
}

// --- A. Anti-ping du propriétaire ---

#[test]
fn owner_ping_triggers_on_the_third_mention_within_thirty_seconds() {
    let enabled = modules(&[ProtectionModule::AntiPingOwner]);
    let mut bursts = MentionBursts::new();

    assert_eq!(OWNER_PING_THRESHOLD, 3);
    assert_eq!(OWNER_PING_WINDOW, Duration::from_secs(30));
    for second in [0, 10] {
        assert_eq!(
            created(&mut bursts, enabled, facts(AUTHOR, second, &[OWNER], &[])),
            MessageRoute::AntiSpam
        );
    }
    // Troisième ping à 30 s pile : encore dans la fenêtre.
    let route = created(&mut bursts, enabled, facts(AUTHOR, 30, &[OWNER], &[]));
    let MessageRoute::Filter(detection) = route else {
        panic!("le troisième ping doit déclencher");
    };
    assert_eq!(detection.module, ProtectionModule::AntiPingOwner);
    assert_eq!(
        detection.finding,
        ContentFinding::OwnerPing {
            count: 3,
            threshold: 3,
            window: Duration::from_secs(30),
        }
    );
}

#[test]
fn owner_pings_outside_the_window_do_not_add_up() {
    let enabled = modules(&[ProtectionModule::AntiPingOwner]);
    let mut bursts = MentionBursts::new();

    for second in [0, 20, 51] {
        assert_eq!(
            created(&mut bursts, enabled, facts(AUTHOR, second, &[OWNER], &[])),
            MessageRoute::AntiSpam,
            "seconde {second}"
        );
    }
}

#[test]
fn owner_ping_counts_real_mentions_only_and_never_the_owner() {
    let enabled = modules(&[ProtectionModule::AntiPingOwner]);
    let mut bursts = MentionBursts::new();

    // Le texte « @owner » sans mention résolue ne compte pas.
    for second in 0..5 {
        let route = route(
            &mut bursts,
            enabled,
            MessageScope::Enforce,
            MessageEvent::Created,
            &text_message("<@100> @owner"),
            facts(AUTHOR, second, &[7], &[]),
        );
        assert_eq!(route, MessageRoute::AntiSpam);
    }
    // Le propriétaire qui se mentionne lui-même n'est jamais retenu.
    for second in 0..5 {
        assert_eq!(
            created(&mut bursts, enabled, facts(OWNER, second, &[OWNER], &[])),
            MessageRoute::AntiSpam
        );
    }
    // Propriétaire inconnu (serveur absent du cache) : jamais de déclenchement.
    for second in 0..5 {
        let mut unknown = facts(AUTHOR, second, &[OWNER], &[]);
        unknown.owner_id = None;
        assert_eq!(
            created(&mut bursts, enabled, unknown),
            MessageRoute::AntiSpam
        );
    }
}

#[test]
fn owner_ping_bursts_are_isolated_per_author_and_guild() {
    let enabled = modules(&[ProtectionModule::AntiPingOwner]);
    let mut bursts = MentionBursts::new();

    created(&mut bursts, enabled, facts(AUTHOR, 0, &[OWNER], &[]));
    created(&mut bursts, enabled, facts(AUTHOR, 1, &[OWNER], &[]));
    // Un autre auteur, puis une autre guilde : comptés à part.
    assert_eq!(
        created(&mut bursts, enabled, facts(AUTHOR + 1, 2, &[OWNER], &[])),
        MessageRoute::AntiSpam
    );
    let mut other_guild = facts(AUTHOR, 2, &[OWNER], &[]);
    other_guild.guild_id = GUILD + 1;
    assert_eq!(
        created(&mut bursts, enabled, other_guild),
        MessageRoute::AntiSpam
    );
    assert_eq!(
        module_of(&created(
            &mut bursts,
            enabled,
            facts(AUTHOR, 3, &[OWNER], &[])
        )),
        Some(ProtectionModule::AntiPingOwner)
    );
}

#[test]
fn owner_ping_is_never_evaluated_for_edits_exempt_authors_or_when_disabled() {
    let enabled = modules(&[ProtectionModule::AntiPingOwner]);
    let mut bursts = MentionBursts::new();
    let message = text_message("salut");

    for second in 0..5 {
        let edited = route(
            &mut bursts,
            enabled,
            MessageScope::Enforce,
            MessageEvent::Edited,
            &message,
            facts(AUTHOR, second, &[OWNER], &[]),
        );
        assert_eq!(edited, MessageRoute::Skip);
        let exempt = route(
            &mut bursts,
            enabled,
            MessageScope::ExemptAuthor,
            MessageEvent::Created,
            &message,
            facts(AUTHOR, second, &[OWNER], &[]),
        );
        assert_eq!(exempt, MessageRoute::Skip);
        let ignored = route(
            &mut bursts,
            enabled,
            MessageScope::IgnoredChannel,
            MessageEvent::Created,
            &message,
            facts(AUTHOR, second, &[OWNER], &[]),
        );
        assert_eq!(ignored, MessageRoute::Skip);
        assert_eq!(
            created(
                &mut bursts,
                ModuleSet::empty(),
                facts(AUTHOR, second, &[OWNER], &[])
            ),
            MessageRoute::AntiSpam
        );
    }
    // Rien n'a été compté : aucune clé suivie.
    assert_eq!(bursts.tracked_key_count(), 0);
}

#[test]
fn owner_ping_incident_carries_the_burst_and_follows_the_deletion() {
    let message = GuildMessage {
        guild_id: GUILD,
        channel_id: 10,
        message_id: 20,
        author_id: AUTHOR,
        timestamp: Duration::from_secs(1),
    };
    let enabled = modules(&[ProtectionModule::AntiPingOwner]);
    let mut bursts = MentionBursts::new();
    let mut last = MessageRoute::Skip;
    for second in 0..3 {
        last = created(&mut bursts, enabled, facts(AUTHOR, second, &[OWNER], &[]));
    }
    let MessageRoute::Filter(detection) = last else {
        panic!("rafale attendue");
    };

    let content = text_message("salut");
    let deleted = build_incident(
        Language::French,
        &message,
        &detection,
        MessageEvent::Created,
        &content,
        &DeleteMessageOutcome::Deleted,
    );
    assert_eq!(deleted.module, "anti_ping_owner");
    assert_eq!(deleted.severity, LogSeverity::Warning);
    assert!(deleted.evidence.contains(&SecurityEvidence::Threshold {
        observed: 3,
        threshold: 3,
        window_seconds: Some(30),
        unit: ThresholdUnit::Messages,
    }));
    assert!(deleted.validate().is_ok());

    let kept = build_incident(
        Language::French,
        &message,
        &detection,
        MessageEvent::Created,
        &content,
        &DeleteMessageOutcome::NotDeletable,
    );
    assert_eq!(kept.severity, LogSeverity::Critical);
}
