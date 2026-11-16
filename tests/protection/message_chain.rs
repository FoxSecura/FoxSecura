// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Étape « mentions » de la chaîne des messages : anti-ping du propriétaire,
//! anti-spam de mentions, ordre et court-circuit.

use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{LogSeverity, SecurityEvidence, ThresholdUnit};
use foxsecura::protection::anti_spam::anti_spam_ping::{MentionTarget, MentionTargetKind};
use foxsecura::protection::automod::bad_words::{
    BadWordsLanguage, BadWordsMatcher, built_in_bad_words,
};
use foxsecura::protection::content_filter::{
    AuthorContext, CONTENT_FILTERS, ContentFinding, MENTION_SPAM_THRESHOLD, MENTION_SPAM_WINDOW,
    MESSAGE_CHAIN, MentionBursts, MentionFacts, MentionStage, MessageContent, MessageEvent,
    MessageRoute, OWNER_PING_THRESHOLD, OWNER_PING_WINDOW, build_incident, route_message_with,
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

// --- B. Anti-spam de mentions ---

fn spam_target(route: &MessageRoute) -> Option<(MentionTarget, usize)> {
    match route {
        MessageRoute::Filter(detection) => match detection.finding {
            ContentFinding::MentionSpam { target, count, .. } => Some((target, count)),
            _ => None,
        },
        _ => None,
    }
}

#[test]
fn mention_spam_triggers_on_the_third_mention_of_a_target_within_ten_seconds() {
    let enabled = modules(&[ProtectionModule::AntiSpamPing]);
    let mut bursts = MentionBursts::new();

    assert_eq!(MENTION_SPAM_THRESHOLD, 3);
    assert_eq!(MENTION_SPAM_WINDOW, Duration::from_secs(10));
    assert_eq!(
        created(&mut bursts, enabled, facts(AUTHOR, 0, &[7], &[])),
        MessageRoute::AntiSpam
    );
    assert_eq!(
        created(&mut bursts, enabled, facts(AUTHOR, 5, &[7], &[])),
        MessageRoute::AntiSpam
    );
    let route = created(&mut bursts, enabled, facts(AUTHOR, 10, &[7], &[]));
    assert_eq!(
        spam_target(&route),
        Some((
            MentionTarget {
                kind: MentionTargetKind::User,
                id: 7
            },
            3
        ))
    );
}

#[test]
fn mention_spam_outside_the_window_does_not_add_up() {
    let enabled = modules(&[ProtectionModule::AntiSpamPing]);
    let mut bursts = MentionBursts::new();

    for second in [0, 6, 17] {
        assert_eq!(
            created(&mut bursts, enabled, facts(AUTHOR, second, &[], &[9])),
            MessageRoute::AntiSpam,
            "seconde {second}"
        );
    }
}

#[test]
fn mention_spam_is_isolated_per_target_kind_and_author() {
    let enabled = modules(&[ProtectionModule::AntiSpamPing]);
    let mut bursts = MentionBursts::new();

    // Utilisateur 7 et rôle 7 sont deux cibles distinctes.
    created(&mut bursts, enabled, facts(AUTHOR, 0, &[7], &[]));
    created(&mut bursts, enabled, facts(AUTHOR, 1, &[7], &[]));
    assert_eq!(
        created(&mut bursts, enabled, facts(AUTHOR, 2, &[], &[7])),
        MessageRoute::AntiSpam
    );
    // Un autre auteur qui mentionne la même cible : compté à part.
    assert_eq!(
        created(&mut bursts, enabled, facts(AUTHOR + 1, 2, &[7], &[])),
        MessageRoute::AntiSpam
    );
    // Une autre cible du même auteur : comptée à part.
    assert_eq!(
        created(&mut bursts, enabled, facts(AUTHOR, 2, &[8], &[])),
        MessageRoute::AntiSpam
    );
    assert_eq!(
        spam_target(&created(&mut bursts, enabled, facts(AUTHOR, 3, &[7], &[]))).map(|(t, _)| t),
        Some(MentionTarget {
            kind: MentionTargetKind::User,
            id: 7
        })
    );
}

#[test]
fn mention_spam_reports_the_first_target_to_reach_the_threshold() {
    let enabled = modules(&[ProtectionModule::AntiSpamPing]);
    let mut bursts = MentionBursts::new();

    created(&mut bursts, enabled, facts(AUTHOR, 0, &[1], &[2]));
    created(&mut bursts, enabled, facts(AUTHOR, 1, &[], &[2]));
    // Le rôle 2 atteint le seuil avant l'utilisateur 1.
    let route = created(&mut bursts, enabled, facts(AUTHOR, 2, &[1], &[2]));
    assert_eq!(
        spam_target(&route),
        Some((
            MentionTarget {
                kind: MentionTargetKind::Role,
                id: 2
            },
            3
        ))
    );
}

#[test]
fn mention_spam_is_never_evaluated_for_edits_or_exempt_authors() {
    let enabled = modules(&[ProtectionModule::AntiSpamPing]);
    let mut bursts = MentionBursts::new();
    let message = text_message("salut");

    for second in 0..5 {
        for (scope, event) in [
            (MessageScope::Enforce, MessageEvent::Edited),
            (MessageScope::ExemptAuthor, MessageEvent::Created),
        ] {
            let route = route(
                &mut bursts,
                enabled,
                scope,
                event,
                &message,
                facts(AUTHOR, second, &[7], &[]),
            );
            assert_eq!(route, MessageRoute::Skip);
        }
    }
    assert_eq!(bursts.tracked_key_count(), 0);
}

// --- C. Ordre et court-circuit ---

fn all_modules() -> ModuleSet {
    ProtectionModule::ALL.into_iter().collect()
}

fn route_all(
    bursts: &mut MentionBursts,
    message: &MessageContent,
    matcher: &BadWordsMatcher,
    facts: MentionFacts<'_>,
) -> MessageRoute {
    route_message_with(
        MessageScope::Enforce,
        MessageEvent::Created,
        all_modules(),
        message,
        AuthorContext::default(),
        Some(matcher),
        Some(MentionStage { bursts, facts }),
    )
}

#[test]
fn message_chain_places_the_mention_stage_between_mass_mentions_and_bad_words() {
    let position = |module| MESSAGE_CHAIN.iter().position(|m| *m == module).unwrap();
    assert!(
        position(ProtectionModule::AntiMassMention) < position(ProtectionModule::AntiPingOwner)
    );
    assert!(position(ProtectionModule::AntiPingOwner) < position(ProtectionModule::AntiSpamPing));
    assert!(position(ProtectionModule::AntiSpamPing) < position(ProtectionModule::BadWords));
    // Les filtres de contenu gardent leur ordre relatif.
    let filters: Vec<_> = MESSAGE_CHAIN
        .iter()
        .copied()
        .filter(|module| CONTENT_FILTERS.contains(module))
        .collect();
    assert_eq!(filters, CONTENT_FILTERS);
}

#[test]
fn an_earlier_filter_short_circuits_the_mention_stage_without_counting() {
    let matcher = BadWordsMatcher::new(built_in_bad_words(BadWordsLanguage::French));
    let mut bursts = MentionBursts::new();
    let invite = text_message("discord.gg/raid");

    for second in 0..5 {
        let route = route_all(
            &mut bursts,
            &invite,
            &matcher,
            facts(AUTHOR, second, &[OWNER], &[]),
        );
        assert_eq!(module_of(&route), Some(ProtectionModule::AntiInvite));
    }
    // Aucune mention comptée : le filtre a arrêté la chaîne avant l'étape.
    assert_eq!(bursts.tracked_key_count(), 0);
}

#[test]
fn owner_ping_wins_over_mention_spam_and_mention_spam_over_bad_words() {
    let matcher = BadWordsMatcher::new(built_in_bad_words(BadWordsLanguage::French));
    let mut bursts = MentionBursts::new();
    let insult = text_message("quelle merde");
    let clean = text_message("salut");

    // Deux pings du propriétaire et d'un rôle : rien n'atteint le seuil.
    for second in 0..2 {
        let route = route_all(
            &mut bursts,
            &clean,
            &matcher,
            facts(AUTHOR, second, &[OWNER], &[5]),
        );
        assert_eq!(route, MessageRoute::AntiSpam);
    }
    // Troisième : les deux rafales atteindraient le seuil, le propriétaire
    // passe en premier et un seul module répond.
    let route = route_all(
        &mut bursts,
        &insult,
        &matcher,
        facts(AUTHOR, 2, &[OWNER], &[5]),
    );
    assert_eq!(module_of(&route), Some(ProtectionModule::AntiPingOwner));

    // Un autre auteur : spam de mentions d'un rôle, avec un mot interdit.
    let other = AUTHOR + 1;
    for second in 0..2 {
        let route = route_all(
            &mut bursts,
            &insult,
            &matcher,
            facts(other, second, &[], &[6]),
        );
        assert_eq!(module_of(&route), Some(ProtectionModule::BadWords));
    }
    let route = route_all(&mut bursts, &insult, &matcher, facts(other, 2, &[], &[6]));
    assert_eq!(module_of(&route), Some(ProtectionModule::AntiSpamPing));
}

#[test]
fn bad_words_still_apply_to_edits_and_exempt_authors_after_the_mention_stage() {
    let matcher = BadWordsMatcher::new(built_in_bad_words(BadWordsLanguage::French));
    let mut bursts = MentionBursts::new();
    let insult = text_message("quelle merde");

    for (scope, event) in [
        (MessageScope::Enforce, MessageEvent::Edited),
        (MessageScope::ExemptAuthor, MessageEvent::Created),
    ] {
        let route = route_message_with(
            scope,
            event,
            all_modules(),
            &insult,
            AuthorContext::default(),
            Some(&matcher),
            Some(MentionStage {
                bursts: &mut bursts,
                facts: facts(AUTHOR, 0, &[OWNER], &[]),
            }),
        );
        assert_eq!(module_of(&route), Some(ProtectionModule::BadWords));
    }
    assert_eq!(bursts.tracked_key_count(), 0);
}

#[test]
fn a_clean_creation_reaches_the_anti_spam_once_the_chain_is_exhausted() {
    let matcher = BadWordsMatcher::new(built_in_bad_words(BadWordsLanguage::French));
    let mut bursts = MentionBursts::new();
    let route = route_all(
        &mut bursts,
        &text_message("bonjour"),
        &matcher,
        facts(AUTHOR, 0, &[OWNER], &[]),
    );
    assert_eq!(route, MessageRoute::AntiSpam);
}
