// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Filtres de contenu : détection par module, ordre, court-circuit, portées,
//! modifications, révision et incident.

use std::time::Duration;

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::logs::{
    ActionStatus, FailureCode, LogSeverity, LogType, SecurityEvidence, ThresholdUnit,
    format_security_log_message,
};
use foxsecura::protection::anti_spam::message_flood::{MessageFloodConfig, MessageFloodTracker};
use foxsecura::protection::automod::bad_words::{
    BadWordsLanguage, BadWordsMatcher, built_in_bad_words,
};
use foxsecura::protection::content_filter::{
    AuthorContext, CONTENT_FILTERS, ContentDetection, ContentFinding, EXCERPT_MAX_CHARS,
    MASS_MENTION_THRESHOLD, MessageContent, MessageEvent, MessageRoute, RevisionCheck,
    build_incident, check_revision, detect_content, excerpt, revision_fetch_failure, route_message,
};
use foxsecura::protection::shared::{
    DeleteMessageOutcome, GuildMessage, MessageScope, ModuleSet, ProtectionModule,
};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn only(module: ProtectionModule) -> ModuleSet {
    [module].into_iter().collect()
}

fn all_modules() -> ModuleSet {
    ProtectionModule::ALL.into_iter().collect()
}

fn text_message(content: &str) -> MessageContent {
    MessageContent {
        content: content.to_owned(),
        ..MessageContent::default()
    }
}

/// Compte ancien et membre installé : seuls les signaux forts déclenchent.
fn established_author() -> AuthorContext {
    AuthorContext {
        now: Some(DAY * 400),
        account_created_at: Some(DAY),
        member_joined_at: Some(DAY * 2),
    }
}

fn detect(module: ProtectionModule, message: &MessageContent) -> Option<ContentFinding> {
    detect_content(only(module), message, established_author(), None).map(|detection| {
        assert_eq!(detection.module, module);
        detection.finding
    })
}

fn blocks(module: ProtectionModule, content: &str) -> bool {
    detect(module, &text_message(content)).is_some()
}

fn guild_message(message_id: u64, at_millis: u64) -> GuildMessage {
    GuildMessage {
        guild_id: 1,
        channel_id: 10,
        message_id,
        author_id: 42,
        timestamp: Duration::from_millis(at_millis),
    }
}

// --- Clés de module ---

#[test]
fn module_keys_round_trip_and_are_unique() {
    for module in ProtectionModule::ALL {
        assert_eq!(ProtectionModule::from_key(module.key()), Ok(module));
        assert_eq!(module.key().parse::<ProtectionModule>(), Ok(module));
        assert_eq!(
            ProtectionModule::ALL
                .iter()
                .filter(|other| other.key() == module.key())
                .count(),
            1
        );
    }
}

#[test]
fn unknown_module_keys_are_refused() {
    for key in [
        "",
        "anti_nuke",
        "anti_spam",
        "ANTI_SCAM",
        "MALICIOUS_LINK",
        "malicious_link ",
        "malicious-link",
    ] {
        let error = ProtectionModule::from_key(key).unwrap_err();
        assert_eq!(error.0, key);
        assert!(error.to_string().contains("inconnu"));
    }
}

#[test]
fn module_set_is_empty_by_default_and_toggles_each_module() {
    let mut set = ModuleSet::default();
    assert!(set.is_empty());

    for module in ProtectionModule::ALL {
        set.set(module, true);
        assert!(set.contains(module));
    }
    set.set(ProtectionModule::AdultLink, false);
    assert!(!set.contains(ProtectionModule::AdultLink));
    assert!(set.contains(ProtectionModule::AntiInvite));
}

#[test]
fn every_content_filter_is_a_known_module_in_v1_order() {
    assert_eq!(
        CONTENT_FILTERS.map(ProtectionModule::key),
        [
            "attachment_filter",
            "invisible_char_filter",
            "anti_scam",
            "malicious_link",
            "adult_link",
            "anti_invite",
            "anti_everyone",
            "anti_mass_mention",
            "bad_words",
        ]
    );
}

#[test]
fn disabled_modules_never_trigger() {
    let message = MessageContent {
        content: "\u{200b} https://grabify.link/x https://pornhub.com discord.gg/abc".to_owned(),
        mentions_everyone: true,
        mention_count: 50,
        attachments: Vec::new(),
    };
    assert_eq!(
        detect_content(ModuleSet::empty(), &message, established_author(), None),
        None
    );
}

// --- Caractères invisibles ---

#[test]
fn invisible_characters_are_blocked() {
    for content in [
        "bon\u{200b}jour",
        "\u{feff}salut",
        "tag\u{e0041}",
        "\u{3164}",
        "latin \u{061c} mark",
    ] {
        assert!(
            blocks(ProtectionModule::InvisibleCharFilter, content),
            "{content:?}"
        );
    }
}

#[test]
fn bidirectional_overrides_and_unpaired_isolates_are_blocked() {
    assert!(blocks(
        ProtectionModule::InvisibleCharFilter,
        "fichier\u{202e}txt.exe"
    ));
    assert!(blocks(
        ProtectionModule::InvisibleCharFilter,
        "début \u{2066}sans fin"
    ));
    // Isolat correctement fermé : usage légitime.
    assert!(!blocks(
        ProtectionModule::InvisibleCharFilter,
        "début \u{2066}isolé\u{2069} fin"
    ));
}

#[test]
fn zalgo_boundary_is_five_stacked_marks() {
    let four = format!("a{}", "\u{0301}".repeat(4));
    let five = format!("a{}", "\u{0301}".repeat(5));
    assert!(!blocks(ProtectionModule::InvisibleCharFilter, &four));
    assert!(blocks(ProtectionModule::InvisibleCharFilter, &five));
}

#[test]
fn legitimate_unicode_text_is_allowed() {
    for content in [
        "",
        "Bonjour, ça va ? Élégant, naïve, Straße",
        "e\u{0301}té décomposé",
        "Émojis ❤️ 👍🏽 👨‍👩‍👧",
        "مرحبا \u{061c}بالعالم",
        "日本語のテキスト",
    ] {
        assert!(
            !blocks(ProtectionModule::InvisibleCharFilter, content),
            "{content:?}"
        );
    }
}

// --- Liens malveillants ---

#[test]
fn malicious_links_are_blocked_whatever_their_case() {
    for content in [
        "https://grabify.link/abc",
        "HTTPS://GRABIFY.LINK/ABC",
        "regarde https://steamcommunity.ru/gift",
        "https://discord.gift/xyz",
        "free nitro ici : https://discord-nitro.example/claim",
        "https://bit.ly/3abc",
    ] {
        assert!(
            blocks(ProtectionModule::MaliciousLink, content),
            "{content}"
        );
    }
}

#[test]
fn official_and_ordinary_links_are_allowed() {
    for content in [
        "https://discord.com/channels/1/2/3",
        "https://steamcommunity.com/id/foxsecura",
        "https://example.com/article",
        "pas de lien du tout",
    ] {
        assert!(
            !blocks(ProtectionModule::MaliciousLink, content),
            "{content}"
        );
    }
}

#[test]
fn risky_links_are_blocked_only_for_accounts_younger_than_seven_days() {
    let message = text_message("connecte-toi sur http://192.168.10.20/login");
    let context = |age: Duration| AuthorContext {
        now: Some(DAY * 100),
        account_created_at: Some(DAY * 100 - age),
        member_joined_at: Some(DAY),
    };

    let fresh = detect_content(
        only(ProtectionModule::MaliciousLink),
        &message,
        context(DAY * 7 - Duration::from_secs(1)),
        None,
    );
    assert!(matches!(
        fresh.map(|detection| detection.finding),
        Some(ContentFinding::MaliciousLink { .. })
    ));

    // Borne : exactement sept jours n'est plus un compte récent.
    assert_eq!(
        detect_content(
            only(ProtectionModule::MaliciousLink),
            &message,
            context(DAY * 7),
            None,
        ),
        None
    );
}

// --- Liens adultes ---

#[test]
fn adult_links_are_blocked_whatever_their_case() {
    for content in [
        "https://www.pornhub.com/view_video",
        "HTTPS://WWW.PORNHUB.COM",
        "https://example.xxx/",
        "https://cdn.example.com/nsfw/image.png",
    ] {
        assert!(blocks(ProtectionModule::AdultLink, content), "{content}");
    }
}

#[test]
fn legitimate_links_with_adult_substrings_are_allowed() {
    for content in [
        "https://www.essex.ac.uk/",
        "https://sussex.example.org/news",
        "https://notporn.example.com/",
        "on parle de sexe sans lien",
    ] {
        assert!(!blocks(ProtectionModule::AdultLink, content), "{content}");
    }
}

#[test]
fn adult_link_evidence_is_the_detected_host() {
    assert_eq!(
        detect(
            ProtectionModule::AdultLink,
            &text_message("vu sur https://WWW.PornHub.com/x")
        ),
        Some(ContentFinding::AdultLink {
            host: "www.pornhub.com".to_owned()
        })
    );
}

// --- Invitations Discord ---

#[test]
fn discord_invites_are_blocked_with_or_without_scheme_or_case() {
    for content in [
        "discord.gg/raid",
        "https://DISCORD.GG/Raid",
        "rejoins https://discord.com/invite/abc-123",
        "https://discordapp.com/invite/abc",
        "(dsc.gg/serveur)",
    ] {
        assert!(blocks(ProtectionModule::AntiInvite, content), "{content}");
    }
}

#[test]
fn non_invite_discord_links_and_lookalikes_are_allowed() {
    for content in [
        "https://discord.gg/",
        "https://discord.com/channels/1/2",
        "https://fakediscord.gg/abc",
        "discord gg slash raid",
    ] {
        assert!(!blocks(ProtectionModule::AntiInvite, content), "{content}");
    }
}

// --- @everyone / @here ---

#[test]
fn broadcast_mentions_are_blocked_when_discord_flags_them() {
    let message = MessageContent {
        content: "@everyone venez vite".to_owned(),
        mentions_everyone: true,
        mention_count: 0,
        attachments: Vec::new(),
    };
    assert_eq!(
        detect(ProtectionModule::AntiEveryone, &message),
        Some(ContentFinding::BroadcastMention)
    );
}

#[test]
fn broadcast_text_that_notified_nobody_is_allowed() {
    // Sans le droit de mentionner tout le monde, Discord ne notifie personne
    // et ne lève pas l'indicateur : rien à supprimer. Même chose pour une
    // variante de casse, que Discord ne reconnaît pas.
    for content in ["@everyone", "@here", "@EVERYONE", "`@everyone`"] {
        assert!(
            !blocks(ProtectionModule::AntiEveryone, content),
            "{content}"
        );
    }
}

// --- Mentions de masse ---

#[test]
fn mass_mention_threshold_is_inclusive() {
    let mentions = |count| MessageContent {
        content: "salut".to_owned(),
        mentions_everyone: false,
        mention_count: count,
        attachments: Vec::new(),
    };

    assert_eq!(MASS_MENTION_THRESHOLD, 5);
    assert_eq!(
        detect(ProtectionModule::AntiMassMention, &mentions(0)),
        None
    );
    assert_eq!(
        detect(ProtectionModule::AntiMassMention, &mentions(4)),
        None
    );
    assert_eq!(
        detect(ProtectionModule::AntiMassMention, &mentions(5)),
        Some(ContentFinding::MassMention {
            count: 5,
            threshold: 5
        })
    );
    assert!(detect(ProtectionModule::AntiMassMention, &mentions(40)).is_some());
}

// --- Ordre et court-circuit ---

#[test]
fn modules_are_evaluated_in_v1_order_and_the_first_one_wins() {
    let message = MessageContent {
        content: "\u{200b} https://grabify.link/x https://pornhub.com discord.gg/abc merde"
            .to_owned(),
        mentions_everyone: true,
        mention_count: MASS_MENTION_THRESHOLD,
        attachments: vec!["facture.pdf.exe".to_owned()],
    };
    let matcher = BadWordsMatcher::new(built_in_bad_words(BadWordsLanguage::French));

    // Chaque module déclenche sur ce message : en retirant tour à tour le
    // premier, on retrouve exactement l'ordre de la spécification.
    let mut enabled = all_modules();
    for expected in CONTENT_FILTERS {
        let detection =
            detect_content(enabled, &message, established_author(), Some(&matcher)).unwrap();
        assert_eq!(detection.module, expected);
        enabled.set(expected, false);
    }
    assert_eq!(
        detect_content(enabled, &message, established_author(), Some(&matcher)),
        None
    );
}

#[test]
fn a_filtered_message_is_never_sent_to_anti_spam() {
    let message = text_message("discord.gg/raid");
    let route = route_message(
        MessageScope::Enforce,
        MessageEvent::Created,
        all_modules(),
        &message,
        established_author(),
        None,
    );

    // Un seul module retenu, donc une seule suppression et un seul incident.
    assert_eq!(
        route,
        MessageRoute::Filter(ContentDetection {
            module: ProtectionModule::AntiInvite,
            finding: ContentFinding::Invite {
                invite: "discord.gg/raid".to_owned()
            },
        })
    );
}

#[test]
fn filtered_messages_are_not_counted_by_anti_spam() {
    let flood = MessageFloodConfig::new(true, 2, 5);
    let run = |first: &str| {
        let mut tracker = MessageFloodTracker::default();
        [first, "message propre"]
            .into_iter()
            .enumerate()
            .filter_map(|(index, content)| {
                let route = route_message(
                    MessageScope::Enforce,
                    MessageEvent::Created,
                    only(ProtectionModule::AntiInvite),
                    &text_message(content),
                    established_author(),
                    None,
                );
                (route == MessageRoute::AntiSpam).then(|| {
                    tracker.observe(&flood, &guild_message(index as u64 + 1, index as u64 * 100))
                })
            })
            .last()
            .flatten()
    };

    // Deux messages propres atteignent le seuil de 2…
    assert!(run("premier message").is_some_and(|detection| detection.is_triggered()));
    // …mais une invitation supprimée par le filtre ne compte pas.
    assert!(!run("discord.gg/raid").is_some_and(|detection| detection.is_triggered()));
}

// --- Portées (liste blanche et salons ignorés) ---

#[test]
fn ignored_channel_skips_every_protection() {
    for event in [MessageEvent::Created, MessageEvent::Edited] {
        for content in ["https://grabify.link/x", "message propre"] {
            assert_eq!(
                route_message(
                    MessageScope::IgnoredChannel,
                    event,
                    all_modules(),
                    &text_message(content),
                    established_author(),
                    None,
                ),
                MessageRoute::Skip
            );
        }
    }
}

#[test]
fn exempt_author_gets_content_corrections_but_no_anti_spam() {
    let filtered = route_message(
        MessageScope::ExemptAuthor,
        MessageEvent::Created,
        all_modules(),
        &text_message("https://grabify.link/x"),
        established_author(),
        None,
    );
    // Avec tous les modules, l'anti-arnaque (avant les liens malveillants)
    // retient le lien : c'est lui qui gradue la réponse.
    assert!(matches!(
        filtered,
        MessageRoute::Filter(ContentDetection {
            module: ProtectionModule::AntiScam,
            ..
        })
    ));

    assert_eq!(
        route_message(
            MessageScope::ExemptAuthor,
            MessageEvent::Created,
            all_modules(),
            &text_message("message propre"),
            established_author(),
            None,
        ),
        MessageRoute::Skip
    );
}

#[test]
fn enforced_author_gets_filters_then_anti_spam() {
    assert!(matches!(
        route_message(
            MessageScope::Enforce,
            MessageEvent::Created,
            all_modules(),
            &text_message("https://grabify.link/x"),
            established_author(),
            None,
        ),
        MessageRoute::Filter(_)
    ));
    assert_eq!(
        route_message(
            MessageScope::Enforce,
            MessageEvent::Created,
            all_modules(),
            &text_message("message propre"),
            established_author(),
            None,
        ),
        MessageRoute::AntiSpam
    );
    // Aucun module activé : l'anti-spam reste consulté.
    assert_eq!(
        route_message(
            MessageScope::Enforce,
            MessageEvent::Created,
            ModuleSet::empty(),
            &text_message("https://grabify.link/x"),
            established_author(),
            None,
        ),
        MessageRoute::AntiSpam
    );
}

// --- Modifications ---

#[test]
fn an_edit_that_makes_a_message_malicious_is_filtered() {
    let modules = only(ProtectionModule::MaliciousLink);
    let original = text_message("lien utile : https://example.com");
    let edited = text_message("lien utile : https://grabify.link/abc");

    assert_eq!(
        route_message(
            MessageScope::Enforce,
            MessageEvent::Created,
            modules,
            &original,
            established_author(),
            None,
        ),
        MessageRoute::AntiSpam
    );
    assert!(matches!(
        route_message(
            MessageScope::Enforce,
            MessageEvent::Edited,
            modules,
            &edited,
            established_author(),
            None,
        ),
        MessageRoute::Filter(ContentDetection {
            module: ProtectionModule::MaliciousLink,
            ..
        })
    ));
}

#[test]
fn edits_are_never_counted_by_anti_spam() {
    for scope in [MessageScope::Enforce, MessageScope::ExemptAuthor] {
        assert_eq!(
            route_message(
                scope,
                MessageEvent::Edited,
                all_modules(),
                &text_message("correction d'une faute"),
                established_author(),
                None,
            ),
            MessageRoute::Skip
        );
    }
}

#[test]
fn only_the_current_revision_is_deleted() {
    let analyzed = text_message("https://grabify.link/abc");
    let corrected = text_message("désolé, lien retiré");

    let current = check_revision(&analyzed, Some(&analyzed.clone()));
    assert_eq!(current, RevisionCheck::Current);
    assert!(current.allows_deletion());

    // Corrigé entre-temps : la version analysée n'est plus courante.
    let superseded = check_revision(&analyzed, Some(&corrected));
    assert_eq!(superseded, RevisionCheck::Superseded);
    assert!(!superseded.allows_deletion());

    // Mentions changées sans changer le texte : autre version aussi.
    let mut mentions_changed = analyzed.clone();
    mentions_changed.mention_count = 3;
    assert_eq!(
        check_revision(&analyzed, Some(&mentions_changed)),
        RevisionCheck::Superseded
    );

    let deleted = check_revision(&analyzed, None);
    assert_eq!(deleted, RevisionCheck::Deleted);
    assert!(!deleted.allows_deletion());
}

#[test]
fn revision_fetch_failures_are_classified() {
    assert_eq!(revision_fetch_failure(Some(404), "Unknown Message"), None);
    assert_eq!(
        revision_fetch_failure(Some(403), "Missing Access"),
        Some(DeleteMessageOutcome::Failed {
            failure_code: FailureCode::MissingPermission,
            details: "Missing Access".to_owned(),
        })
    );
    for status in [Some(429), Some(503), None] {
        assert!(matches!(
            revision_fetch_failure(status, "x"),
            Some(DeleteMessageOutcome::Failed {
                failure_code: FailureCode::DiscordUnavailable,
                ..
            })
        ));
    }
    assert!(matches!(
        revision_fetch_failure(Some(400), "x"),
        Some(DeleteMessageOutcome::Failed {
            failure_code: FailureCode::Unknown,
            ..
        })
    ));
}

// --- Incident ---

fn detection(module: ProtectionModule, finding: ContentFinding) -> ContentDetection {
    ContentDetection { module, finding }
}

#[test]
fn deleted_message_produces_a_warning_incident_with_module_evidence() {
    let content = text_message("vu sur https://www.pornhub.com/x");
    let incident = build_incident(
        Language::French,
        &guild_message(77, 0),
        &detection(
            ProtectionModule::AdultLink,
            ContentFinding::AdultLink {
                host: "www.pornhub.com".to_owned(),
            },
        ),
        MessageEvent::Created,
        &content,
        &DeleteMessageOutcome::Deleted,
    );

    assert_eq!(incident.module, "adult_link");
    assert_eq!(incident.log_type, LogType::Message);
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(
        incident.summary,
        text(Language::French, TextKey::ContentFilterSummaryAdultLink)
    );
    assert_eq!(incident.actions.len(), 1);
    assert_eq!(incident.actions[0].status, ActionStatus::Success);
    assert_eq!(
        incident.evidence,
        vec![
            SecurityEvidence::Domain {
                domain: "www.pornhub.com".to_owned(),
                signals: Vec::new(),
                score: None,
            },
            SecurityEvidence::Content {
                excerpt: content.content.clone(),
            },
        ]
    );
    assert_eq!(incident.actor.as_ref().unwrap().user_id, "42");
    assert_eq!(
        incident.location.as_ref().unwrap().jump_url.as_deref(),
        Some("https://discord.com/channels/1/10/77")
    );
    assert_eq!(incident.validate(), Ok(()));
}

#[test]
fn undeletable_message_produces_a_critical_incident() {
    let incident = build_incident(
        Language::English,
        &guild_message(78, 0),
        &detection(
            ProtectionModule::AntiMassMention,
            ContentFinding::MassMention {
                count: 7,
                threshold: 5,
            },
        ),
        MessageEvent::Edited,
        &MessageContent::default(),
        &DeleteMessageOutcome::NotDeletable,
    );

    assert_eq!(incident.module, "anti_mass_mention");
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.actions[0].status, ActionStatus::Skipped);
    assert_eq!(
        incident.actions[0].failure_code,
        Some(FailureCode::MissingPermission)
    );
    assert_eq!(
        incident.evidence[0],
        SecurityEvidence::Threshold {
            observed: 7,
            threshold: 5,
            window_seconds: None,
            unit: ThresholdUnit::Mentions,
        }
    );
    // Modification signalée ; contenu vide non recopié.
    assert_eq!(incident.evidence.len(), 2);
    assert!(matches!(
        &incident.evidence[1],
        SecurityEvidence::Text { value, .. } if value == text(Language::English, TextKey::ContentFilterEventEdited)
    ));
    assert_eq!(
        incident.recommendation.as_deref(),
        Some(text(
            Language::English,
            TextKey::AntiSpamRecommendationCheckPermissions
        ))
    );
    assert_eq!(incident.validate(), Ok(()));
}

#[test]
fn failed_deletion_is_critical_for_every_module() {
    let failed = DeleteMessageOutcome::Failed {
        failure_code: FailureCode::DiscordUnavailable,
        details: "503".to_owned(),
    };
    let findings = [
        ContentFinding::Obfuscation {
            reason: "Invisible character detected: U+200B".to_owned(),
        },
        ContentFinding::MaliciousLink {
            pattern: "grabify.link/abc".to_owned(),
            reason: "Suspicious link pattern detected".to_owned(),
        },
        ContentFinding::AdultLink {
            host: "pornhub.com".to_owned(),
        },
        ContentFinding::Invite {
            invite: "discord.gg/raid".to_owned(),
        },
        ContentFinding::BroadcastMention,
        ContentFinding::MassMention {
            count: 5,
            threshold: 5,
        },
    ];

    for (module, finding) in CONTENT_FILTERS.into_iter().zip(findings) {
        let incident = build_incident(
            Language::German,
            &guild_message(1, 0),
            &detection(module, finding),
            MessageEvent::Created,
            &text_message("x"),
            &failed,
        );
        assert_eq!(incident.module, module.key());
        assert_eq!(incident.severity, LogSeverity::Critical);
        assert_eq!(incident.actions[0].status, ActionStatus::Failed);
        assert!(!incident.evidence.is_empty());
        assert_eq!(incident.validate(), Ok(()), "{module}");
    }
}

#[test]
fn excerpt_is_truncated_on_character_boundaries() {
    let short = "é".repeat(EXCERPT_MAX_CHARS);
    assert_eq!(excerpt(&short), short);

    let long = "é".repeat(EXCERPT_MAX_CHARS + 1);
    let truncated = excerpt(&long);
    assert_eq!(truncated.chars().count(), EXCERPT_MAX_CHARS + 1);
    assert!(truncated.ends_with('…'));
}

#[test]
fn hostile_content_cannot_ping_or_inject_formatting_in_the_log_channel() {
    let hostile = "@everyone <@123> <@&456> **gras** ||spoiler|| `x` [clic](https://evil.example)\nModule: faux\u{202e}txt.exe\u{200b}";
    let incident = build_incident(
        Language::French,
        &guild_message(79, 0),
        &detection(
            ProtectionModule::MaliciousLink,
            ContentFinding::MaliciousLink {
                pattern: "evil.example`**x**".to_owned(),
                reason: "Suspicious link pattern detected".to_owned(),
            },
        ),
        MessageEvent::Created,
        &text_message(hostile),
        &DeleteMessageOutcome::Deleted,
    );

    let rendered = format_security_log_message(Language::French, &incident);
    let evidence_lines: Vec<&str> = rendered
        .lines()
        .filter(|line| line.starts_with(text(Language::French, TextKey::LogsFieldEvidence)))
        .collect();

    // Le retour à la ligne du contenu ne crée pas de fausse ligne de log.
    assert_eq!(evidence_lines.len(), 2);
    assert!(
        !rendered
            .lines()
            .any(|line| line.starts_with("Module: faux"))
    );

    for line in &evidence_lines {
        // Chaque valeur non fiable est dans un code en ligne fermé : deux
        // accents graves par valeur, aucun apporté par le contenu.
        let (_, value) = line.split_once(" = ").unwrap();
        assert!(value.starts_with('`'), "{line}");
        assert_eq!(value.matches('`').count() % 2, 0, "{line}");
        assert!(
            !line.contains('\u{202e}') && !line.contains('\u{200b}'),
            "{line}"
        );
    }

    let excerpt_line = evidence_lines[1];
    let (_, excerpt_value) = excerpt_line.split_once(" = ").unwrap();
    assert!(excerpt_value.starts_with('`') && excerpt_value.ends_with('`'));
    assert_eq!(excerpt_value.matches('`').count(), 2);
    assert!(excerpt_value.contains("<@123>"));
    assert!(excerpt_value.contains('\u{fffd}'));

    // Domaine neutralisé : plus un lien, même hors du bloc de code.
    let domain_line = evidence_lines[0];
    assert!(domain_line.contains("evil[.]example"));
    assert!(!domain_line.contains("evil.example"));

    // Aucune mention ni aucun lien brut hors code en ligne.
    let outside_code: String = rendered.split('`').step_by(2).collect::<Vec<_>>().join("");
    for forbidden in ["@everyone", "<@123>", "<@&456>", "**", "||", "https://evil"] {
        assert!(!outside_code.contains(forbidden), "{forbidden}");
    }
}

// --- Chaîne complète V1 : pièces jointes et anti-arnaque ---

#[test]
fn anti_scam_runs_before_malicious_links_and_grades_the_response() {
    let modules: ModuleSet = [ProtectionModule::AntiScam, ProtectionModule::MaliciousLink]
        .into_iter()
        .collect();
    let route = route_message(
        MessageScope::Enforce,
        MessageEvent::Created,
        modules,
        &text_message("https://grabify.link/x"),
        established_author(),
        None,
    );
    // Un seul module retenu : l'anti-arnaque, jamais les deux.
    assert!(matches!(
        route,
        MessageRoute::Filter(ContentDetection {
            module: ProtectionModule::AntiScam,
            ..
        })
    ));

    // Sans l'anti-arnaque, le filtre de liens prend le relais.
    assert!(matches!(
        route_message(
            MessageScope::Enforce,
            MessageEvent::Created,
            only(ProtectionModule::MaliciousLink),
            &text_message("https://grabify.link/x"),
            established_author(),
            None,
        ),
        MessageRoute::Filter(ContentDetection {
            module: ProtectionModule::MaliciousLink,
            ..
        })
    ));
}

#[test]
fn low_confidence_scam_falls_through_to_the_next_filters() {
    // « urgent » seul : confiance basse, l'anti-arnaque laisse passer et le
    // mot interdit qui suit est retenu.
    let matcher = BadWordsMatcher::new(["zut"]);
    let route = route_message(
        MessageScope::Enforce,
        MessageEvent::Created,
        [ProtectionModule::AntiScam, ProtectionModule::BadWords]
            .into_iter()
            .collect(),
        &text_message("urgent, zut"),
        established_author(),
        Some(&matcher),
    );
    assert!(matches!(
        route,
        MessageRoute::Filter(ContentDetection {
            module: ProtectionModule::BadWords,
            ..
        })
    ));
}

#[test]
fn dangerous_attachment_comes_first_and_short_circuits_the_chain() {
    let matcher = BadWordsMatcher::new(["zut"]);
    let message = MessageContent {
        content: "\u{200b} urgent verify your account https://grabify.link/x zut".to_owned(),
        attachments: vec!["facture.pdf.exe".to_owned()],
        ..MessageContent::default()
    };
    let route = route_message(
        MessageScope::Enforce,
        MessageEvent::Created,
        all_modules(),
        &message,
        established_author(),
        Some(&matcher),
    );
    assert!(matches!(
        route,
        MessageRoute::Filter(ContentDetection {
            module: ProtectionModule::AttachmentFilter,
            ..
        })
    ));
}

#[test]
fn attachments_and_anti_scam_also_apply_to_edits() {
    let attachment = MessageContent {
        content: "voici la facture".to_owned(),
        attachments: vec!["facture.pdf.exe".to_owned()],
        ..MessageContent::default()
    };
    let scam = text_message("urgent, verify your account https://grabify.link/x");

    for (module, message) in [
        (ProtectionModule::AttachmentFilter, &attachment),
        (ProtectionModule::AntiScam, &scam),
    ] {
        for scope in [MessageScope::Enforce, MessageScope::ExemptAuthor] {
            let route = route_message(
                scope,
                MessageEvent::Edited,
                only(module),
                message,
                established_author(),
                None,
            );
            assert!(
                matches!(route, MessageRoute::Filter(ContentDetection { module: found, .. }) if found == module),
                "{module} {scope:?}"
            );
        }
    }
}

#[test]
fn attachment_changes_make_a_new_revision() {
    let analyzed = MessageContent {
        content: "facture".to_owned(),
        attachments: vec!["facture.pdf.exe".to_owned()],
        ..MessageContent::default()
    };
    let mut removed = analyzed.clone();
    removed.attachments.clear();

    assert_eq!(
        check_revision(&analyzed, Some(&analyzed.clone())),
        RevisionCheck::Current
    );
    assert_eq!(
        check_revision(&analyzed, Some(&removed)),
        RevisionCheck::Superseded
    );
}
