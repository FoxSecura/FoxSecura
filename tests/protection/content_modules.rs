// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Pièces jointes dangereuses, anti-arnaque gradué et mots interdits :
//! détection, suite donnée (sanction ou revue), exemption et incident.

use std::time::Duration;

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::logs::{
    ActionCode, ActionStatus, FailureCode, LogSeverity, SecurityEvidence, SecurityIncident,
    format_security_log_message,
};
use foxsecura::protection::anti_spam::anti_scam::ScamConfidence;
use foxsecura::protection::automod::bad_words::{
    BadWordsLanguage, BadWordsMatcher, BadWordsMatcherCache, CustomWordsError,
    MAX_CUSTOM_WORD_CHARS, MAX_CUSTOM_WORDS, MAX_CUSTOM_WORDS_INPUT_CHARS, built_in_bad_words,
    parse_custom_words,
};
use foxsecura::protection::content_filter::{
    ANTI_SCAM_BAN_PURGE, ANTI_SCAM_TIMEOUT, AuthorContext, CONTENT_FILTERS, ContentDetection,
    ContentFinding, FollowUp, FollowUpOutcome, MessageContent, MessageEvent, MessageRoute,
    anti_scam_audit_reason, build_incident, detect_content, plan_follow_up, record_follow_up,
    route_message,
};
use foxsecura::protection::shared::{
    DeleteMessageOutcome, GuildMessage, MessageScope, ModuleSet, ProtectionModule, SanctionKind,
    SanctionOutcome, SanctionPermission, SanctionSkip, is_foxsecura_audit_reason,
};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Moyenne : un lien malveillant seul (score 4).
const MEDIUM_SCAM: &str = "cadeau : https://grabify.link/abc";
/// Haute : lien malveillant + urgence (score 5).
const HIGH_SCAM: &str = "urgent https://grabify.link/abc";
/// Critique : lien malveillant + demande d'identifiants + urgence (score 8).
const CRITICAL_SCAM: &str = "urgent, verify your account https://grabify.link/abc";

fn only(module: ProtectionModule) -> ModuleSet {
    [module].into_iter().collect()
}

fn established_author() -> AuthorContext {
    AuthorContext {
        now: Some(DAY * 400),
        account_created_at: Some(DAY),
        member_joined_at: Some(DAY * 2),
    }
}

fn text_message(content: &str) -> MessageContent {
    MessageContent {
        content: content.to_owned(),
        ..MessageContent::default()
    }
}

fn with_attachments(names: &[&str]) -> MessageContent {
    MessageContent {
        attachments: names.iter().map(|name| (*name).to_owned()).collect(),
        ..MessageContent::default()
    }
}

fn french_matcher() -> BadWordsMatcher {
    BadWordsMatcher::new(built_in_bad_words(BadWordsLanguage::French))
}

fn detect(
    module: ProtectionModule,
    message: &MessageContent,
    matcher: Option<&BadWordsMatcher>,
) -> Option<ContentDetection> {
    detect_content(only(module), message, established_author(), matcher)
}

fn scam(content: &str) -> ContentDetection {
    detect(ProtectionModule::AntiScam, &text_message(content), None)
        .unwrap_or_else(|| panic!("arnaque attendue : {content}"))
}

fn confidence(detection: &ContentDetection) -> ScamConfidence {
    match &detection.finding {
        ContentFinding::Scam { confidence, .. } => *confidence,
        other => panic!("preuve d'arnaque attendue, obtenu {other:?}"),
    }
}

fn guild_message() -> GuildMessage {
    GuildMessage {
        guild_id: 1,
        channel_id: 10,
        message_id: 77,
        author_id: 42,
        timestamp: Duration::ZERO,
    }
}

fn incident(
    detection: &ContentDetection,
    content: &MessageContent,
    deletion: &DeleteMessageOutcome,
    follow_up: &FollowUpOutcome,
) -> SecurityIncident {
    let mut incident = build_incident(
        Language::French,
        &guild_message(),
        detection,
        MessageEvent::Created,
        content,
        deletion,
    );
    record_follow_up(&mut incident, Language::French, deletion, follow_up);
    incident
}

fn actions(incident: &SecurityIncident) -> Vec<(ActionCode, ActionStatus)> {
    incident
        .actions
        .iter()
        .map(|action| (action.action, action.status))
        .collect()
}

// --- Pièces jointes ---

#[test]
fn dangerous_final_extensions_are_blocked_including_double_extensions() {
    for name in [
        "setup.exe",
        "facture.pdf.exe",
        "photo.JPG.scr",
        "script.PS1",
        "raccourci.lnk",
        "app.apk",
    ] {
        let detection = detect(
            ProtectionModule::AttachmentFilter,
            &with_attachments(&["ok.png", name]),
            None,
        )
        .unwrap_or_else(|| panic!("{name}"));
        let ContentFinding::DangerousAttachment {
            file_name,
            extension,
        } = detection.finding
        else {
            panic!("{name}");
        };
        assert_eq!(file_name, name);
        assert_eq!(extension, name.rsplit('.').next().unwrap());
    }
}

#[test]
fn only_the_final_extension_counts() {
    for name in [
        "setup.exe.txt",
        "archive.exe.zip",
        "notes.pdf",
        "exe",
        "rapport",
    ] {
        assert!(
            detect(
                ProtectionModule::AttachmentFilter,
                &with_attachments(&[name]),
                None
            )
            .is_none(),
            "{name}"
        );
    }
    assert!(
        detect(
            ProtectionModule::AttachmentFilter,
            &MessageContent::default(),
            None
        )
        .is_none()
    );
}

#[test]
fn attachment_evidence_is_rendered_as_inert_literals() {
    let content = with_attachments(&["`@everyone`\n**x**.pdf.exe"]);
    let detection = detect(ProtectionModule::AttachmentFilter, &content, None).unwrap();
    let incident = incident(
        &detection,
        &content,
        &DeleteMessageOutcome::Deleted,
        &FollowUpOutcome::None,
    );
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(
        actions(&incident),
        vec![(ActionCode::DeleteMessage, ActionStatus::Success)]
    );

    let log = format_security_log_message(Language::French, &incident);
    assert!(
        log.contains("Fichier = `ˋ@everyoneˋ **x**.pdf.exe`"),
        "{log}"
    );
    assert!(log.contains("Extension = `exe`"), "{log}");
    assert!(!log.contains('\u{0060}'.to_string().repeat(2).as_str()));
}

// --- Anti-arnaque : gradation ---

#[test]
fn scam_confidence_levels_follow_the_score() {
    assert_eq!(confidence(&scam(MEDIUM_SCAM)), ScamConfidence::Medium);
    assert_eq!(confidence(&scam(HIGH_SCAM)), ScamConfidence::High);
    assert_eq!(confidence(&scam(CRITICAL_SCAM)), ScamConfidence::Critical);

    // Confiance basse : le message continue dans la chaîne.
    assert!(
        detect(
            ProtectionModule::AntiScam,
            &text_message("urgent, réunion"),
            None
        )
        .is_none()
    );
}

#[test]
fn medium_scam_asks_for_staff_review_without_sanction() {
    let detection = scam(MEDIUM_SCAM);
    assert_eq!(
        plan_follow_up(&detection, MessageScope::Enforce),
        FollowUp::StaffReview
    );

    let content = text_message(MEDIUM_SCAM);
    // Sévérité selon la suppression.
    let deleted = incident(
        &detection,
        &content,
        &DeleteMessageOutcome::Deleted,
        &FollowUpOutcome::StaffReview,
    );
    assert_eq!(deleted.severity, LogSeverity::Warning);
    assert_eq!(
        actions(&deleted),
        vec![
            (ActionCode::DeleteMessage, ActionStatus::Success),
            (ActionCode::RequestStaffReview, ActionStatus::Success),
        ]
    );
    assert_eq!(
        deleted.recommendation.as_deref(),
        Some(text(
            Language::French,
            TextKey::AntiScamRecommendationReview
        ))
    );

    let visible = incident(
        &detection,
        &content,
        &DeleteMessageOutcome::NotDeletable,
        &FollowUpOutcome::StaffReview,
    );
    assert_eq!(visible.severity, LogSeverity::Critical);
    assert_eq!(visible.validate(), Ok(()));
}

#[test]
fn high_scam_times_out_for_one_hour() {
    let detection = scam(HIGH_SCAM);
    let kind = SanctionKind::Timeout {
        duration: ANTI_SCAM_TIMEOUT,
    };
    assert_eq!(ANTI_SCAM_TIMEOUT, Duration::from_secs(3600));
    assert_eq!(
        plan_follow_up(&detection, MessageScope::Enforce),
        FollowUp::Sanction(kind)
    );

    let incident = incident(
        &detection,
        &text_message(HIGH_SCAM),
        &DeleteMessageOutcome::Deleted,
        &FollowUpOutcome::Sanction {
            kind,
            outcome: SanctionOutcome::Applied,
        },
    );
    // Critique dès la confiance haute, même si tout a réussi.
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(
        actions(&incident),
        vec![
            (ActionCode::DeleteMessage, ActionStatus::Success),
            (ActionCode::TimeoutMember, ActionStatus::Success),
        ]
    );
    assert_eq!(incident.validate(), Ok(()));
}

#[test]
fn critical_scam_bans_with_a_seven_day_purge() {
    let detection = scam(CRITICAL_SCAM);
    let kind = SanctionKind::Ban {
        purge: ANTI_SCAM_BAN_PURGE,
    };
    assert_eq!(kind.ban_purge_days(), Some(7));
    assert_eq!(
        plan_follow_up(&detection, MessageScope::Enforce),
        FollowUp::Sanction(kind)
    );

    let applied = incident(
        &detection,
        &text_message(CRITICAL_SCAM),
        &DeleteMessageOutcome::Deleted,
        &FollowUpOutcome::Sanction {
            kind,
            outcome: SanctionOutcome::Applied,
        },
    );
    assert_eq!(applied.severity, LogSeverity::Critical);
    assert_eq!(
        actions(&applied),
        vec![
            (ActionCode::DeleteMessage, ActionStatus::Success),
            (ActionCode::BanMember, ActionStatus::Success),
        ]
    );
    assert_eq!(
        applied.recommendation.as_deref(),
        Some(text(
            Language::French,
            TextKey::AntiScamRecommendationBanFalsePositive
        ))
    );
}

#[test]
fn failed_sanction_recommends_checking_the_ban_hierarchy() {
    let detection = scam(CRITICAL_SCAM);
    let kind = SanctionKind::Ban {
        purge: ANTI_SCAM_BAN_PURGE,
    };
    for outcome in [
        SanctionOutcome::Skipped(SanctionSkip::RoleHierarchy { target: 5, bot: 3 }),
        SanctionOutcome::Skipped(SanctionSkip::MissingPermission(
            SanctionPermission::BanMembers,
        )),
        SanctionOutcome::Failed {
            failure_code: FailureCode::DiscordUnavailable,
            details: "503".to_owned(),
        },
    ] {
        let incident = incident(
            &detection,
            &text_message(CRITICAL_SCAM),
            &DeleteMessageOutcome::Deleted,
            &FollowUpOutcome::Sanction {
                kind,
                outcome: outcome.clone(),
            },
        );
        assert_eq!(incident.severity, LogSeverity::Critical);
        assert_ne!(incident.actions[1].status, ActionStatus::Success);
        assert_eq!(
            incident.recommendation.as_deref(),
            Some(text(
                Language::French,
                TextKey::AntiScamRecommendationCheckHierarchy
            )),
            "{outcome:?}"
        );
    }

    // Message resté visible : les permissions de suppression d'abord.
    let visible = incident(
        &detection,
        &text_message(CRITICAL_SCAM),
        &DeleteMessageOutcome::NotDeletable,
        &FollowUpOutcome::Sanction {
            kind,
            outcome: SanctionOutcome::Applied,
        },
    );
    assert_eq!(
        visible.recommendation.as_deref(),
        Some(text(
            Language::French,
            TextKey::AntiSpamRecommendationCheckPermissions
        ))
    );
}

#[test]
fn audit_reason_carries_the_level_but_never_the_message() {
    let reason = anti_scam_audit_reason(&scam(CRITICAL_SCAM));
    assert!(reason.starts_with("FoxSecura Anti-Scam: "), "{reason}");
    assert!(is_foxsecura_audit_reason(&reason));
    assert!(reason.contains("critical"));
    assert!(!reason.contains("grabify"));
    assert!(!reason.contains("verify"));
}

// --- Anti-arnaque : preuves ---

#[test]
fn scam_evidence_never_contains_the_full_url_query_or_credentials() {
    let content = text_message(
        "urgent, verify your account https://victim:hunter2@steamcommunity.xyz/login/confirm?token=SECRET123&id=42#frag",
    );
    let detection = detect(ProtectionModule::AntiScam, &content, None).unwrap();
    let ContentFinding::Scam {
        host,
        score,
        signals,
        confidence,
    } = &detection.finding
    else {
        panic!("{detection:?}");
    };
    assert_eq!(host.as_deref(), Some("steamcommunity.xyz"));
    assert!(*score >= 8);
    assert!(signals.len() <= 6);
    assert!(signals.contains(&"malicious_link"));
    assert_eq!(*confidence, ScamConfidence::Critical);

    let incident = incident(
        &detection,
        &content,
        &DeleteMessageOutcome::Deleted,
        &FollowUpOutcome::Sanction {
            kind: SanctionKind::Ban {
                purge: ANTI_SCAM_BAN_PURGE,
            },
            outcome: SanctionOutcome::Applied,
        },
    );
    // Aucun extrait du message : il contiendrait l'URL.
    assert!(
        !incident
            .evidence
            .iter()
            .any(|evidence| matches!(evidence, SecurityEvidence::Content { .. }))
    );

    let rendered = format!(
        "{:?}\n{}",
        incident.evidence,
        format_security_log_message(Language::French, &incident)
    );
    for leak in [
        "SECRET123",
        "token",
        "id=42",
        "/login",
        "confirm",
        "hunter2",
        "victim",
        "frag",
        "?",
        "https",
    ] {
        assert!(!rendered.contains(leak), "{leak} présent dans : {rendered}");
    }
    // Hôte défangué dans le salon de logs.
    assert!(rendered.contains("steamcommunity[.]xyz"), "{rendered}");
    assert!(rendered.contains("critical"));
}

#[test]
fn scam_without_link_has_no_host_but_keeps_signals_score_and_confidence() {
    let content = text_message("URGENT: free nitro, verify your account and send your seed phrase");
    let detection = detect(ProtectionModule::AntiScam, &content, None).unwrap();
    let ContentFinding::Scam { host, signals, .. } = &detection.finding else {
        panic!("{detection:?}");
    };
    assert_eq!(host, &None);
    assert!(signals.contains(&"credential_request"));

    let incident = incident(
        &detection,
        &content,
        &DeleteMessageOutcome::Deleted,
        &FollowUpOutcome::None,
    );
    assert_eq!(incident.evidence.len(), 3);
    assert!(
        incident
            .evidence
            .iter()
            .all(|evidence| matches!(evidence, SecurityEvidence::Text { .. }))
    );
}

#[test]
fn scam_context_uses_account_age_and_join_date() {
    // Lien vers une IP : risqué seulement pour un compte ou un membre récent.
    let content = text_message("connecte-toi http://192.168.1.20/login");
    let author = |account_age: Duration, member_age: Duration| AuthorContext {
        now: Some(DAY * 100),
        account_created_at: Some(DAY * 100 - account_age),
        member_joined_at: Some(DAY * 100 - member_age),
    };
    let scam_for =
        |author| detect_content(only(ProtectionModule::AntiScam), &content, author, None).is_some();

    assert!(!scam_for(author(DAY * 30, DAY * 30)));
    assert!(scam_for(author(DAY, DAY * 30)));
    assert!(scam_for(author(DAY * 30, Duration::from_secs(60))));
}

// --- Liste blanche ---

/// Un message qui déclenche chaque module.
fn trigger(module: ProtectionModule) -> MessageContent {
    match module {
        ProtectionModule::AttachmentFilter => with_attachments(&["facture.pdf.exe"]),
        ProtectionModule::InvisibleCharFilter => text_message("sa\u{200b}lut"),
        ProtectionModule::AntiScam => text_message(CRITICAL_SCAM),
        ProtectionModule::MaliciousLink => text_message("https://grabify.link/x"),
        ProtectionModule::AdultLink => text_message("https://pornhub.com"),
        ProtectionModule::AntiInvite => text_message("discord.gg/raid"),
        ProtectionModule::AntiEveryone => MessageContent {
            content: "@everyone".to_owned(),
            mentions_everyone: true,
            ..MessageContent::default()
        },
        ProtectionModule::AntiMassMention => MessageContent {
            content: "salut".to_owned(),
            mention_count: 10,
            ..MessageContent::default()
        },
        ProtectionModule::BadWords => text_message("quelle merde"),
        ProtectionModule::AntiBot | ProtectionModule::AntiNewAccount => {
            unreachable!("module des arrivées, absent de CONTENT_FILTERS")
        }
    }
}

#[test]
fn exempt_author_is_deleted_but_never_sanctioned_in_any_module() {
    let matcher = french_matcher();
    for module in CONTENT_FILTERS {
        let content = trigger(module);
        let MessageRoute::Filter(detection) = route_message(
            MessageScope::ExemptAuthor,
            MessageEvent::Created,
            only(module),
            &content,
            established_author(),
            Some(&matcher),
        ) else {
            panic!("{module} doit supprimer le message d'un auteur exempté");
        };
        assert_eq!(detection.module, module);

        let follow_up = plan_follow_up(&detection, MessageScope::ExemptAuthor);
        assert!(
            !matches!(follow_up, FollowUp::Sanction(_)),
            "{module} : {follow_up:?}"
        );

        let outcome = match follow_up {
            FollowUp::None => FollowUpOutcome::None,
            FollowUp::StaffReview => FollowUpOutcome::StaffReview,
            FollowUp::ExemptMember(kind) => FollowUpOutcome::ExemptMember(kind),
            FollowUp::Sanction(_) => unreachable!(),
        };
        let incident = incident(
            &detection,
            &content,
            &DeleteMessageOutcome::Deleted,
            &outcome,
        );
        assert_eq!(incident.actions[0].action, ActionCode::DeleteMessage);
        assert!(
            incident.actions.iter().all(|action| !matches!(
                action.action,
                ActionCode::BanMember | ActionCode::TimeoutMember
            )),
            "{module}"
        );
    }
}

#[test]
fn exempt_author_scam_is_logged_as_ignore_exempt_member() {
    for content in [HIGH_SCAM, CRITICAL_SCAM] {
        let detection = scam(content);
        let FollowUp::ExemptMember(kind) = plan_follow_up(&detection, MessageScope::ExemptAuthor)
        else {
            panic!("{content}");
        };
        let incident = incident(
            &detection,
            &text_message(content),
            &DeleteMessageOutcome::Deleted,
            &FollowUpOutcome::ExemptMember(kind),
        );
        assert_eq!(
            actions(&incident),
            vec![
                (ActionCode::DeleteMessage, ActionStatus::Success),
                (ActionCode::IgnoreExemptMember, ActionStatus::Skipped),
            ]
        );
        assert_eq!(
            incident.recommendation.as_deref(),
            Some(text(
                Language::French,
                TextKey::RecommendationReviewWhitelist
            ))
        );
    }

    // Confiance moyenne : pas de sanction prévue, donc rien à ignorer.
    assert_eq!(
        plan_follow_up(&scam(MEDIUM_SCAM), MessageScope::ExemptAuthor),
        FollowUp::StaffReview
    );
}

#[test]
fn only_the_anti_scam_ever_plans_a_sanction() {
    let matcher = french_matcher();
    for module in CONTENT_FILTERS {
        let detection = detect(module, &trigger(module), Some(&matcher)).unwrap();
        let sanctioned = matches!(
            plan_follow_up(&detection, MessageScope::Enforce),
            FollowUp::Sanction(_)
        );
        assert_eq!(sanctioned, module == ProtectionModule::AntiScam, "{module}");
    }
}

// --- Mots interdits ---

#[test]
fn bad_words_are_case_insensitive_with_unicode_boundaries() {
    let matcher = BadWordsMatcher::new(["merde", "enculé", "fdp", "gros mot"]);
    let blocked = |content: &str| {
        detect(
            ProtectionModule::BadWords,
            &text_message(content),
            Some(&matcher),
        )
        .map(|detection| detection.finding)
    };

    for content in [
        "MERDE",
        "Merde !",
        "(merde)",
        "c'est de la merde.",
        "ENCULÉ",
        "espèce d'enculé",
        "fdp",
        "un GROS MOT ici",
        "«merde»",
    ] {
        assert!(blocked(content).is_some(), "{content}");
    }

    // Lettre, chiffre ou `_` accolé : pas de correspondance, y compris hors
    // ASCII (é, ß, chiffres arabes).
    for content in [
        "emmerdement",
        "merdes2",
        "merde_",
        "_merde",
        "2merde",
        "éfdp",
        "fdpé",
        "fdpß",
        "fdp٣",
        "enculément",
        "grosmot",
    ] {
        assert_eq!(blocked(content), None, "{content}");
    }

    assert_eq!(
        blocked("Oh MERDE"),
        Some(ContentFinding::BadWord {
            word: "merde".to_owned()
        })
    );
}

#[test]
fn bad_words_need_a_loaded_list() {
    assert!(detect(ProtectionModule::BadWords, &text_message("merde"), None).is_none());
}

#[test]
fn bad_words_only_delete() {
    let matcher = french_matcher();
    let detection = detect(
        ProtectionModule::BadWords,
        &text_message("merde"),
        Some(&matcher),
    )
    .unwrap();
    assert_eq!(
        plan_follow_up(&detection, MessageScope::Enforce),
        FollowUp::None
    );
    let incident = incident(
        &detection,
        &text_message("merde"),
        &DeleteMessageOutcome::Deleted,
        &FollowUpOutcome::None,
    );
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(incident.actions.len(), 1);
    assert!(format_security_log_message(Language::French, &incident).contains("Mot = `merde`"));
}

#[test]
fn custom_words_are_parsed_normalized_and_deduplicated() {
    assert_eq!(
        parse_custom_words("Spoiler\n  gros mot , SPOILER\n\n,,machin").unwrap(),
        vec!["spoiler", "gros mot", "machin"]
    );
    assert_eq!(parse_custom_words("").unwrap(), Vec::<String>::new());
    assert_eq!(parse_custom_words(" \n , ").unwrap(), Vec::<String>::new());
}

#[test]
fn custom_words_respect_v1_bounds() {
    // 100 caractères par mot (en caractères, pas en octets).
    let longest = "é".repeat(MAX_CUSTOM_WORD_CHARS);
    assert_eq!(parse_custom_words(&longest).unwrap(), vec![longest.clone()]);
    assert_eq!(
        parse_custom_words(&format!("{longest}é")),
        Err(CustomWordsError::WordTooLong)
    );

    // 200 mots au plus (les doublons ne comptent pas).
    let words = |count: usize| {
        (0..count)
            .map(|index| format!("m{index}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        parse_custom_words(&words(MAX_CUSTOM_WORDS)).unwrap().len(),
        MAX_CUSTOM_WORDS
    );
    assert_eq!(
        parse_custom_words(&words(MAX_CUSTOM_WORDS + 1)),
        Err(CustomWordsError::TooManyWords)
    );
    assert_eq!(
        parse_custom_words(&"a\n".repeat(300)).unwrap(),
        vec!["a".to_owned()]
    );

    // 2 000 caractères de saisie au total.
    let input = "x".repeat(MAX_CUSTOM_WORDS_INPUT_CHARS);
    assert_eq!(
        parse_custom_words(&input),
        Err(CustomWordsError::WordTooLong)
    );
    assert_eq!(
        parse_custom_words(&format!("{input}\n")),
        Err(CustomWordsError::InputTooLong)
    );
    assert_eq!(
        parse_custom_words(&",".repeat(MAX_CUSTOM_WORDS_INPUT_CHARS)).unwrap(),
        Vec::<String>::new()
    );

    assert_eq!(
        parse_custom_words("mot\u{7}"),
        Err(CustomWordsError::InvalidCharacter)
    );
}

#[test]
fn matchers_are_compiled_once_per_list_and_bounded() {
    let mut cache = BadWordsMatcherCache::new(2);
    let custom = vec!["spoiler".to_owned()];

    let first = cache.matcher(BadWordsLanguage::French, &custom);
    let again = cache.matcher(BadWordsLanguage::French, &custom);
    assert!(std::sync::Arc::ptr_eq(&first, &again));
    assert_eq!(cache.compilations(), 1);
    assert_eq!(
        first.detect("SPOILER !").matched_word.as_deref(),
        Some("spoiler")
    );
    assert!(first.detect("merde").matched_word.is_some());

    // Autre langue ou autre liste : autre matcher.
    let english = cache.matcher(BadWordsLanguage::English, &custom);
    assert!(english.detect("merde").matched_word.is_none());
    assert_eq!(cache.compilations(), 2);
    assert_eq!(cache.len(), 2);

    // Borné : la liste la moins récemment utilisée est oubliée.
    cache.matcher(BadWordsLanguage::French, &custom);
    cache.matcher(BadWordsLanguage::All, &[]);
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.compilations(), 3);
    cache.matcher(BadWordsLanguage::French, &custom);
    assert_eq!(cache.compilations(), 3, "la liste récente est conservée");
    cache.matcher(BadWordsLanguage::English, &custom);
    assert_eq!(cache.compilations(), 4, "la liste oubliée est recompilée");
}

#[test]
fn built_in_language_keys_round_trip() {
    for language in BadWordsLanguage::ALL {
        assert_eq!(BadWordsLanguage::from_key(language.key()), Some(language));
    }
    assert_eq!(BadWordsLanguage::from_key("French"), None);
    assert_eq!(BadWordsLanguage::from_key("fr"), None);
}
