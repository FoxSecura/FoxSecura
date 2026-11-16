// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Charge JSON brute des règles natives (à l'octet près), limites Discord,
//! raisons d'audit et lecture des règles par serenity.

use foxsecura::protection::automod::member_profile::profile_filter_keywords;
use foxsecura::protection::automod::native_rules::{
    AUTOMOD_CLEANUP_REASON, AUTOMOD_DUPLICATE_CLEANUP_REASON, AUTOMOD_MIGRATE_REASON,
    AUTOMOD_NO_KEYWORDS_REASON, AUTOMOD_RULE_PREFIX, AUTOMOD_SETUP_REASON, AutoModRuleKey,
    AutoModRuleSpec, AutoModRuleTriggerMetadata, AutoModRuleTriggerType, BLOCK_MESSAGE_TEXT,
    MAX_CUSTOM_MESSAGE_CHARS, MAX_KEYWORD_CHARS, MAX_KEYWORDS, MAX_MENTION_TOTAL_LIMIT, UpdateMode,
    apply_discord_limits, build_rule_specs, create_payload, existing_rule, plan_reconciliation,
    trigger_type_code, trigger_type_from_code, update_payload,
};
use foxsecura::protection::shared::is_foxsecura_audit_reason;
use serenity::model::guild::automod::Rule;

fn spec(key: AutoModRuleKey) -> AutoModRuleSpec {
    build_rule_specs(["merde", "connard"])
        .into_iter()
        .find(|spec| spec.key == key)
        .unwrap()
}

fn create(key: AutoModRuleKey) -> String {
    serde_json::to_string(&create_payload(&spec(key), true)).unwrap()
}

fn update(key: AutoModRuleKey) -> String {
    serde_json::to_string(&update_payload(&spec(key), true, UpdateMode::FullSpec)).unwrap()
}

const BLOCK: &str = r#"[{"metadata":{"custom_message":"Blocked by FoxSecura."},"type":1}]"#;

#[test]
fn invite_rule_payload_is_exact() {
    let metadata = r#"{"keyword_filter":["discord.gg/*","discord.com/invite/*","discordapp.com/invite/*","discord.me/*","dsc.gg/*"]}"#;
    assert_eq!(
        create(AutoModRuleKey::InviteLinkBlocking),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Invite Link Blocking","trigger_metadata":{metadata},"trigger_type":1}}"#
        )
    );
    assert_eq!(
        update(AutoModRuleKey::InviteLinkBlocking),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Invite Link Blocking","trigger_metadata":{metadata}}}"#
        )
    );
}

#[test]
fn adult_rule_payload_uses_sexual_content_preset() {
    assert_eq!(
        create(AutoModRuleKey::AdultLinksFiltering),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Adult Links Filtering","trigger_metadata":{{"presets":[2]}},"trigger_type":4}}"#
        )
    );
    assert_eq!(
        update(AutoModRuleKey::AdultLinksFiltering),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Adult Links Filtering","trigger_metadata":{{"presets":[2]}}}}"#
        )
    );
}

#[test]
fn bad_words_rule_payload_carries_the_word_list() {
    assert_eq!(
        create(AutoModRuleKey::BadWordsFilter),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Bad Words Filter","trigger_metadata":{{"keyword_filter":["merde","connard"]}},"trigger_type":1}}"#
        )
    );
    assert_eq!(
        update(AutoModRuleKey::BadWordsFilter),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Bad Words Filter","trigger_metadata":{{"keyword_filter":["merde","connard"]}}}}"#
        )
    );
}

#[test]
fn mention_rule_payload_enables_raid_protection() {
    assert_eq!(
        create(AutoModRuleKey::MentionSpamBlocking),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Mention Spam Blocking","trigger_metadata":{{"mention_raid_protection_enabled":true,"mention_total_limit":5}},"trigger_type":5}}"#
        )
    );
    assert_eq!(
        update(AutoModRuleKey::MentionSpamBlocking),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Mention Spam Blocking","trigger_metadata":{{"mention_raid_protection_enabled":true,"mention_total_limit":5}}}}"#
        )
    );
}

#[test]
fn spam_rule_payload_has_no_metadata() {
    assert_eq!(
        create(AutoModRuleKey::GenericSpamBlocking),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Spam Blocking","trigger_type":3}}"#
        )
    );
    assert_eq!(
        update(AutoModRuleKey::GenericSpamBlocking),
        format!(
            r#"{{"actions":{BLOCK},"enabled":true,"event_type":1,"name":"FoxSecura • Spam Blocking"}}"#
        )
    );
}

#[test]
fn member_profile_rule_payload_blocks_member_interaction() {
    let keywords = serde_json::to_string(&profile_filter_keywords()).unwrap();
    assert_eq!(
        create(AutoModRuleKey::MemberProfileFilter),
        format!(
            r#"{{"actions":[{{"type":4}}],"enabled":true,"event_type":2,"name":"FoxSecura • Member Profile Filter","trigger_metadata":{{"keyword_filter":{keywords}}},"trigger_type":6}}"#
        )
    );
    assert_eq!(
        update(AutoModRuleKey::MemberProfileFilter),
        format!(
            r#"{{"actions":[{{"type":4}}],"enabled":true,"event_type":2,"name":"FoxSecura • Member Profile Filter","trigger_metadata":{{"keyword_filter":{keywords}}}}}"#
        )
    );
}

#[test]
fn update_payload_never_changes_the_trigger_type() {
    for key in AutoModRuleKey::ALL {
        for enabled in [true, false] {
            let payload = update_payload(&spec(key), enabled, UpdateMode::FullSpec);
            assert!(payload.get("trigger_type").is_none(), "{key:?}");
            assert_eq!(payload["enabled"], enabled, "{key:?}");
        }
        let create = create_payload(&spec(key), false);
        assert_eq!(create["enabled"], false);
        assert_eq!(
            create["trigger_type"],
            trigger_type_code(spec(key).trigger_type)
        );
    }
}

#[test]
fn disable_only_payload_is_name_and_disabled() {
    for key in AutoModRuleKey::ALL {
        let payload = update_payload(&spec(key), true, UpdateMode::DisableOnly);
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            format!(r#"{{"enabled":false,"name":"{}"}}"#, key.rule_name())
        );
    }
}

#[test]
fn rule_names_keep_the_ownership_prefix() {
    assert_eq!(AUTOMOD_RULE_PREFIX, "FoxSecura •");
    for key in AutoModRuleKey::ALL {
        assert!(key.rule_name().starts_with(AUTOMOD_RULE_PREFIX), "{key:?}");
        assert_eq!(AutoModRuleKey::from_rule_name(key.rule_name()), Some(key));
        for legacy in key.legacy_names() {
            assert_eq!(AutoModRuleKey::from_rule_name(legacy), Some(key));
        }
    }
    assert_eq!(AutoModRuleKey::from_rule_name("FoxSecura • Custom"), None);
    assert_eq!(AutoModRuleKey::from_rule_name("Spam Blocking"), None);
}

#[test]
fn audit_reasons_follow_the_foxsecura_convention() {
    for reason in [
        AUTOMOD_SETUP_REASON,
        AUTOMOD_NO_KEYWORDS_REASON,
        AUTOMOD_MIGRATE_REASON,
        AUTOMOD_DUPLICATE_CLEANUP_REASON,
        AUTOMOD_CLEANUP_REASON,
    ] {
        assert!(is_foxsecura_audit_reason(reason), "{reason}");
        assert!(reason.chars().count() <= 512);
    }
    assert_eq!(AUTOMOD_SETUP_REASON, "FoxSecura AutoMod setup");
    assert_eq!(
        AUTOMOD_NO_KEYWORDS_REASON,
        "FoxSecura AutoMod setup: no keywords configured"
    );
    assert_eq!(
        AUTOMOD_MIGRATE_REASON,
        "FoxSecura AutoMod setup: migrate trigger type"
    );
}

#[test]
fn every_payload_respects_discord_limits() {
    assert!(BLOCK_MESSAGE_TEXT.chars().count() <= MAX_CUSTOM_MESSAGE_CHARS);
    for spec in build_rule_specs(["mot"]) {
        let (limited, report) = apply_discord_limits(&spec);
        assert!(report.is_empty(), "{:?}", spec.key);
        assert_eq!(limited, spec);
        match &limited.trigger_metadata {
            AutoModRuleTriggerMetadata::KeywordFilter(words) => {
                assert!(words.len() <= MAX_KEYWORDS);
                for word in words {
                    assert!(word.chars().count() <= MAX_KEYWORD_CHARS, "{word}");
                }
            }
            AutoModRuleTriggerMetadata::MentionSpam { total_limit, .. } => {
                assert!(*total_limit <= MAX_MENTION_TOTAL_LIMIT);
            }
            _ => {}
        }
    }
}

#[test]
fn too_long_words_are_excluded_and_reported() {
    let long = "é".repeat(61);
    let exact = "a".repeat(60);
    let spec = build_rule_specs(["court", long.as_str(), exact.as_str()])
        .into_iter()
        .find(|spec| spec.key == AutoModRuleKey::BadWordsFilter)
        .unwrap();

    let (limited, report) = apply_discord_limits(&spec);

    assert_eq!(
        limited.trigger_metadata,
        AutoModRuleTriggerMetadata::KeywordFilter(vec!["court".to_owned(), exact])
    );
    assert_eq!(report.too_long, vec![long]);
    assert_eq!(report.truncated, 0);
    assert!(!report.is_empty());
}

#[test]
fn more_than_a_thousand_words_are_truncated_and_reported() {
    let words: Vec<String> = (0..1205).map(|index| format!("mot{index}")).collect();
    let spec = build_rule_specs(&words)
        .into_iter()
        .find(|spec| spec.key == AutoModRuleKey::BadWordsFilter)
        .unwrap();

    let (limited, report) = apply_discord_limits(&spec);

    let AutoModRuleTriggerMetadata::KeywordFilter(kept) = &limited.trigger_metadata else {
        panic!("liste de mots attendue");
    };
    assert_eq!(kept.len(), MAX_KEYWORDS);
    assert_eq!(kept[0], "mot0");
    assert_eq!(kept[999], "mot999");
    assert_eq!(report.truncated, 205);
    assert!(report.too_long.is_empty());
}

#[test]
fn a_list_of_only_too_long_words_deletes_the_rule() {
    let long = "x".repeat(80);
    let spec = build_rule_specs([long.as_str()])
        .into_iter()
        .find(|spec| spec.key == AutoModRuleKey::BadWordsFilter)
        .unwrap();
    let (limited, report) = apply_discord_limits(&spec);

    assert!(limited.is_empty_keyword_spec());
    assert_eq!(report.too_long.len(), 1);
    let plan = plan_reconciliation(&[], &limited, true, true);
    assert!(plan.mutations.is_empty());
    assert!(plan.skipped_reason.is_some());
}

#[test]
fn mention_limit_is_capped() {
    let mut spec = spec(AutoModRuleKey::MentionSpamBlocking);
    spec.trigger_metadata = AutoModRuleTriggerMetadata::MentionSpam {
        total_limit: 90,
        raid_protection_enabled: true,
    };
    let (limited, _) = apply_discord_limits(&spec);
    assert_eq!(
        limited.trigger_metadata,
        AutoModRuleTriggerMetadata::MentionSpam {
            total_limit: MAX_MENTION_TOTAL_LIMIT,
            raid_protection_enabled: true,
        }
    );
}

#[test]
fn trigger_type_codes_round_trip() {
    for (code, trigger_type) in [
        (1, AutoModRuleTriggerType::Keyword),
        (3, AutoModRuleTriggerType::Spam),
        (4, AutoModRuleTriggerType::KeywordPreset),
        (5, AutoModRuleTriggerType::MentionSpam),
        (6, AutoModRuleTriggerType::MemberProfile),
        (2, AutoModRuleTriggerType::Other(2)),
    ] {
        assert_eq!(trigger_type_from_code(code), trigger_type);
        assert_eq!(trigger_type_code(trigger_type), code);
    }
    assert!(!AutoModRuleTriggerType::Other(9).is_singleton());
}

/// Règle `MEMBER_PROFILE` telle que Discord la renvoie : serenity 0.12.5 ne
/// connaît ni le déclencheur 6, ni l'événement 2, ni l'action 4, mais ne doit
/// pas la rejeter.
#[test]
fn serenity_reads_a_member_profile_rule() {
    let rule: Rule = serde_json::from_value(serde_json::json!({
        "id": "1300000000000000100",
        "guild_id": "1300000000000000001",
        "name": "FoxSecura • Member Profile Filter",
        "creator_id": "1300000000000000002",
        "event_type": 2,
        "trigger_type": 6,
        "trigger_metadata": {
            "keyword_filter": ["free nitro", "discord.gg/*"],
            "regex_patterns": [],
            "allow_list": []
        },
        "actions": [{ "type": 4, "metadata": {} }],
        "enabled": false,
        "exempt_roles": [],
        "exempt_channels": []
    }))
    .unwrap();

    let existing = existing_rule(&rule);

    assert_eq!(existing.id, 1_300_000_000_000_000_100);
    assert_eq!(existing.name, "FoxSecura • Member Profile Filter");
    assert_eq!(existing.trigger_type, AutoModRuleTriggerType::MemberProfile);
    assert!(!existing.enabled);
}

#[test]
fn serenity_reads_a_raid_protected_mention_rule() {
    let rule: Rule = serde_json::from_value(serde_json::json!({
        "id": "1300000000000000101",
        "guild_id": "1300000000000000001",
        "name": "FoxSecura • Mention Spam Blocking",
        "creator_id": "1300000000000000002",
        "event_type": 1,
        "trigger_type": 5,
        "trigger_metadata": {
            "mention_total_limit": 5,
            "mention_raid_protection_enabled": true
        },
        "actions": [{ "type": 1, "metadata": { "custom_message": "Blocked by FoxSecura." } }],
        "enabled": true,
        "exempt_roles": [],
        "exempt_channels": []
    }))
    .unwrap();

    let existing = existing_rule(&rule);
    assert_eq!(existing.trigger_type, AutoModRuleTriggerType::MentionSpam);
    assert!(existing.enabled);
}
