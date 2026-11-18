// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::automod::{
    anti_invite::INVITE_PATTERNS,
    member_profile::{PROFILE_LURE_KEYWORDS, profile_filter_keywords},
    native_rules::{
        AutoModRuleKey, MAX_KEYWORD_CHARS, MAX_KEYWORDS, apply_discord_limits, build_rule_specs,
    },
};
use foxsecura::protection::shared::ProtectionModule;

#[test]
fn profile_filter_reuses_invite_patterns() {
    let keywords = profile_filter_keywords();

    for pattern in INVITE_PATTERNS {
        assert!(keywords.iter().any(|keyword| keyword == pattern));
    }
}

#[test]
fn profile_filter_contains_specific_scam_lures() {
    let keywords = profile_filter_keywords();

    assert!(PROFILE_LURE_KEYWORDS.contains(&"free nitro"));
    assert!(keywords.iter().any(|keyword| keyword == "crypto giveaway"));
    assert!(keywords.iter().any(|keyword| keyword == "bit.ly/*"));
}

#[test]
fn profile_filter_keywords_fit_native_rule_limits() {
    let keywords = profile_filter_keywords();

    assert!(!keywords.is_empty());
    assert!(keywords.len() <= MAX_KEYWORDS);
    for keyword in &keywords {
        assert!(keyword.chars().count() <= MAX_KEYWORD_CHARS, "{keyword}");
        assert_eq!(keyword.trim(), keyword);
    }
    let spec = build_rule_specs(Vec::<String>::new())
        .into_iter()
        .find(|spec| spec.key == AutoModRuleKey::MemberProfileFilter)
        .unwrap();
    let (limited, report) = apply_discord_limits(&spec);
    assert!(report.is_empty());
    assert_eq!(limited, spec);
    // La liste ne dépend pas des mots interdits : jamais vide.
    assert!(!spec.is_empty_keyword_spec());
}

#[test]
fn profile_filter_is_a_native_rule_switched_by_its_own_module() {
    assert_eq!(
        AutoModRuleKey::MemberProfileFilter.switch(),
        foxsecura::protection::automod::native_rules::RuleSwitch::Module(
            ProtectionModule::MemberProfileFilter
        )
    );
    assert_eq!(
        ProtectionModule::MemberProfileFilter.key(),
        "member_profile_filter"
    );
    assert_eq!(
        ProtectionModule::from_key("member_profile_filter"),
        Ok(ProtectionModule::MemberProfileFilter)
    );
}
