// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::automod::native_rules::{
    AutoModActionType, AutoModEventType, AutoModRuleKey, AutoModRuleSkipReason,
    AutoModRuleTriggerMetadata, AutoModRuleTriggerType, ExistingAutoModRule, KeywordPreset,
    RuleMutation, UpdateMode, build_rule_specs, plan_reconciliation,
};

fn spec(key: AutoModRuleKey) -> foxsecura::protection::automod::native_rules::AutoModRuleSpec {
    build_rule_specs(["blocked-word"])
        .into_iter()
        .find(|spec| spec.key == key)
        .expect("spec must exist")
}

#[test]
fn builds_all_six_native_rule_specs() {
    let specs = build_rule_specs(["blocked-word"]);

    assert_eq!(specs.len(), 6);
    assert!(specs.iter().any(|spec| spec.key == AutoModRuleKey::InviteLinkBlocking));
    assert!(specs.iter().any(|spec| spec.key == AutoModRuleKey::AdultLinksFiltering));
    assert!(specs.iter().any(|spec| spec.key == AutoModRuleKey::BadWordsFilter));
    assert!(specs.iter().any(|spec| spec.key == AutoModRuleKey::MentionSpamBlocking));
    assert!(specs.iter().any(|spec| spec.key == AutoModRuleKey::GenericSpamBlocking));
    assert!(specs.iter().any(|spec| spec.key == AutoModRuleKey::MemberProfileFilter));
}

#[test]
fn adult_rule_uses_discord_sexual_content_preset() {
    let spec = spec(AutoModRuleKey::AdultLinksFiltering);

    assert_eq!(spec.trigger_type, AutoModRuleTriggerType::KeywordPreset);
    assert_eq!(
        spec.trigger_metadata,
        AutoModRuleTriggerMetadata::KeywordPreset(vec![KeywordPreset::SexualContent])
    );
    assert_eq!(spec.event_type(), AutoModEventType::MessageSend);
    assert_eq!(spec.action_type(), AutoModActionType::BlockMessage);
}

#[test]
fn member_profile_rule_uses_member_update_action() {
    let spec = spec(AutoModRuleKey::MemberProfileFilter);

    assert_eq!(spec.trigger_type, AutoModRuleTriggerType::MemberProfile);
    assert_eq!(spec.event_type(), AutoModEventType::MemberUpdate);
    assert_eq!(spec.action_type(), AutoModActionType::BlockMemberInteraction);
}

#[test]
fn empty_bad_words_rule_removes_stale_rules() {
    let spec = build_rule_specs(Vec::<String>::new())
        .into_iter()
        .find(|spec| spec.key == AutoModRuleKey::BadWordsFilter)
        .unwrap();
    let rules = vec![
        ExistingAutoModRule::new(1, spec.name, AutoModRuleTriggerType::Keyword),
        ExistingAutoModRule::new(2, "FoxSecura • Bad Words", AutoModRuleTriggerType::Keyword),
    ];

    let plan = plan_reconciliation(&rules, &spec, true, true);

    assert_eq!(plan.skipped_reason, Some(AutoModRuleSkipReason::NoKeywords));
    assert_eq!(
        plan.mutations,
        vec![RuleMutation::Delete { rule_id: 1 }, RuleMutation::Delete { rule_id: 2 }]
    );
}

#[test]
fn disabled_missing_rule_is_not_created_during_toggle() {
    let spec = spec(AutoModRuleKey::InviteLinkBlocking);
    let plan = plan_reconciliation(&[], &spec, false, false);

    assert!(plan.missing);
    assert!(plan.mutations.is_empty());
}

#[test]
fn setup_can_create_a_disabled_rule() {
    let spec = spec(AutoModRuleKey::InviteLinkBlocking);
    let plan = plan_reconciliation(&[], &spec, false, true);

    assert_eq!(plan.mutations, vec![RuleMutation::Create { enabled: false }]);
}

#[test]
fn singleton_trigger_conflict_skips_foreign_rule() {
    let spec = spec(AutoModRuleKey::GenericSpamBlocking);
    let rules = vec![ExistingAutoModRule::new(
        99,
        "Server Spam Rule",
        AutoModRuleTriggerType::Spam,
    )];

    let plan = plan_reconciliation(&rules, &spec, true, true);

    assert!(plan.missing);
    assert_eq!(
        plan.skipped_reason,
        Some(AutoModRuleSkipReason::TriggerTypeConflict)
    );
    assert!(plan.mutations.is_empty());
}

#[test]
fn keyword_preset_conflict_has_specific_reason() {
    let spec = spec(AutoModRuleKey::AdultLinksFiltering);
    let rules = vec![ExistingAutoModRule::new(
        99,
        "Server Preset Rule",
        AutoModRuleTriggerType::KeywordPreset,
    )];

    let plan = plan_reconciliation(&rules, &spec, true, true);

    assert_eq!(
        plan.skipped_reason,
        Some(AutoModRuleSkipReason::KeywordPresetConflict)
    );
}

#[test]
fn changed_trigger_type_is_recreated_when_enabled() {
    let spec = spec(AutoModRuleKey::MemberProfileFilter);
    let rules = vec![ExistingAutoModRule::new(
        10,
        spec.name,
        AutoModRuleTriggerType::Keyword,
    )];

    let plan = plan_reconciliation(&rules, &spec, true, true);

    assert_eq!(
        plan.mutations,
        vec![
            RuleMutation::Delete { rule_id: 10 },
            RuleMutation::Create { enabled: true },
        ]
    );
}

#[test]
fn changed_trigger_type_is_only_disabled_when_rule_is_off() {
    let spec = spec(AutoModRuleKey::MemberProfileFilter);
    let rules = vec![ExistingAutoModRule::new(
        10,
        spec.name,
        AutoModRuleTriggerType::Keyword,
    )];

    let plan = plan_reconciliation(&rules, &spec, false, true);

    assert_eq!(
        plan.mutations,
        vec![RuleMutation::Update {
            rule_id: 10,
            enabled: false,
            mode: UpdateMode::DisableOnly,
        }]
    );
}

#[test]
fn current_name_wins_and_legacy_duplicate_is_removed() {
    let spec = spec(AutoModRuleKey::InviteLinkBlocking);
    let rules = vec![
        ExistingAutoModRule::new(10, spec.name, AutoModRuleTriggerType::Keyword),
        ExistingAutoModRule::new(
            11,
            "FoxSecura • Invite Links",
            AutoModRuleTriggerType::Keyword,
        ),
    ];

    let plan = plan_reconciliation(&rules, &spec, true, true);

    assert_eq!(
        plan.mutations,
        vec![
            RuleMutation::Delete { rule_id: 11 },
            RuleMutation::Update {
                rule_id: 10,
                enabled: true,
                mode: UpdateMode::FullSpec,
            },
        ]
    );
}
