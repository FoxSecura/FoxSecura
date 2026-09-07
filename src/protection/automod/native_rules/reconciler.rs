// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::spec::{
    AutoModRuleSkipReason, AutoModRuleSpec, AutoModRuleTriggerType, rule_name_matches_spec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingAutoModRule {
    pub id: u64,
    pub name: String,
    pub trigger_type: AutoModRuleTriggerType,
}

impl ExistingAutoModRule {
    pub fn new(id: u64, name: impl Into<String>, trigger_type: AutoModRuleTriggerType) -> Self {
        Self {
            id,
            name: name.into(),
            trigger_type,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    FullSpec,
    DisableOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMutation {
    Create {
        enabled: bool,
    },
    Update {
        rule_id: u64,
        enabled: bool,
        mode: UpdateMode,
    },
    Delete {
        rule_id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncPlan {
    pub mutations: Vec<RuleMutation>,
    pub missing: bool,
    pub skipped_reason: Option<AutoModRuleSkipReason>,
}

pub fn plan_reconciliation(
    existing_rules: &[ExistingAutoModRule],
    spec: &AutoModRuleSpec,
    enabled: bool,
    create_when_disabled: bool,
) -> SyncPlan {
    let matches: Vec<&ExistingAutoModRule> = existing_rules
        .iter()
        .filter(|rule| rule_name_matches_spec(&rule.name, spec))
        .collect();

    if spec.is_empty_keyword_spec() {
        return SyncPlan {
            mutations: matches
                .into_iter()
                .map(|rule| RuleMutation::Delete { rule_id: rule.id })
                .collect(),
            missing: false,
            skipped_reason: Some(AutoModRuleSkipReason::NoKeywords),
        };
    }

    let primary = matches
        .iter()
        .copied()
        .find(|rule| rule.name == spec.name)
        .or_else(|| matches.first().copied());

    let Some(primary) = primary else {
        if !enabled && !create_when_disabled {
            return SyncPlan {
                missing: true,
                ..SyncPlan::default()
            };
        }

        if has_trigger_type_conflict(existing_rules, spec, None) {
            return SyncPlan {
                missing: true,
                skipped_reason: Some(trigger_conflict_reason(spec.trigger_type)),
                ..SyncPlan::default()
            };
        }

        return SyncPlan {
            mutations: vec![RuleMutation::Create { enabled }],
            ..SyncPlan::default()
        };
    };

    let mut mutations: Vec<RuleMutation> = matches
        .iter()
        .copied()
        .filter(|rule| rule.id != primary.id)
        .map(|rule| RuleMutation::Delete { rule_id: rule.id })
        .collect();

    if primary.trigger_type != spec.trigger_type && enabled {
        if has_trigger_type_conflict(existing_rules, spec, Some(primary.id)) {
            return SyncPlan {
                mutations,
                missing: false,
                skipped_reason: Some(trigger_conflict_reason(spec.trigger_type)),
            };
        }

        mutations.push(RuleMutation::Delete {
            rule_id: primary.id,
        });
        mutations.push(RuleMutation::Create { enabled });

        return SyncPlan {
            mutations,
            ..SyncPlan::default()
        };
    }

    mutations.push(RuleMutation::Update {
        rule_id: primary.id,
        enabled,
        mode: if primary.trigger_type == spec.trigger_type {
            UpdateMode::FullSpec
        } else {
            UpdateMode::DisableOnly
        },
    });

    SyncPlan {
        mutations,
        ..SyncPlan::default()
    }
}

fn has_trigger_type_conflict(
    existing_rules: &[ExistingAutoModRule],
    spec: &AutoModRuleSpec,
    primary_rule_id: Option<u64>,
) -> bool {
    if !spec.trigger_type.is_singleton() {
        return false;
    }

    existing_rules.iter().any(|rule| {
        Some(rule.id) != primary_rule_id
            && rule.trigger_type == spec.trigger_type
            && !rule_name_matches_spec(&rule.name, spec)
    })
}

fn trigger_conflict_reason(trigger_type: AutoModRuleTriggerType) -> AutoModRuleSkipReason {
    if matches!(trigger_type, AutoModRuleTriggerType::KeywordPreset) {
        AutoModRuleSkipReason::KeywordPresetConflict
    } else {
        AutoModRuleSkipReason::TriggerTypeConflict
    }
}
