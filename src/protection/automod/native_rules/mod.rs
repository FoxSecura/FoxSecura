// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Gestion et réconciliation des règles AutoMod natives de Discord.
//!
//! La protection contre la modification ou la suppression abusive de ces règles
//! reste dans `anti_nuke::server_integrity::automod_rule_guard`.

mod reconciler;
mod spec;

pub use reconciler::{
    ExistingAutoModRule, RuleMutation, SyncPlan, UpdateMode, plan_reconciliation,
};
pub use spec::{
    AUTOMOD_RULE_PREFIX, AutoModActionType, AutoModEventType, AutoModRuleKey, AutoModRuleSkipReason,
    AutoModRuleSpec, AutoModRuleTriggerMetadata, AutoModRuleTriggerType, KeywordPreset,
    build_rule_specs, rule_name_matches_spec,
};
