// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Gestion et réconciliation des règles AutoMod natives de Discord.
//!
//! - `spec` : les six règles (nom, déclencheur, métadonnées) ;
//! - `reconciler` : plan de réconciliation d'une règle ([`plan_reconciliation`]) ;
//! - `payload` : charge JSON brute et limites Discord.
//!
//! La protection contre la modification ou la suppression abusive de ces règles
//! reste dans `anti_nuke::server_integrity::automod_rule_guard`.

mod payload;
mod reconciler;
mod spec;

pub use payload::{
    AUTOMOD_CLEANUP_REASON, AUTOMOD_DUPLICATE_CLEANUP_REASON, AUTOMOD_MIGRATE_REASON,
    AUTOMOD_NO_KEYWORDS_REASON, AUTOMOD_SETUP_REASON, BLOCK_MESSAGE_TEXT, KeywordLimitReport,
    MAX_CUSTOM_MESSAGE_CHARS, MAX_KEYWORD_CHARS, MAX_KEYWORDS, MAX_MENTION_TOTAL_LIMIT,
    apply_discord_limits, create_payload, existing_rule, trigger_type_code, trigger_type_from_code,
    update_payload,
};
pub use reconciler::{
    ExistingAutoModRule, RuleMutation, SyncPlan, UpdateMode, plan_reconciliation,
};
pub use spec::{
    AUTOMOD_RULE_PREFIX, AutoModActionType, AutoModEventType, AutoModRuleKey,
    AutoModRuleSkipReason, AutoModRuleSpec, AutoModRuleTriggerMetadata, AutoModRuleTriggerType,
    KeywordPreset, build_rule_specs, rule_name_matches_spec,
};
