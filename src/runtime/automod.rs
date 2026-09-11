// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;
use serde_json::{Value, json};
use crate::protection::automod::{
    bad_words::{BadWordsLanguage, built_in_bad_words},
    native_rules::{AutoModRuleKey, AutoModRuleSpec, AutoModRuleTriggerType,
        AutoModRuleTriggerMetadata, ExistingAutoModRule, RuleMutation, UpdateMode,
        build_rule_specs, plan_reconciliation},
};
use super::{Error, GuildProtectionConfig};

pub fn rule_payload(spec: &AutoModRuleSpec, enabled: bool, config: &GuildProtectionConfig) -> Value {
    let trigger_type = match spec.trigger_type {
        AutoModRuleTriggerType::Keyword => 1,
        AutoModRuleTriggerType::Spam => 3,
        AutoModRuleTriggerType::KeywordPreset => 4,
        AutoModRuleTriggerType::MentionSpam => 5,
        AutoModRuleTriggerType::MemberProfile => 6,
    };
    let metadata = match &spec.trigger_metadata {
        AutoModRuleTriggerMetadata::None => json!({}),
        AutoModRuleTriggerMetadata::KeywordFilter(words) => json!({"keyword_filter": words}),
        AutoModRuleTriggerMetadata::KeywordPreset(_) => json!({"presets": [2]}),
        AutoModRuleTriggerMetadata::MentionSpam { total_limit, raid_protection_enabled } =>
            json!({"mention_total_limit": total_limit, "mention_raid_protection_enabled": raid_protection_enabled}),
    };
    let profile = spec.trigger_type == AutoModRuleTriggerType::MemberProfile;
    json!({
        "name": spec.name, "event_type": if profile { 2 } else { 1 }, "trigger_type": trigger_type,
        "trigger_metadata": metadata, "actions": [{"type": if profile { 4 } else { 1 }}],
        "enabled": enabled,
        "exempt_roles": config.exempt_roles.iter().map(u64::to_string).collect::<Vec<_>>(),
        "exempt_channels": config.ignored_channels.iter().map(u64::to_string).collect::<Vec<_>>(),
    })
}

pub async fn synchronize(
    ctx: &serenity::Context, guild: serenity::GuildId, config: &GuildProtectionConfig,
) -> Result<(), Error> {
    // Les règles natives ne peuvent pas fonctionner en observation avec une action bloquante.
    if !config.enforce || !config.enabled("native_rules") { return Ok(()); }
    let words = if config.blocked_words.is_empty() {
        built_in_bad_words(BadWordsLanguage::French).into_iter().map(str::to_owned).collect()
    } else { config.blocked_words.clone() };
    let mut failures = 0;
    for spec in build_rule_specs(&words) {
        let enabled = match spec.key {
            AutoModRuleKey::InviteLinkBlocking => config.enabled("anti_invite"),
            AutoModRuleKey::AdultLinksFiltering => config.enabled("adult_link"),
            AutoModRuleKey::BadWordsFilter => config.enabled("bad_words"),
            AutoModRuleKey::MentionSpamBlocking => config.enabled("anti_mass_mention"),
            AutoModRuleKey::GenericSpamBlocking => config.enabled("message_flood"),
            AutoModRuleKey::MemberProfileFilter => config.enabled("member_profile"),
        };
        let current = ctx.http.get_automod_rules(guild).await?;
        // Ne revendiquer que les règles créées par ce bot, même en cas d'homonymie.
        let bot = ctx.cache.current_user().id;
        let existing: Vec<ExistingAutoModRule> = current.iter().filter_map(|rule| {
            let trigger = match u8::from(rule.trigger.kind()) {
                1 => AutoModRuleTriggerType::Keyword,
                3 => AutoModRuleTriggerType::Spam,
                4 => AutoModRuleTriggerType::KeywordPreset,
                5 => AutoModRuleTriggerType::MentionSpam,
                6 => AutoModRuleTriggerType::MemberProfile,
                _ => return None,
            };
            let name = if rule.creator_id == bot { rule.name.clone() }
                else { format!("external:{}", rule.id) };
            Some(ExistingAutoModRule::new(rule.id.get(), name, trigger))
        }).collect();
        let plan = plan_reconciliation(&existing, &spec, enabled, false);
        if let Some(reason) = plan.skipped_reason {
            eprintln!("FoxSecura : règle {:?} non synchronisée ({reason:?})", spec.key);
        }
        for mutation in plan.mutations {
            let result = match mutation {
                RuleMutation::Create { enabled } => ctx.http.create_automod_rule(guild,
                    &rule_payload(&spec, enabled, config), Some("FoxSecura : synchronisation AutoMod")).await.map(|_| ()),
                RuleMutation::Update { rule_id, enabled, mode } => {
                    let payload = if mode == UpdateMode::DisableOnly { json!({"enabled": enabled}) }
                        else {
                            let mut payload = rule_payload(&spec, enabled, config);
                            // Le type du trigger est immuable après création.
                            payload.as_object_mut().unwrap().remove("trigger_type");
                            payload
                        };
                    ctx.http.edit_automod_rule(guild, serenity::RuleId::new(rule_id), &payload,
                        Some("FoxSecura : synchronisation AutoMod")).await.map(|_| ())
                }
                RuleMutation::Delete { rule_id } => ctx.http.delete_automod_rule(
                    guild, serenity::RuleId::new(rule_id), Some("FoxSecura : synchronisation AutoMod")).await,
            };
            if result.is_err() {
                failures += 1;
                eprintln!("FoxSecura : échec de synchronisation de {:?}", spec.key);
                // Ne pas créer un remplacement si la suppression précédente a échoué.
                break;
            }
        }
    }
    if failures == 0 { Ok(()) } else { Err("Synchronisation AutoMod partielle".into()) }
}
