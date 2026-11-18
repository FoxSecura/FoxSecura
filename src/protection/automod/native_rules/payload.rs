// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Charge utile JSON des règles AutoMod natives et limites Discord, sans
//! effet Discord.
//!
//! serenity 0.12.5 ne connaît ni le déclencheur `MEMBER_PROFILE` (6), ni
//! l'événement `MEMBER_UPDATE` (2), ni l'action `BLOCK_MEMBER_INTERACTION`
//! (4), et son `Trigger::MentionSpam` n'a pas `mention_raid_protection_enabled`
//! (`Trigger::Unknown` perd même les métadonnées à la sérialisation). La
//! charge est donc construite en JSON brut, par des fonctions pures testées à
//! l'octet près, puis envoyée telle quelle (`Http::create_automod_rule` et
//! `Http::edit_automod_rule` prennent `&impl Serialize`).
//!
//! # Limites Discord ([`apply_discord_limits`])
//!
//! Au plus [`MAX_KEYWORDS`] mots-clés de [`MAX_KEYWORD_CHARS`] caractères
//! chacun. Un mot personnalisé trop long (les mots perso en acceptent 100) est
//! **exclu de la règle native** mais reste dans le filtre runtime ; au-delà de
//! 1000 mots, la liste est tronquée. Les deux cas sont signalés dans le
//! rapport, jamais en échec global.

use serde_json::{Map, Value, json};
use serenity::model::guild::automod::{Rule, TriggerType};

use super::reconciler::{ExistingAutoModRule, UpdateMode};
use super::spec::{
    AutoModActionType, AutoModEventType, AutoModRuleSpec, AutoModRuleTriggerMetadata,
    AutoModRuleTriggerType, KeywordPreset,
};

/// Mots-clés au plus par règle (`keyword_filter`).
pub const MAX_KEYWORDS: usize = 1000;
/// Caractères au plus par mot-clé.
pub const MAX_KEYWORD_CHARS: usize = 60;
/// Mentions uniques au plus (`mention_total_limit`).
pub const MAX_MENTION_TOTAL_LIMIT: u8 = 50;
/// Caractères au plus du message de blocage (`custom_message`).
pub const MAX_CUSTOM_MESSAGE_CHARS: usize = 150;

/// Message affiché à l'auteur d'un message bloqué.
pub const BLOCK_MESSAGE_TEXT: &str = "Blocked by FoxSecura.";

/// Raison d'audit log de toute création, modification ou suppression par la
/// synchronisation (V1). Suit la convention `FoxSecura <module>: …` au sens
/// de `is_foxsecura_audit_reason` : `FoxSecura` suivi d'une espace.
pub const AUTOMOD_SETUP_REASON: &str = "FoxSecura AutoMod setup";
/// Suppression d'une règle de mots-clés dont la liste est vide.
pub const AUTOMOD_NO_KEYWORDS_REASON: &str = "FoxSecura AutoMod setup: no keywords configured";
/// Suppression puis recréation d'une règle dont le déclencheur a changé.
pub const AUTOMOD_MIGRATE_REASON: &str = "FoxSecura AutoMod setup: migrate trigger type";
/// Suppression d'un doublon d'une règle FoxSecura.
pub const AUTOMOD_DUPLICATE_CLEANUP_REASON: &str = "FoxSecura AutoMod duplicate cleanup";
/// Suppression de toutes les règles FoxSecura (propriétaire).
pub const AUTOMOD_CLEANUP_REASON: &str = "FoxSecura AutoMod cleanup";

const _: () = assert!(BLOCK_MESSAGE_TEXT.len() <= MAX_CUSTOM_MESSAGE_CHARS);

/// Mots-clés écartés de la règle native pour respecter les limites Discord.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeywordLimitReport {
    /// Mots de plus de [`MAX_KEYWORD_CHARS`] caractères, exclus de la règle
    /// native (toujours appliqués par le filtre runtime).
    pub too_long: Vec<String>,
    /// Mots au-delà des [`MAX_KEYWORDS`] premiers, non envoyés.
    pub truncated: usize,
}

impl KeywordLimitReport {
    pub fn is_empty(&self) -> bool {
        self.too_long.is_empty() && self.truncated == 0
    }
}

/// Applique les limites Discord à une spécification ; jamais d'échec.
///
/// Mots-clés trop longs exclus, liste tronquée à [`MAX_KEYWORDS`],
/// `mention_total_limit` borné à [`MAX_MENTION_TOTAL_LIMIT`]. Une liste
/// devenue vide fait supprimer la règle (`NoKeywords` du planificateur).
pub fn apply_discord_limits(spec: &AutoModRuleSpec) -> (AutoModRuleSpec, KeywordLimitReport) {
    let mut limited = spec.clone();
    let mut report = KeywordLimitReport::default();
    match &mut limited.trigger_metadata {
        AutoModRuleTriggerMetadata::KeywordFilter(words) => {
            let (kept, too_long): (Vec<String>, Vec<String>) = std::mem::take(words)
                .into_iter()
                .partition(|word| word.chars().count() <= MAX_KEYWORD_CHARS);
            report.too_long = too_long;
            report.truncated = kept.len().saturating_sub(MAX_KEYWORDS);
            *words = kept.into_iter().take(MAX_KEYWORDS).collect();
        }
        AutoModRuleTriggerMetadata::MentionSpam { total_limit, .. } => {
            *total_limit = (*total_limit).min(MAX_MENTION_TOTAL_LIMIT);
        }
        AutoModRuleTriggerMetadata::None | AutoModRuleTriggerMetadata::KeywordPreset(_) => {}
    }
    (limited, report)
}

/// Code Discord du déclencheur.
pub const fn trigger_type_code(trigger_type: AutoModRuleTriggerType) -> u8 {
    match trigger_type {
        AutoModRuleTriggerType::Keyword => 1,
        AutoModRuleTriggerType::Spam => 3,
        AutoModRuleTriggerType::KeywordPreset => 4,
        AutoModRuleTriggerType::MentionSpam => 5,
        AutoModRuleTriggerType::MemberProfile => 6,
        AutoModRuleTriggerType::Other(code) => code,
    }
}

/// Déclencheur d'un code Discord.
pub const fn trigger_type_from_code(code: u8) -> AutoModRuleTriggerType {
    match code {
        1 => AutoModRuleTriggerType::Keyword,
        3 => AutoModRuleTriggerType::Spam,
        4 => AutoModRuleTriggerType::KeywordPreset,
        5 => AutoModRuleTriggerType::MentionSpam,
        6 => AutoModRuleTriggerType::MemberProfile,
        other => AutoModRuleTriggerType::Other(other),
    }
}

const fn event_type_code(event_type: AutoModEventType) -> u8 {
    match event_type {
        AutoModEventType::MessageSend => 1,
        AutoModEventType::MemberUpdate => 2,
    }
}

const fn preset_code(preset: KeywordPreset) -> u8 {
    match preset {
        KeywordPreset::SexualContent => 2,
    }
}

fn actions(spec: &AutoModRuleSpec) -> Value {
    match spec.action_type() {
        AutoModActionType::BlockMemberInteraction => json!([{ "type": 4 }]),
        AutoModActionType::BlockMessage => json!([{
            "type": 1,
            "metadata": { "custom_message": BLOCK_MESSAGE_TEXT }
        }]),
    }
}

/// Métadonnées du déclencheur ; `None` pour le spam (aucune).
fn trigger_metadata(spec: &AutoModRuleSpec) -> Option<Value> {
    match &spec.trigger_metadata {
        AutoModRuleTriggerMetadata::None => None,
        AutoModRuleTriggerMetadata::KeywordFilter(words) => {
            Some(json!({ "keyword_filter": words }))
        }
        AutoModRuleTriggerMetadata::KeywordPreset(presets) => Some(json!({
            "presets": presets.iter().map(|preset| preset_code(*preset)).collect::<Vec<_>>()
        })),
        AutoModRuleTriggerMetadata::MentionSpam {
            total_limit,
            raid_protection_enabled,
        } => Some(json!({
            "mention_total_limit": total_limit,
            "mention_raid_protection_enabled": raid_protection_enabled
        })),
    }
}

fn full_body(spec: &AutoModRuleSpec, enabled: bool, with_trigger_type: bool) -> Value {
    let mut body = Map::new();
    body.insert("name".to_owned(), json!(spec.name));
    body.insert(
        "event_type".to_owned(),
        json!(event_type_code(spec.event_type())),
    );
    if with_trigger_type {
        body.insert(
            "trigger_type".to_owned(),
            json!(trigger_type_code(spec.trigger_type)),
        );
    }
    if let Some(metadata) = trigger_metadata(spec) {
        body.insert("trigger_metadata".to_owned(), metadata);
    }
    body.insert("actions".to_owned(), actions(spec));
    body.insert("enabled".to_owned(), json!(enabled));
    Value::Object(body)
}

/// Charge de création (`POST /guilds/{id}/auto-moderation/rules`).
///
/// La spécification doit être passée par [`apply_discord_limits`].
pub fn create_payload(spec: &AutoModRuleSpec, enabled: bool) -> Value {
    full_body(spec, enabled, true)
}

/// Charge de modification (`PATCH …/rules/{rule_id}`).
///
/// Jamais de `trigger_type` (Discord refuse de le changer). `DisableOnly`
/// (règle dont le déclencheur ne correspond plus) : seulement le nom et
/// `enabled: false`.
pub fn update_payload(spec: &AutoModRuleSpec, enabled: bool, mode: UpdateMode) -> Value {
    match mode {
        UpdateMode::FullSpec => full_body(spec, enabled, false),
        UpdateMode::DisableOnly => json!({ "name": spec.name, "enabled": false }),
    }
}

/// Règle lue sur Discord, réduite à ce que la réconciliation compare.
///
/// `TriggerType::Unknown(6)` est le filtre de profil (`MEMBER_PROFILE`), que
/// serenity 0.12.5 ne nomme pas.
pub fn existing_rule(rule: &Rule) -> ExistingAutoModRule {
    let code = u8::from(rule.trigger.kind());
    let trigger_type = match rule.trigger.kind() {
        TriggerType::Keyword => AutoModRuleTriggerType::Keyword,
        TriggerType::Spam => AutoModRuleTriggerType::Spam,
        TriggerType::KeywordPreset => AutoModRuleTriggerType::KeywordPreset,
        TriggerType::MentionSpam => AutoModRuleTriggerType::MentionSpam,
        _ => trigger_type_from_code(code),
    };
    ExistingAutoModRule::new(rule.id.get(), rule.name.clone(), trigger_type)
        .with_enabled(rule.enabled)
}
