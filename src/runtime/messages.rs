// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::{
    anti_raid::{
        honeypot::{HoneypotDetectionInput, detect_honeypot_message},
        webhook_message::{WebhookMessageDetectionInput, WebhookMessageSpamInput,
            detect_webhook_message_threat},
    },
    anti_spam::{
        anti_everyone::detect_everyone_mention,
        anti_ghost_ping::GhostPingMessage,
        anti_mass_mention::detect_mass_mention,
        anti_ping_owner::AntiPingOwnerInput,
        anti_scam::{AntiScamContext, AntiScamObservation, detect_scam_message},
        anti_spam_ping::{AntiSpamPingInput, MentionTarget, MentionTargetKind},
        attachment_filter::detect_dangerous_attachment,
        invisible_char_filter::detect_obfuscated_text,
        malicious_link::{MaliciousLinkContext, detect_malicious_link},
        message_flood::{MessageFloodConfig, MessageWindow, evaluate},
    },
    automod::{adult_link::detect_adult_link, anti_invite::detect_invite_link,
        bad_words::{BadWordsLanguage, built_in_bad_words, detect_bad_words}},
    shared::{ActionBurstInput, ProtectionDecision},
};

use super::{Action, GuildProtectionConfig, PlannedAction, ProtectionEngine};

#[derive(Debug, Clone, Default)]
pub struct MessageInput {
    pub guild: u64,
    pub channel: u64,
    pub id: u64,
    pub author: u64,
    pub owner: u64,
    pub bot: bool,
    pub exempt: bool,
    pub webhook: Option<u64>,
    pub content: String,
    pub attachments: Vec<String>,
    pub mentions: Vec<u64>,
    pub role_mentions: Vec<u64>,
    pub mentions_everyone: bool,
    pub created_at: Option<Duration>,
    pub joined_at: Option<Duration>,
}

impl MessageInput {
    fn ghost(&self, now: Duration) -> GhostPingMessage {
        GhostPingMessage {
            guild_id: self.guild, message_id: self.id, channel_id: self.channel,
            author_id: self.author, mention_ids: self.mentions.clone(),
            role_mention_ids: self.role_mentions.clone(), mentions_everyone: self.mentions_everyone,
            timestamp: now,
        }
    }
}

impl ProtectionEngine {
    pub fn message(
        &mut self,
        config: &GuildProtectionConfig,
        message: &MessageInput,
        now: Duration,
        epoch: Duration,
        edited: bool,
    ) -> Vec<PlannedAction> {
        if message.guild == 0 || message.exempt || config.ignored_channels.contains(&message.channel)
            || (message.bot && message.webhook.is_none())
        {
            self.discard_message(message.guild, message.id);
            return Vec::new();
        }
        if !edited && !self.admit(message.guild, message.id, "message", now) {
            return Vec::new();
        }
        let mut actions = Vec::new();
        let mut reasons = Vec::new();
        let enabled = |name| config.enabled(name);
        let mentions = message.mentions.len() + message.role_mentions.len();
        let filenames: Vec<&str> = message.attachments.iter().map(String::as_str).collect();
        let links = MaliciousLinkContext {
            now: Some(epoch), account_created_at: message.created_at,
            member_joined_at: message.joined_at, ..Default::default()
        };
        for (module, triggered) in [
            ("anti_everyone", enabled("anti_everyone") &&
                detect_everyone_mention(&message.content, Some(message.mentions_everyone)).triggered),
            ("anti_mass_mention", enabled("anti_mass_mention") &&
                detect_mass_mention(mentions, None).triggered),
            ("attachment_filter", enabled("attachment_filter") &&
                detect_dangerous_attachment(&filenames).triggered),
            ("invisible_char_filter", enabled("invisible_char_filter") &&
                detect_obfuscated_text(&message.content).triggered),
            ("malicious_link", enabled("malicious_link") &&
                detect_malicious_link(&message.content, links).triggered),
            ("anti_scam", enabled("anti_scam") &&
                detect_scam_message(AntiScamObservation {
                    content: &message.content, attachment_names: &filenames,
                }, AntiScamContext { link_context: links }).decision == ProtectionDecision::Block),
            ("anti_invite", enabled("anti_invite") &&
                detect_invite_link(&message.content).decision == ProtectionDecision::Block),
            ("adult_link", enabled("adult_link") &&
                detect_adult_link(&message.content).decision == ProtectionDecision::Block),
        ] {
            if triggered { reasons.push(module); }
        }
        if enabled("bad_words") {
            let words = if config.blocked_words.is_empty() {
                built_in_bad_words(BadWordsLanguage::French).iter().map(|word| (*word).to_owned()).collect()
            } else { config.blocked_words.clone() };
            if detect_bad_words(&message.content, &words).decision == ProtectionDecision::Block {
                reasons.push("bad_words");
            }
        }
        if enabled("honeypot") && detect_honeypot_message(HoneypotDetectionInput {
            channel_id: message.channel, honeypot_channel_id: config.honeypot_channel,
            is_owner: message.author == message.owner, is_administrator: false,
            can_manage_guild: false, whitelisted: message.exempt,
        }).triggered {
            reasons.push("honeypot");
        }
        // Une modification ne compte pas comme un nouveau message dans les fenêtres.
        if !edited {
            if enabled("message_flood") {
                let flood = MessageFloodConfig { enabled: true, ..Default::default() };
                let count = self.burst.detect(ActionBurstInput::new(
                    message.guild, message.author, "message_flood", flood.message_limit + 1,
                    flood.window, now,
                )).count;
                if evaluate(flood, MessageWindow::new(count, Duration::ZERO)) == ProtectionDecision::Block {
                    reasons.push("message_flood");
                }
            }
            if enabled("anti_ping_owner") && self.owner_ping.detect(AntiPingOwnerInput {
                enabled: true, author_is_bot: message.bot, author_is_owner: message.author == message.owner,
                mentions_owner: message.mentions.contains(&message.owner), guild_id: message.guild,
                author_id: message.author, timestamp: now, threshold: None, window: None,
            }).decision == ProtectionDecision::Block {
                reasons.push("anti_ping_owner");
            }
            let targets: Vec<MentionTarget> = message.mentions.iter().map(|id| MentionTarget {
                kind: MentionTargetKind::User, id: *id,
            }).chain(message.role_mentions.iter().map(|id| MentionTarget {
                kind: MentionTargetKind::Role, id: *id,
            })).collect();
            if enabled("anti_spam_ping") && self.spam_ping.detect(AntiSpamPingInput {
                enabled: true, author_is_bot: message.bot, guild_id: message.guild,
                author_id: message.author, targets: &targets, timestamp: now, threshold: None, window: None,
            }).decision == ProtectionDecision::Block {
                reasons.push("anti_spam_ping");
            }
            if enabled("auto_slowmode") && self.slowmode.record(message.guild, message.channel, now)
                .decision == ProtectionDecision::Block
            {
                actions.push(PlannedAction::new("auto_slowmode", Action::Slowmode {
                    channel: message.channel, seconds: 10,
                }));
            }
        }
        if let Some(webhook) = message.webhook.filter(|_| enabled("webhook_message")) {
            let count = if edited { 0 } else {
                self.webhook_spam.detect(WebhookMessageSpamInput {
                    guild_id: message.guild, webhook_id: webhook, timestamp: now,
                    threshold: None, window: None,
                }).message_count
            };
            if detect_webhook_message_threat(WebhookMessageDetectionInput {
                content: &message.content, mentions_everyone: Some(message.mentions_everyone),
                mention_count: mentions, mass_mention_threshold: None, recent_message_count: Some(count),
                spam_threshold: None, malicious_link_context: links,
            }).triggered {
                reasons.push("webhook_message");
                actions.push(PlannedAction::new("webhook_message", Action::RemoveWebhook { webhook }));
            }
        }
        if enabled("anti_ghost_ping") && message.webhook.is_none() {
            if edited {
                let ghost = self.ghost.detect_updated(message.ghost(now));
                if ghost.decision == ProtectionDecision::Block {
                    actions.push(PlannedAction::new("anti_ghost_ping", Action::Alert));
                    if ghost.repeat_offense {
                        actions.push(PlannedAction::new("anti_ghost_ping", Action::Timeout { user: message.author }));
                    }
                }
            } else { self.ghost.record(message.ghost(now)); }
        }
        if let Some(module) = reasons.first().copied() {
            actions.push(PlannedAction::new(module, Action::DeleteMessage {
                channel: message.channel, message: message.id,
            }));
            // Conserver toutes les causes, mais ne supprimer le message qu'une fois.
            actions.extend(reasons.into_iter().skip(1).map(|module| PlannedAction::new(module, Action::Alert)));
        }
        actions
    }

    pub fn message_deleted(
        &mut self, config: &GuildProtectionConfig, guild: u64, message: u64, now: Duration,
    ) -> Vec<PlannedAction> {
        if !config.enabled("anti_ghost_ping") { return Vec::new(); }
        let result = self.ghost.detect_deleted(guild, message, now);
        if result.decision != ProtectionDecision::Block { return Vec::new(); }
        // Discord ne fournit pas l'auteur de la suppression : alerte seule, pas de sanction.
        vec![PlannedAction::new("anti_ghost_ping", Action::Alert)]
    }
}
