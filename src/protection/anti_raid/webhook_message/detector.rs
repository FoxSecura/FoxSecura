// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::{
    anti_spam::{
        anti_everyone::detect_everyone_mention,
        anti_mass_mention::detect_mass_mention,
        malicious_link::{MaliciousLinkContext, detect_malicious_link},
    },
    automod::anti_invite::detect_invite_link,
    shared::{ActionBurstDetector, ActionBurstInput, ProtectionDecision},
};

const DEFAULT_MASS_MENTION_THRESHOLD: usize = 5;
const DEFAULT_SPAM_THRESHOLD: usize = 5;
const DEFAULT_SPAM_WINDOW: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookMessageThreat {
    DiscordInvite,
    SuspiciousLink,
    BroadcastMention,
    MassMention,
    Spam,
}

#[derive(Debug, Clone, Copy)]
pub struct WebhookMessageDetectionInput<'a> {
    pub content: &'a str,
    pub mentions_everyone: Option<bool>,
    pub mention_count: usize,
    pub mass_mention_threshold: Option<usize>,
    pub recent_message_count: Option<usize>,
    pub spam_threshold: Option<usize>,
    pub malicious_link_context: MaliciousLinkContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookMessageDetectionResult {
    pub triggered: bool,
    pub threats: Vec<WebhookMessageThreat>,
    pub mention_count: usize,
    pub mass_mention_threshold: usize,
    pub recent_message_count: usize,
    pub spam_threshold: usize,
}

pub fn detect_webhook_message_threat(
    input: WebhookMessageDetectionInput<'_>,
) -> WebhookMessageDetectionResult {
    let mass_mention_threshold = input
        .mass_mention_threshold
        .unwrap_or(DEFAULT_MASS_MENTION_THRESHOLD)
        .max(1);
    let spam_threshold = input.spam_threshold.unwrap_or(DEFAULT_SPAM_THRESHOLD).max(1);
    let recent_message_count = input.recent_message_count.unwrap_or(0);
    let mut threats = Vec::new();

    if detect_invite_link(input.content).decision == ProtectionDecision::Block {
        threats.push(WebhookMessageThreat::DiscordInvite);
    }

    if detect_malicious_link(input.content, input.malicious_link_context).triggered {
        threats.push(WebhookMessageThreat::SuspiciousLink);
    }

    if detect_everyone_mention(input.content, input.mentions_everyone).triggered {
        threats.push(WebhookMessageThreat::BroadcastMention);
    }

    if detect_mass_mention(input.mention_count, Some(mass_mention_threshold)).triggered {
        threats.push(WebhookMessageThreat::MassMention);
    }

    if recent_message_count >= spam_threshold {
        threats.push(WebhookMessageThreat::Spam);
    }

    WebhookMessageDetectionResult {
        triggered: !threats.is_empty(),
        threats,
        mention_count: input.mention_count,
        mass_mention_threshold,
        recent_message_count,
        spam_threshold,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookMessageSpamInput {
    pub guild_id: u64,
    pub webhook_id: u64,
    pub timestamp: Duration,
    pub threshold: Option<usize>,
    pub window: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookMessageSpamResult {
    pub triggered: bool,
    pub message_count: usize,
    pub threshold: usize,
    pub window: Duration,
}

#[derive(Debug, Default)]
pub struct WebhookMessageSpamDetector {
    detector: ActionBurstDetector,
}

impl WebhookMessageSpamDetector {
    pub fn detect(&mut self, input: WebhookMessageSpamInput) -> WebhookMessageSpamResult {
        let threshold = input.threshold.unwrap_or(DEFAULT_SPAM_THRESHOLD).max(1);
        let window = input.window.unwrap_or(DEFAULT_SPAM_WINDOW);
        let result = self.detector.detect(ActionBurstInput::new(
            input.guild_id,
            input.webhook_id,
            "webhook_message",
            threshold,
            window,
            input.timestamp,
        ));

        WebhookMessageSpamResult {
            triggered: result.decision == ProtectionDecision::Block,
            message_count: result.count,
            threshold,
            window,
        }
    }

    pub fn reset(&mut self) {
        self.detector.reset();
    }

    pub fn tracked_key_count(&self) -> usize {
        self.detector.tracked_key_count()
    }
}
