// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::{
    anti_spam::{
        attachment_filter::detect_dangerous_attachment,
        malicious_link::{MaliciousLinkContext, detect_malicious_link},
    },
    shared::ProtectionDecision,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScamConfidence {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy)]
pub struct AntiScamObservation<'a> {
    pub content: &'a str,
    pub attachment_names: &'a [&'a str],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AntiScamContext {
    pub link_context: MaliciousLinkContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiScamDetectionResult {
    pub decision: ProtectionDecision,
    pub confidence: ScamConfidence,
    pub score: u8,
    pub signals: Vec<&'static str>,
}

pub fn detect_scam_message(
    observation: AntiScamObservation<'_>,
    context: AntiScamContext,
) -> AntiScamDetectionResult {
    let mut score = 0u8;
    let mut signals = Vec::new();
    let content = observation.content.to_ascii_lowercase();

    let malicious_link = detect_malicious_link(observation.content, context.link_context);
    if malicious_link.triggered {
        score = score.saturating_add(4);
        signals.push("malicious_link");
    }

    if detect_dangerous_attachment(observation.attachment_names).triggered {
        score = score.saturating_add(4);
        signals.push("dangerous_attachment");
    }

    if contains_any(&content, &["verify your account", "login to claim", "scan qr", "confirm your account", "re-authenticate"]) {
        score = score.saturating_add(3);
        signals.push("credential_request");
    }

    if contains_any(&content, &["free nitro", "nitro gift", "steam gift", "crypto giveaway", "airdrop", "free gift"]) {
        score = score.saturating_add(2);
        signals.push("bait_offer");
    }

    if contains_any(&content, &["act now", "limited time", "urgent", "expires soon", "immediately"]) {
        score = score.saturating_add(1);
        signals.push("urgency");
    }

    if contains_any(&content, &["seed phrase", "wallet connect", "recovery phrase", "private key"]) {
        score = score.saturating_add(3);
        signals.push("wallet_credentials");
    }

    let confidence = match score {
        0 => ScamConfidence::None,
        1..=2 => ScamConfidence::Low,
        3..=4 => ScamConfidence::Medium,
        5..=7 => ScamConfidence::High,
        _ => ScamConfidence::Critical,
    };
    let decision = if confidence >= ScamConfidence::Medium {
        ProtectionDecision::Block
    } else {
        ProtectionDecision::Allow
    };

    AntiScamDetectionResult {
        decision,
        confidence,
        score,
        signals,
    }
}

fn contains_any(content: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| content.contains(pattern))
}
