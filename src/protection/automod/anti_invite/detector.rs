// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::shared::{ProtectionDecision, UrlSignal, extract_url_signals, host_matches};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiInviteDetectionResult {
    pub decision: ProtectionDecision,
    pub matched_invite: Option<String>,
}

pub fn detect_invite_link(content: &str) -> AntiInviteDetectionResult {
    let matched = extract_url_signals(content)
        .into_iter()
        .find(is_discord_invite);

    AntiInviteDetectionResult {
        decision: if matched.is_some() {
            ProtectionDecision::Block
        } else {
            ProtectionDecision::Allow
        },
        matched_invite: matched.map(|signal| signal.raw),
    }
}

fn is_discord_invite(signal: &UrlSignal) -> bool {
    if host_matches(&signal.hostname, "discord.gg")
        || host_matches(&signal.hostname, "discord.me")
        || host_matches(&signal.hostname, "dsc.gg")
    {
        return signal
            .path
            .strip_prefix('/')
            .is_some_and(has_valid_invite_code);
    }

    if host_matches(&signal.hostname, "discord.com")
        || host_matches(&signal.hostname, "discordapp.com")
    {
        return signal
            .path
            .strip_prefix("/invite/")
            .is_some_and(has_valid_invite_code);
    }

    false
}

fn has_valid_invite_code(value: &str) -> bool {
    let code = value
        .split(|character: char| matches!(character, '/' | '?' | '#'))
        .next()
        .unwrap_or_default();

    !code.is_empty()
        && code
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}
