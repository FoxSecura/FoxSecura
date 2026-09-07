// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoneypotDetectionInput {
    pub channel_id: u64,
    pub honeypot_channel_id: Option<u64>,
    pub is_owner: bool,
    pub is_administrator: bool,
    pub can_manage_guild: bool,
    pub whitelisted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoneypotDetectionResult {
    pub triggered: bool,
    pub protected_channel: bool,
    pub exempt: bool,
}

pub const fn detect_honeypot_message(input: HoneypotDetectionInput) -> HoneypotDetectionResult {
    let protected_channel = match input.honeypot_channel_id {
        Some(honeypot_channel_id) => input.channel_id == honeypot_channel_id,
        None => false,
    };
    let exempt = input.is_owner
        || input.is_administrator
        || input.can_manage_guild
        || input.whitelisted;

    HoneypotDetectionResult {
        triggered: protected_channel && !exempt,
        protected_channel,
        exempt,
    }
}
