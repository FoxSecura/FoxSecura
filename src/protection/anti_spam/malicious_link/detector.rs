// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::shared::{UrlSignal, extract_url_signals, host_matches};

const SHORTENERS: &[&str] = &["bit.ly", "tinyurl.com"];
const LOGGER_DOMAINS: &[&str] = &["grabify.link", "iplogger.org", "iplogger.com", "2no.co"];
const OFFICIAL_DOMAINS: &[&str] = &[
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "steamcommunity.com",
    "steampowered.com",
];
const SUSPICIOUS_TLDS: &[&str] = &["zip", "mov", "top", "xyz", "click", "work", "gq", "tk"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaliciousLinkContext {
    pub now: Option<Duration>,
    pub account_created_at: Option<Duration>,
    pub member_joined_at: Option<Duration>,
    pub new_account_min_age: Duration,
    pub new_member_grace: Duration,
}

impl Default for MaliciousLinkContext {
    fn default() -> Self {
        Self {
            now: None,
            account_created_at: None,
            member_joined_at: None,
            new_account_min_age: Duration::from_secs(7 * 24 * 60 * 60),
            new_member_grace: Duration::from_secs(10 * 60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaliciousLinkDetectionResult {
    pub triggered: bool,
    pub matched_pattern: Option<String>,
    pub reason: &'static str,
}

pub fn detect_malicious_link(
    content: &str,
    context: MaliciousLinkContext,
) -> MaliciousLinkDetectionResult {
    let normalized = content.to_ascii_lowercase();

    if let Some(pattern) = [
        "discord-nitro",
        "discord.nitro",
        "discordnitro",
        "free-nitro",
        "free.nitro",
        "freenitro",
        "grabify.link",
        "iplogger.",
    ]
    .into_iter()
    .find(|pattern| normalized.contains(pattern))
    {
        return detected(pattern.to_owned(), "Suspicious link pattern detected");
    }

    let signals = extract_url_signals(content);

    if let Some(signal) = signals.iter().find(|signal| is_suspicious_signal(signal)) {
        return detected(signal.searchable(), "Suspicious link pattern detected");
    }

    if let Some(signal) = signals
        .iter()
        .find(|signal| is_fresh_account_risk(signal, context))
    {
        let reason = if is_fresh_account(context) {
            "New account posted a risky external link"
        } else {
            "Recently joined member posted a risky external link"
        };
        return detected(signal.searchable(), reason);
    }

    MaliciousLinkDetectionResult {
        triggered: false,
        matched_pattern: None,
        reason: "No suspicious link detected",
    }
}

fn is_suspicious_signal(signal: &UrlSignal) -> bool {
    let host = signal.hostname.as_str();
    let searchable = signal.searchable();

    SHORTENERS.iter().any(|domain| host_matches(host, domain))
        || LOGGER_DOMAINS.iter().any(|domain| host_matches(host, domain))
        || is_fake_steam_host(host)
        || has_embedded_official_domain(host)
        || is_discord_gift_scam_host(host)
        || searchable.contains("free-nitro")
        || searchable.contains("free.nitro")
        || searchable.contains("discord-nitro")
        || searchable.contains("discord.nitro")
        || (host.contains("xn--")
            && ["discord", "nitro", "steam", "gift", "claim", "login"]
                .iter()
                .any(|word| signal.raw.to_ascii_lowercase().contains(word)))
}

fn is_fake_steam_host(host: &str) -> bool {
    host.starts_with("steamcommunity.") && host != "steamcommunity.com"
}

fn is_discord_gift_scam_host(host: &str) -> bool {
    matches!(host, "discord.gift" | "discord.promo" | "discord.claim" | "discordapp.gift" | "discordapp.promo" | "discordapp.claim")
}

fn has_embedded_official_domain(host: &str) -> bool {
    OFFICIAL_DOMAINS.iter().any(|domain| {
        host != *domain && host.contains(&format!("{domain}.")) && !host_matches(host, domain)
    })
}

fn is_fresh_account_risk(signal: &UrlSignal, context: MaliciousLinkContext) -> bool {
    (is_fresh_account(context) || is_fresh_member(context)) && has_secondary_risk(signal)
}

fn is_fresh_account(context: MaliciousLinkContext) -> bool {
    let (Some(now), Some(created_at)) = (context.now, context.account_created_at) else {
        return false;
    };

    now.saturating_sub(created_at) < context.new_account_min_age
}

fn is_fresh_member(context: MaliciousLinkContext) -> bool {
    let (Some(now), Some(joined_at)) = (context.now, context.member_joined_at) else {
        return false;
    };

    now.saturating_sub(joined_at) < context.new_member_grace
}

fn has_secondary_risk(signal: &UrlSignal) -> bool {
    signal.has_credentials
        || is_ipv4_host(&signal.hostname)
        || excessive_subdomain_depth(&signal.hostname)
        || signal
            .hostname
            .rsplit('.')
            .next()
            .is_some_and(|tld| SUSPICIOUS_TLDS.contains(&tld))
}

fn is_ipv4_host(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn excessive_subdomain_depth(host: &str) -> bool {
    host.split('.').count() > 4
}

fn detected(pattern: String, reason: &'static str) -> MaliciousLinkDetectionResult {
    MaliciousLinkDetectionResult {
        triggered: true,
        matched_pattern: Some(pattern),
        reason,
    }
}
