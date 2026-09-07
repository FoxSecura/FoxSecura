// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_spam::malicious_link::{
    MaliciousLinkContext, detect_malicious_link,
};

#[test]
fn detects_logger_and_fake_brand_hosts() {
    assert!(detect_malicious_link("https://grabify.link/abc", MaliciousLinkContext::default()).triggered);
    assert!(detect_malicious_link("https://steamcommunity.ru/login", MaliciousLinkContext::default()).triggered);
}

#[test]
fn official_discord_link_is_allowed() {
    assert!(!detect_malicious_link("https://discord.com/channels/1/2", MaliciousLinkContext::default()).triggered);
}

#[test]
fn fresh_account_needs_secondary_url_risk() {
    let context = MaliciousLinkContext {
        now: Some(Duration::from_secs(10 * 24 * 60 * 60)),
        account_created_at: Some(Duration::from_secs(9 * 24 * 60 * 60)),
        ..MaliciousLinkContext::default()
    };
    assert!(detect_malicious_link("https://example.zip/claim", context).triggered);
    assert!(!detect_malicious_link("https://example.com/hello", context).triggered);
}
