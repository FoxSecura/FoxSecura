// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::shared::{extract_url_signals, host_matches};

#[test]
fn extracts_scheme_and_bare_urls() {
    let signals = extract_url_signals("https://discord.com/invite/test example.org/path");

    assert_eq!(signals.len(), 2);
    assert_eq!(signals[0].hostname, "discord.com");
    assert_eq!(signals[0].path, "/invite/test");
    assert_eq!(signals[1].hostname, "example.org");
    assert_eq!(signals[1].path, "/path");
}

#[test]
fn extracts_url_from_markdown_link() {
    let signals = extract_url_signals("[FoxSecura](https://discord.gg/FoxSecura)");

    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].hostname, "discord.gg");
    assert_eq!(signals[0].path, "/FoxSecura");
}

#[test]
fn host_matching_accepts_subdomains_only() {
    assert!(host_matches("canary.discord.com", "discord.com"));
    assert!(host_matches("discord.com", "discord.com"));
    assert!(!host_matches("notdiscord.com", "discord.com"));
}
