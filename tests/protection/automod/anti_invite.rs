// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::{ProtectionDecision, automod::anti_invite::detect_invite_link};

#[test]
fn detects_discord_gg_invite() {
    let result = detect_invite_link("Rejoins-nous sur https://discord.gg/AbC-123");

    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(
        result.matched_invite.as_deref(),
        Some("https://discord.gg/AbC-123")
    );
}

#[test]
fn detects_discord_com_invite() {
    let result = detect_invite_link("https://discord.com/invite/FoxSecura");

    assert_eq!(result.decision, ProtectionDecision::Block);
}

#[test]
fn detects_bare_invite_link() {
    let result = detect_invite_link("discord.gg/FoxSecura");

    assert_eq!(result.decision, ProtectionDecision::Block);
}

#[test]
fn detects_invite_inside_markdown_link() {
    let result = detect_invite_link("[Serveur](https://discord.gg/FoxSecura)");

    assert_eq!(result.decision, ProtectionDecision::Block);
}

#[test]
fn detects_supported_invite_aliases() {
    assert_eq!(
        detect_invite_link("https://discord.me/FoxSecura").decision,
        ProtectionDecision::Block
    );
    assert_eq!(
        detect_invite_link("https://dsc.gg/FoxSecura").decision,
        ProtectionDecision::Block
    );
}

#[test]
fn ignores_discord_page_without_invite() {
    let result = detect_invite_link("https://discord.com/developers/docs");

    assert_eq!(result.decision, ProtectionDecision::Allow);
    assert!(result.matched_invite.is_none());
}

#[test]
fn ignores_invite_host_without_code() {
    let result = detect_invite_link("https://discord.gg/");

    assert_eq!(result.decision, ProtectionDecision::Allow);
}

#[test]
fn ignores_unrelated_links() {
    let result = detect_invite_link("https://example.com/invite/FoxSecura");

    assert_eq!(result.decision, ProtectionDecision::Allow);
}
