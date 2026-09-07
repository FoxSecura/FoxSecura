// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::prefilter::{
    MAX_ANALYZABLE_LENGTH, PrefilterVerdict, prefilter_message,
};

#[test]
fn empty_content_is_skipped() {
    assert_eq!(prefilter_message("   \n\t"), PrefilterVerdict::Skip);
}

#[test]
fn short_text_is_analyzed() {
    assert_eq!(prefilter_message("kys"), PrefilterVerdict::Analyze);
}

#[test]
fn url_only_content_is_skipped() {
    assert_eq!(
        prefilter_message("https://example.com/path"),
        PrefilterVerdict::Skip
    );
}

#[test]
fn discord_markup_and_emoji_only_content_is_skipped() {
    assert_eq!(
        prefilter_message("<@123456> <:fox:789012> 👍"),
        PrefilterVerdict::Skip
    );
}

#[test]
fn prose_with_a_url_is_analyzed() {
    assert_eq!(
        prefilter_message("regarde https://example.com"),
        PrefilterVerdict::Analyze
    );
}

#[test]
fn content_above_limit_is_skipped() {
    let content = "a".repeat(MAX_ANALYZABLE_LENGTH + 1);
    assert_eq!(prefilter_message(&content), PrefilterVerdict::Skip);
}

#[test]
fn content_at_limit_is_analyzed() {
    let content = "a".repeat(MAX_ANALYZABLE_LENGTH);
    assert_eq!(prefilter_message(&content), PrefilterVerdict::Analyze);
}
