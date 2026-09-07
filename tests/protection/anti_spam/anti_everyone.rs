// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_spam::anti_everyone::detect_everyone_mention;

#[test]
fn detects_everyone_and_here_with_text_fallback() {
    assert!(detect_everyone_mention("hello @everyone", None).triggered);
    assert!(detect_everyone_mention("hello @HERE!", None).triggered);
}

#[test]
fn discord_metadata_is_authoritative() {
    assert!(!detect_everyone_mention("@everyone", Some(false)).triggered);
    assert!(detect_everyone_mention("nothing", Some(true)).triggered);
}

#[test]
fn ignores_embedded_word_like_markers() {
    assert!(!detect_everyone_mention("mail@everyone_test", None).triggered);
}
