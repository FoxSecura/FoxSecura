// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_raid::anti_bot::detect_bot_join;

#[test]
fn detects_bot_accounts_only() {
    assert!(detect_bot_join(true).triggered);
    assert!(!detect_bot_join(false).triggered);
}
