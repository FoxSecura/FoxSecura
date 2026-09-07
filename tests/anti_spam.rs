// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_spam::{
    AntiSpamConfig, AntiSpamDecision, MessageWindow, evaluate,
};

fn config(enabled: bool) -> AntiSpamConfig {
    AntiSpamConfig::new(enabled, 5, Duration::from_secs(5))
}

#[test]
fn disabled_protection_allows_messages() {
    let decision = evaluate(
        config(false),
        MessageWindow::new(20, Duration::from_secs(1)),
    );

    assert_eq!(decision, AntiSpamDecision::Allow);
}

#[test]
fn message_count_at_limit_is_allowed() {
    let decision = evaluate(
        config(true),
        MessageWindow::new(5, Duration::from_secs(5)),
    );

    assert_eq!(decision, AntiSpamDecision::Allow);
}

#[test]
fn message_count_above_limit_is_blocked() {
    let decision = evaluate(
        config(true),
        MessageWindow::new(6, Duration::from_secs(5)),
    );

    assert_eq!(decision, AntiSpamDecision::Block);
}

#[test]
fn messages_outside_the_window_are_allowed() {
    let decision = evaluate(
        config(true),
        MessageWindow::new(20, Duration::from_secs(6)),
    );

    assert_eq!(decision, AntiSpamDecision::Allow);
}
