// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_raid::honeypot::{
    HoneypotDetectionInput, detect_honeypot_message,
};

fn input() -> HoneypotDetectionInput {
    HoneypotDetectionInput {
        channel_id: 100,
        honeypot_channel_id: Some(100),
        is_owner: false,
        is_administrator: false,
        can_manage_guild: false,
        whitelisted: false,
    }
}

#[test]
fn triggers_for_non_exempt_member_in_honeypot() {
    assert!(detect_honeypot_message(input()).triggered);
}

#[test]
fn ignores_messages_outside_honeypot() {
    let mut value = input();
    value.channel_id = 200;
    assert!(!detect_honeypot_message(value).triggered);
}

#[test]
fn exempts_staff_and_whitelisted_members() {
    let mut staff = input();
    staff.can_manage_guild = true;
    assert!(!detect_honeypot_message(staff).triggered);

    let mut whitelisted = input();
    whitelisted.whitelisted = true;
    assert!(!detect_honeypot_message(whitelisted).triggered);
}
