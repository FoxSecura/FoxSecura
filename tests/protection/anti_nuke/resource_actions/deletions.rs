// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_nuke::{
    ExecutorDecision,
    resource_actions::{anti_channel_delete::detect_channel_delete, anti_role_delete::detect_role_delete},
};

#[test]
fn delete_modules_share_the_same_executor_policy() {
    for detect in [detect_channel_delete, detect_role_delete] {
        assert_eq!(detect(false, true, false), ExecutorDecision::Ignore);
        assert_eq!(detect(true, false, false), ExecutorDecision::Alert);
        assert_eq!(detect(true, true, true), ExecutorDecision::Ignore);
        assert_eq!(detect(true, true, false), ExecutorDecision::Enforce);
    }
}
