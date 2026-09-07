// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_raid::webhook_watch::{
    WebhookAuditCandidate, WebhookChangeType, is_unauthorized_webhook_executor,
    resolve_recent_webhook_audit_entry,
};

#[test]
fn rejects_only_unauthorized_executors() {
    assert!(is_unauthorized_webhook_executor(Some(50), Some(10), 20, false));
    assert!(!is_unauthorized_webhook_executor(Some(10), Some(10), 20, false));
    assert!(!is_unauthorized_webhook_executor(Some(20), Some(10), 20, false));
    assert!(!is_unauthorized_webhook_executor(Some(50), Some(10), 20, true));
    assert!(!is_unauthorized_webhook_executor(None, Some(10), 20, false));
}

#[test]
fn resolves_one_recent_unprocessed_candidate_for_channel() {
    let candidates = [
        WebhookAuditCandidate {
            id: 1,
            executor_id: Some(50),
            target_id: Some(100),
            channel_id: Some(7),
            change_type: WebhookChangeType::Create,
            created_at: Duration::from_secs(98),
        },
        WebhookAuditCandidate {
            id: 2,
            executor_id: Some(60),
            target_id: Some(200),
            channel_id: Some(8),
            change_type: WebhookChangeType::Delete,
            created_at: Duration::from_secs(99),
        },
    ];

    let result = resolve_recent_webhook_audit_entry(
        &candidates,
        7,
        Duration::from_secs(100),
        Duration::from_secs(10),
        &[],
    )
    .expect("one candidate should resolve");

    assert_eq!(result.id, 1);
    assert_eq!(result.delay, Duration::from_secs(2));
}

#[test]
fn refuses_ambiguous_or_processed_candidates() {
    let candidates = [
        WebhookAuditCandidate {
            id: 1,
            executor_id: Some(50),
            target_id: Some(100),
            channel_id: Some(7),
            change_type: WebhookChangeType::Create,
            created_at: Duration::from_secs(98),
        },
        WebhookAuditCandidate {
            id: 2,
            executor_id: Some(60),
            target_id: Some(200),
            channel_id: Some(7),
            change_type: WebhookChangeType::Update,
            created_at: Duration::from_secs(99),
        },
    ];

    assert!(resolve_recent_webhook_audit_entry(
        &candidates,
        7,
        Duration::from_secs(100),
        Duration::from_secs(10),
        &[],
    )
    .is_none());

    assert!(resolve_recent_webhook_audit_entry(
        &candidates[..1],
        7,
        Duration::from_secs(100),
        Duration::from_secs(10),
        &[1],
    )
    .is_none());
}
