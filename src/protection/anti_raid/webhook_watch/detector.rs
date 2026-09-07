// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookChangeType {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookAuditCandidate {
    pub id: u64,
    pub executor_id: Option<u64>,
    pub target_id: Option<u64>,
    pub channel_id: Option<u64>,
    pub change_type: WebhookChangeType,
    pub created_at: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedWebhookAuditEntry {
    pub id: u64,
    pub executor_id: Option<u64>,
    pub target_id: Option<u64>,
    pub change_type: WebhookChangeType,
    pub delay: Duration,
}

pub fn is_unauthorized_webhook_executor(
    executor_id: Option<u64>,
    bot_user_id: Option<u64>,
    owner_id: u64,
    whitelisted: bool,
) -> bool {
    let Some(executor_id) = executor_id else {
        return false;
    };

    if Some(executor_id) == bot_user_id || executor_id == owner_id {
        return false;
    }

    !whitelisted
}

pub fn resolve_recent_webhook_audit_entry(
    candidates: &[WebhookAuditCandidate],
    channel_id: u64,
    now: Duration,
    max_age: Duration,
    processed_entry_ids: &[u64],
) -> Option<ResolvedWebhookAuditEntry> {
    let future_tolerance = Duration::from_secs(1);
    let mut matching = candidates.iter().filter(|candidate| {
        if processed_entry_ids.contains(&candidate.id) || candidate.channel_id != Some(channel_id) {
            return false;
        }

        if candidate.created_at > now.saturating_add(future_tolerance) {
            return false;
        }

        now.saturating_sub(candidate.created_at) <= max_age
    });

    let candidate = *matching.next()?;
    if matching.next().is_some() {
        return None;
    }

    Some(ResolvedWebhookAuditEntry {
        id: candidate.id,
        executor_id: candidate.executor_id,
        target_id: candidate.target_id,
        change_type: candidate.change_type,
        delay: now.saturating_sub(candidate.created_at),
    })
}
