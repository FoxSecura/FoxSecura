// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;

pub use detector::{
    ResolvedWebhookAuditEntry, WebhookAuditCandidate, WebhookChangeType,
    is_unauthorized_webhook_executor, resolve_recent_webhook_audit_entry,
};
