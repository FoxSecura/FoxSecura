// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;
mod response;

pub use detector::{
    WebhookMessageDetectionInput, WebhookMessageDetectionResult, WebhookMessageSpamDetector,
    WebhookMessageSpamInput, WebhookMessageSpamResult, WebhookMessageThreat,
    detect_webhook_message_threat,
};
pub use response::{
    WEBHOOK_MASS_MENTION_THRESHOLD, WEBHOOK_SPAM_THRESHOLD, WEBHOOK_SPAM_WINDOW,
    WebhookMessageIncidentInput, WebhookOrigin, is_own_webhook_message, webhook_message_incident,
};
