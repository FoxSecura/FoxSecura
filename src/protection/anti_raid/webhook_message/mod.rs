// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;

pub use detector::{
    WebhookMessageDetectionInput, WebhookMessageDetectionResult, WebhookMessageSpamDetector,
    WebhookMessageSpamInput, WebhookMessageSpamResult, WebhookMessageThreat,
    detect_webhook_message_threat,
};
