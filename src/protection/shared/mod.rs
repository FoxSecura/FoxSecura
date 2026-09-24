// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod action_burst;
mod decision;
mod exemption;
mod message;
mod url_signal;

pub use action_burst::{
    ActionBurstDetector, ActionBurstDetectorConfig, ActionBurstInput, ActionBurstResult,
};
pub use decision::ProtectionDecision;
pub use exemption::{
    AuthorWhitelist, MessageScope, is_author_exempt, is_everyone_role, message_scope,
};
pub use message::{
    DISCORD_EPOCH_MILLIS, GuildMessage, MessageIgnoreReason, MessageSnapshot, screen_message,
    snowflake_timestamp,
};
pub use url_signal::{UrlSignal, extract_url_signals, host_matches};
