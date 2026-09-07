// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod action_burst;
mod decision;
mod url_signal;

pub use action_burst::{
    ActionBurstDetector, ActionBurstDetectorConfig, ActionBurstInput, ActionBurstResult,
};
pub use decision::ProtectionDecision;
pub use url_signal::{UrlSignal, extract_url_signals, host_matches};
