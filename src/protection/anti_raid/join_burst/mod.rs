// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod config;
mod detector;

pub use config::{
    DEFAULT_JOIN_THRESHOLD, DEFAULT_JOIN_WINDOW_SECONDS, JoinBurstConfig, JoinBurstLimits,
    JoinBurstLimitsError, MAX_JOIN_THRESHOLD, MAX_JOIN_WINDOW_SECONDS, MIN_JOIN_THRESHOLD,
    MIN_JOIN_WINDOW_SECONDS,
};
pub use detector::{JoinBurstDetector, JoinBurstResult, JoinEvent};
