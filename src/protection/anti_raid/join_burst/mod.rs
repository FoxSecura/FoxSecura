// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod config;
mod detector;

pub use config::JoinBurstConfig;
pub use detector::{JoinBurstDetector, JoinBurstResult, JoinEvent};
