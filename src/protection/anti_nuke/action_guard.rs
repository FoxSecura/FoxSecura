// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::shared::{ActionBurstDetector, ActionBurstInput, ActionBurstResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NukeActionSpec {
    pub action: &'static str,
    pub threshold: usize,
    pub window: Duration,
}

impl NukeActionSpec {
    pub const fn new(action: &'static str, threshold: usize, window: Duration) -> Self {
        Self {
            action,
            threshold,
            window,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NukeActionInput {
    pub guild_id: u64,
    pub executor_id: u64,
    pub timestamp: Duration,
    pub threshold: Option<usize>,
    pub window: Option<Duration>,
}

impl NukeActionInput {
    pub const fn new(guild_id: u64, executor_id: u64, timestamp: Duration) -> Self {
        Self {
            guild_id,
            executor_id,
            timestamp,
            threshold: None,
            window: None,
        }
    }
}

pub fn detect_nuke_action(
    detector: &mut ActionBurstDetector,
    input: NukeActionInput,
    spec: NukeActionSpec,
) -> ActionBurstResult {
    detector.detect(ActionBurstInput::new(
        input.guild_id,
        input.executor_id,
        spec.action,
        input.threshold.unwrap_or(spec.threshold).max(1),
        input.window.unwrap_or(spec.window),
        input.timestamp,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorDecision {
    Ignore,
    Alert,
    Enforce,
}

pub const fn evaluate_executor_action(
    enabled: bool,
    executor_resolved: bool,
    executor_exempt: bool,
) -> ExecutorDecision {
    if !enabled || executor_exempt {
        return ExecutorDecision::Ignore;
    }

    if !executor_resolved {
        return ExecutorDecision::Alert;
    }

    ExecutorDecision::Enforce
}
