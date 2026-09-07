// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

pub const DEFAULT_SIGNAL_THRESHOLD: usize = 3;
pub const DEFAULT_CORRELATION_WINDOW: Duration = Duration::from_secs(30);
pub const DEFAULT_LOCKDOWN_DURATION: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_LOCKDOWN_SLOWMODE_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanicModeConfig {
    pub signal_threshold: usize,
    pub correlation_window: Duration,
}

impl Default for PanicModeConfig {
    fn default() -> Self {
        Self {
            signal_threshold: DEFAULT_SIGNAL_THRESHOLD,
            correlation_window: DEFAULT_CORRELATION_WINDOW,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PanicSignal {
    kind: String,
    timestamp: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanicModeResult {
    pub triggered: bool,
    pub distinct_types: usize,
    pub threshold: usize,
}

#[derive(Debug, Default)]
pub struct PanicModeDetector {
    config: PanicModeConfig,
    signals_by_guild: HashMap<u64, VecDeque<PanicSignal>>,
}

impl PanicModeDetector {
    pub fn new(mut config: PanicModeConfig) -> Self {
        config.signal_threshold = config.signal_threshold.max(1);
        config.correlation_window = config.correlation_window.max(Duration::from_millis(1));

        Self {
            config,
            signals_by_guild: HashMap::new(),
        }
    }

    pub fn record(
        &mut self,
        guild_id: u64,
        kind: impl Into<String>,
        timestamp: Duration,
    ) -> PanicModeResult {
        let signals = self.signals_by_guild.entry(guild_id).or_default();
        signals.retain(|signal| {
            timestamp.saturating_sub(signal.timestamp) <= self.config.correlation_window
        });
        signals.push_back(PanicSignal {
            kind: kind.into(),
            timestamp,
        });

        let distinct_types = signals
            .iter()
            .map(|signal| signal.kind.as_str())
            .collect::<HashSet<_>>()
            .len();
        let triggered = distinct_types >= self.config.signal_threshold;

        if triggered {
            self.signals_by_guild.remove(&guild_id);
        }

        PanicModeResult {
            triggered,
            distinct_types,
            threshold: self.config.signal_threshold,
        }
    }

    pub fn reset(&mut self) {
        self.signals_by_guild.clear();
    }
}
