// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::AiAnalysisOutcome;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AiTelemetryCounters {
    pub classified: u64,
    pub skipped: u64,
    pub failed: u64,
}

impl AiTelemetryCounters {
    pub fn record(&mut self, outcome: &AiAnalysisOutcome) {
        match outcome {
            AiAnalysisOutcome::Classified { .. } => self.classified += 1,
            AiAnalysisOutcome::Skipped { .. } => self.skipped += 1,
            AiAnalysisOutcome::Failed { .. } => self.failed += 1,
        }
    }
}
