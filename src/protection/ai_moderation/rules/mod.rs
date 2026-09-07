// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod decision;

pub use decision::{
    AiDecision, AiModerationAction, AiRuleSettings, decide_ai_moderation_action,
    is_at_least_severity,
};
