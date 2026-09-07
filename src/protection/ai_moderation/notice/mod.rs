// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{AiClassification, rules::AiDecision};

pub fn build_moderator_notice(
    classification: &AiClassification,
    decision: &AiDecision,
) -> String {
    let categories = decision
        .categories
        .iter()
        .map(|category| category.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let reason = classification.reason.as_deref().unwrap_or("Aucune justification fournie");

    format!(
        "AI Moderation | severity={} | categories={} | reason={}",
        decision.severity.as_str(), categories, reason
    )
}
