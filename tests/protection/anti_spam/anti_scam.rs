// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::{
    anti_spam::anti_scam::{
        AntiScamContext, AntiScamObservation, ScamConfidence, detect_scam_message,
    },
    shared::ProtectionDecision,
};

#[test]
fn correlates_bait_and_malicious_link() {
    let result = detect_scam_message(
        AntiScamObservation {
            content: "Free Nitro, act now: https://grabify.link/claim",
            attachment_names: &[],
        },
        AntiScamContext::default(),
    );
    assert_eq!(result.decision, ProtectionDecision::Block);
    assert!(result.confidence >= ScamConfidence::High);
}

#[test]
fn scam_vocabulary_alone_is_not_enough() {
    let result = detect_scam_message(
        AntiScamObservation {
            content: "We are discussing how fake free nitro scams work.",
            attachment_names: &[],
        },
        AntiScamContext::default(),
    );
    assert_eq!(result.decision, ProtectionDecision::Allow);
}

#[test]
fn dangerous_attachment_is_actionable() {
    let result = detect_scam_message(
        AntiScamObservation {
            content: "invoice attached",
            attachment_names: &["invoice.pdf.exe"],
        },
        AntiScamContext::default(),
    );
    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(result.confidence, ScamConfidence::Medium);
}
