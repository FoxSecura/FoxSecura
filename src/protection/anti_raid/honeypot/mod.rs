// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;
mod plan;

pub use detector::{HoneypotDetectionInput, HoneypotDetectionResult, detect_honeypot_message};
pub use plan::{
    HONEYPOT_AUDIT_LABEL, HONEYPOT_QUARANTINE, HoneypotAuthor, HoneypotExemption, HoneypotPlan,
    HoneypotRoute, honeypot_audit_reason, honeypot_incident, plan_honeypot, route_honeypot,
};
