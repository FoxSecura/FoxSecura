// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::SecurityIncident;

pub fn format_security_log(incident: &SecurityIncident) -> String {
    let actions = incident
        .actions
        .iter()
        .map(|action| format!("{}:{}", action.action.as_str(), action.status.as_str()))
        .collect::<Vec<_>>()
        .join(", ");

    [
        format!("FoxSecura Security Incident {}", incident.incident_id),
        format!("Module: {}", incident.module),
        format!("Type: {}", incident.log_type.as_str()),
        format!("Severity: {}", incident.severity.as_str()),
        format!("Summary: {}", incident.summary),
        format!("Actions: {actions}"),
    ]
    .join("\n")
}
