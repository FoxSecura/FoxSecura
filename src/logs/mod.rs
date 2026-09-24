// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod formatter;
mod model;
mod structure;

pub use formatter::{format_security_log, format_security_log_message, inline_literal};
pub use model::{
    ActionCode, ActionStatus, AffectedResource, AffectedResourceType, FailureCode, LogSeverity,
    LogType, SecurityActionOutcome, SecurityActor, SecurityEvidence, SecurityIncident,
    SecurityIncidentError, SecurityLocation, ThresholdUnit, create_incident_id,
};
pub use structure::{
    LOG_CHANNEL_DEFINITIONS, LOG_STRUCTURE_CATEGORY_ALIASES, LOG_STRUCTURE_CATEGORY_NAME,
    LogChannelDefinition,
};
