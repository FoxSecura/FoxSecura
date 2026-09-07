// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod formatter;
mod model;
mod structure;

pub use formatter::format_security_log;
pub use model::{
    create_incident_id, ActionCode, ActionStatus, AffectedResource, AffectedResourceType,
    FailureCode, LogSeverity, LogType, SecurityActionOutcome, SecurityActor, SecurityEvidence,
    SecurityIncident, SecurityIncidentError, SecurityLocation, ThresholdUnit,
};
pub use structure::{
    LogChannelDefinition, LOG_CHANNEL_DEFINITIONS, LOG_STRUCTURE_CATEGORY_ALIASES,
    LOG_STRUCTURE_CATEGORY_NAME,
};
