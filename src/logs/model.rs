// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static INCIDENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogType {
    Message,
    Server,
    Member,
    Channel,
    Role,
    Moderation,
}

impl LogType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Server => "server",
            Self::Member => "member",
            Self::Channel => "channel",
            Self::Role => "role",
            Self::Moderation => "moderation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSeverity {
    Info,
    Warning,
    Critical,
}

impl LogSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    Success,
    Partial,
    Failed,
    Skipped,
}

impl ActionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCode {
    MissingPermission,
    RoleHierarchy,
    ResourceMissing,
    ExecutorUnavailable,
    DiscordUnavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCode {
    DeleteMessage,
    BanMember,
    KickMember,
    QuarantineMember,
    TimeoutMember,
    ApplyLockdown,
    RestoreLockdown,
    RestoreChannel,
    RestoreRole,
    RemoveWebhook,
    ApplySlowmode,
    RemoveLimitedRole,
    RestoreAutomodRule,
    ImportBackup,
    RestoreBackup,
    UpdateConfig,
    ExecuteSensitiveAction,
    NormalizeNickname,
    RollbackPermissions,
    IgnoreExemptMember,
    RequestStaffReview,
    RecordAlert,
    NotifyMember,
}

impl ActionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeleteMessage => "delete_message",
            Self::BanMember => "ban_member",
            Self::KickMember => "kick_member",
            Self::QuarantineMember => "quarantine_member",
            Self::TimeoutMember => "timeout_member",
            Self::ApplyLockdown => "apply_lockdown",
            Self::RestoreLockdown => "restore_lockdown",
            Self::RestoreChannel => "restore_channel",
            Self::RestoreRole => "restore_role",
            Self::RemoveWebhook => "remove_webhook",
            Self::ApplySlowmode => "apply_slowmode",
            Self::RemoveLimitedRole => "remove_limited_role",
            Self::RestoreAutomodRule => "restore_automod_rule",
            Self::ImportBackup => "import_backup",
            Self::RestoreBackup => "restore_backup",
            Self::UpdateConfig => "update_config",
            Self::ExecuteSensitiveAction => "execute_sensitive_action",
            Self::NormalizeNickname => "normalize_nickname",
            Self::RollbackPermissions => "rollback_permissions",
            Self::IgnoreExemptMember => "ignore_exempt_member",
            Self::RequestStaffReview => "request_staff_review",
            Self::RecordAlert => "record_alert",
            Self::NotifyMember => "notify_member",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdUnit {
    Messages,
    Mentions,
    Joins,
    Actions,
    Signals,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityEvidence {
    Threshold {
        observed: u64,
        threshold: u64,
        window_seconds: Option<u64>,
        unit: ThresholdUnit,
    },
    Content {
        excerpt: String,
    },
    Domain {
        domain: String,
        signals: Vec<String>,
        score: Option<f64>,
    },
    AuditLog {
        executor_resolved: bool,
        delay_ms: Option<u64>,
    },
    AccountAge {
        age_seconds: u64,
        minimum_age_seconds: u64,
    },
    Text {
        label: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityActionOutcome {
    pub action: ActionCode,
    pub status: ActionStatus,
    pub details: Option<String>,
    pub failure_code: Option<FailureCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityActor {
    pub user_id: String,
    pub tag: Option<String>,
    pub account_created_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityLocation {
    pub channel_id: Option<String>,
    pub message_id: Option<String>,
    pub jump_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffectedResourceType {
    Message,
    Member,
    Channel,
    Role,
    Server,
    Webhook,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedResource {
    pub resource_type: AffectedResourceType,
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityIncident {
    pub incident_id: String,
    pub module: String,
    pub log_type: LogType,
    pub severity: LogSeverity,
    pub summary: String,
    pub occurred_at: SystemTime,
    pub actor: Option<SecurityActor>,
    pub location: Option<SecurityLocation>,
    pub affected_resource: Option<AffectedResource>,
    pub evidence: Vec<SecurityEvidence>,
    pub actions: Vec<SecurityActionOutcome>,
    pub recommendation: Option<String>,
}

impl SecurityIncident {
    pub fn new(
        module: impl Into<String>,
        log_type: LogType,
        severity: LogSeverity,
        summary: impl Into<String>,
        actions: Vec<SecurityActionOutcome>,
    ) -> Self {
        Self {
            incident_id: create_incident_id(),
            module: module.into(),
            log_type,
            severity,
            summary: summary.into(),
            occurred_at: SystemTime::now(),
            actor: None,
            location: None,
            affected_resource: None,
            evidence: Vec::new(),
            actions,
            recommendation: None,
        }
    }

    pub fn validate(&self) -> Result<(), SecurityIncidentError> {
        if !self.incident_id.starts_with("FS-") {
            return Err(SecurityIncidentError::InvalidIncidentId);
        }

        if self.actions.is_empty() {
            return Err(SecurityIncidentError::MissingActionOutcome);
        }

        if self.severity == LogSeverity::Critical && self.evidence.is_empty() {
            return Err(SecurityIncidentError::CriticalIncidentWithoutEvidence);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityIncidentError {
    InvalidIncidentId,
    MissingActionOutcome,
    CriticalIncidentWithoutEvidence,
}

impl fmt::Display for SecurityIncidentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIncidentId => "l'identifiant d'incident doit commencer par FS-",
            Self::MissingActionOutcome => "un incident doit contenir au moins un résultat d'action",
            Self::CriticalIncidentWithoutEvidence => {
                "un incident critique doit contenir au moins une preuve"
            }
        };

        formatter.write_str(message)
    }
}

impl Error for SecurityIncidentError {}

pub fn create_incident_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let sequence = INCIDENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);

    format!("FS-{timestamp:X}-{sequence:04X}")
}
