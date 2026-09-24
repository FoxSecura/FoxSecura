// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::i18n::{Language, TextKey, text};

use super::{
    ActionCode, ActionStatus, LogSeverity, LogType, SecurityEvidence, SecurityIncident,
    ThresholdUnit,
};

pub fn format_security_log(language: Language, incident: &SecurityIncident) -> String {
    let actions = incident
        .actions
        .iter()
        .map(|action| {
            format!(
                "{}: {}",
                text(language, action_key(action.action)),
                text(language, action_status_key(action.status))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    [
        format!(
            "{} {}",
            text(language, TextKey::LogsIncidentTitle),
            incident.incident_id
        ),
        format!(
            "{}: {}",
            text(language, TextKey::LogsFieldModule),
            incident.module
        ),
        format!(
            "{}: {}",
            text(language, TextKey::LogsFieldType),
            text(language, log_type_key(incident.log_type))
        ),
        format!(
            "{}: {}",
            text(language, TextKey::LogsFieldSeverity),
            text(language, severity_key(incident.severity))
        ),
        format!(
            "{}: {}",
            text(language, TextKey::LogsFieldSummary),
            incident.summary
        ),
        format!("{}: {actions}", text(language, TextKey::LogsFieldActions)),
    ]
    .join("\n")
}

/// Message complet envoyé dans un salon de logs.
///
/// Reprend [`format_security_log`] puis ajoute le membre, le salon, les preuves
/// chiffrées et la recommandation. Les mentions sont produites au format
/// Discord (`<@id>`, `<#id>`) : l'appelant doit désactiver les pings.
pub fn format_security_log_message(language: Language, incident: &SecurityIncident) -> String {
    let mut lines = vec![format_security_log(language, incident)];

    if let Some(actor) = &incident.actor {
        lines.push(format!(
            "{}: <@{}>",
            text(language, TextKey::LogsFieldActor),
            actor.user_id
        ));
    }

    if let Some(channel_id) = incident
        .location
        .as_ref()
        .and_then(|location| location.channel_id.as_ref())
    {
        lines.push(format!(
            "{}: <#{channel_id}>",
            text(language, TextKey::LogsFieldLocation)
        ));
    }

    for evidence in &incident.evidence {
        if let Some(value) = format_evidence(language, evidence) {
            lines.push(format!(
                "{}: {value}",
                text(language, TextKey::LogsFieldEvidence)
            ));
        }
    }

    if let Some(recommendation) = &incident.recommendation {
        lines.push(format!(
            "{}: {recommendation}",
            text(language, TextKey::LogsFieldRecommendation)
        ));
    }

    lines.join("\n")
}

/// Rend les preuves chiffrées. Les autres variantes (extraits de contenu,
/// domaines…) seront rendues par les modules qui les produisent.
fn format_evidence(language: Language, evidence: &SecurityEvidence) -> Option<String> {
    match evidence {
        SecurityEvidence::Threshold {
            observed,
            threshold,
            window_seconds,
            unit,
        } => {
            let mut value = format!("{observed}/{threshold} {}", text(language, unit_key(*unit)));
            if let Some(window_seconds) = window_seconds {
                value.push_str(&format!(
                    " {} {window_seconds} s",
                    text(language, TextKey::LogsEvidenceWindow)
                ));
            }
            Some(value)
        }
        SecurityEvidence::Text { label, value } => Some(format!("{label} = {value}")),
        _ => None,
    }
}

const fn unit_key(unit: ThresholdUnit) -> TextKey {
    match unit {
        ThresholdUnit::Messages => TextKey::LogsUnitMessages,
        ThresholdUnit::Mentions => TextKey::LogsUnitMentions,
        ThresholdUnit::Joins => TextKey::LogsUnitJoins,
        ThresholdUnit::Actions => TextKey::LogsUnitActions,
        ThresholdUnit::Signals => TextKey::LogsUnitSignals,
    }
}

const fn log_type_key(log_type: LogType) -> TextKey {
    match log_type {
        LogType::Message => TextKey::LogsTypeMessage,
        LogType::Server => TextKey::LogsTypeServer,
        LogType::Member => TextKey::LogsTypeMember,
        LogType::Channel => TextKey::LogsTypeChannel,
        LogType::Role => TextKey::LogsTypeRole,
        LogType::Moderation => TextKey::LogsTypeModeration,
    }
}

const fn severity_key(severity: LogSeverity) -> TextKey {
    match severity {
        LogSeverity::Info => TextKey::LogsSeverityInfo,
        LogSeverity::Warning => TextKey::LogsSeverityWarning,
        LogSeverity::Critical => TextKey::LogsSeverityCritical,
    }
}

const fn action_status_key(status: ActionStatus) -> TextKey {
    match status {
        ActionStatus::Success => TextKey::LogsStatusSuccess,
        ActionStatus::Partial => TextKey::LogsStatusPartial,
        ActionStatus::Failed => TextKey::LogsStatusFailed,
        ActionStatus::Skipped => TextKey::LogsStatusSkipped,
    }
}

const fn action_key(action: ActionCode) -> TextKey {
    match action {
        ActionCode::DeleteMessage => TextKey::LogsActionDeleteMessage,
        ActionCode::BanMember => TextKey::LogsActionBanMember,
        ActionCode::KickMember => TextKey::LogsActionKickMember,
        ActionCode::QuarantineMember => TextKey::LogsActionQuarantineMember,
        ActionCode::TimeoutMember => TextKey::LogsActionTimeoutMember,
        ActionCode::ApplyLockdown => TextKey::LogsActionApplyLockdown,
        ActionCode::RestoreLockdown => TextKey::LogsActionRestoreLockdown,
        ActionCode::RestoreChannel => TextKey::LogsActionRestoreChannel,
        ActionCode::RestoreRole => TextKey::LogsActionRestoreRole,
        ActionCode::RemoveWebhook => TextKey::LogsActionRemoveWebhook,
        ActionCode::ApplySlowmode => TextKey::LogsActionApplySlowmode,
        ActionCode::RemoveLimitedRole => TextKey::LogsActionRemoveLimitedRole,
        ActionCode::RestoreAutomodRule => TextKey::LogsActionRestoreAutomodRule,
        ActionCode::ImportBackup => TextKey::LogsActionImportBackup,
        ActionCode::RestoreBackup => TextKey::LogsActionRestoreBackup,
        ActionCode::UpdateConfig => TextKey::LogsActionUpdateConfig,
        ActionCode::ExecuteSensitiveAction => TextKey::LogsActionExecuteSensitiveAction,
        ActionCode::NormalizeNickname => TextKey::LogsActionNormalizeNickname,
        ActionCode::RollbackPermissions => TextKey::LogsActionRollbackPermissions,
        ActionCode::IgnoreExemptMember => TextKey::LogsActionIgnoreExemptMember,
        ActionCode::RequestStaffReview => TextKey::LogsActionRequestStaffReview,
        ActionCode::RecordAlert => TextKey::LogsActionRecordAlert,
        ActionCode::NotifyMember => TextKey::LogsActionNotifyMember,
    }
}
