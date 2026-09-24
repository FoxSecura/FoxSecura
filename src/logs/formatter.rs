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

/// Rend une preuve sur une ligne.
///
/// Toute valeur issue d'un message (extrait, domaine, motif, texte) passe par
/// [`inline_literal`] : elle ne peut ni notifier, ni injecter de formatage, ni
/// produire un lien cliquable. Les autres variantes seront rendues par les
/// modules qui les produisent.
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
        SecurityEvidence::Text { label, value } => Some(format!(
            "{label} = {}",
            inline_literal(value, LITERAL_MAX_CHARS)
        )),
        SecurityEvidence::Content { excerpt } => Some(format!(
            "{} = {}",
            text(language, TextKey::LogsEvidenceExcerpt),
            inline_literal(excerpt, LITERAL_MAX_CHARS)
        )),
        SecurityEvidence::Domain {
            domain, signals, ..
        } => {
            let mut value = format!(
                "{} = {}",
                text(language, TextKey::LogsEvidenceDomain),
                inline_literal(&defang(domain), LITERAL_MAX_CHARS)
            );
            for signal in signals {
                value.push_str(&format!(" ({})", inline_literal(signal, LITERAL_MAX_CHARS)));
            }
            Some(value)
        }
        _ => None,
    }
}

/// Longueur maximale d'une valeur rendue dans un log, en caractères.
const LITERAL_MAX_CHARS: usize = 150;

/// Rend une valeur non fiable en code en ligne Discord, sans possibilité d'en
/// sortir.
///
/// - Le code en ligne désactive le Markdown, les liens et le rendu des
///   mentions ; les accents graves sont remplacés (`ˋ`) pour qu'aucun ne ferme
///   le bloc.
/// - Les retours à la ligne et caractères de contrôle deviennent des espaces :
///   une valeur ne peut pas simuler une autre ligne du log.
/// - Les caractères invisibles, bidirectionnels ou de balise deviennent `�`,
///   et les marques combinantes empilées (zalgo) sont réduites à une seule : la
///   suite du message de log reste lisible et dans le bon sens.
/// - La valeur est tronquée à `max_chars` caractères.
pub fn inline_literal(value: &str, max_chars: usize) -> String {
    let mut rendered = String::with_capacity(value.len().min(max_chars * 4) + 2);
    rendered.push('`');

    let mut count = 0;
    let mut previous_combining = false;
    let mut truncated = false;
    for character in value.chars() {
        let combining = is_combining_mark(character);
        if combining && previous_combining {
            continue;
        }
        previous_combining = combining;

        if count == max_chars {
            truncated = true;
            break;
        }
        count += 1;

        rendered.push(match character {
            '`' => 'ˋ',
            character if character.is_control() => ' ',
            character if is_hidden_character(character) => '\u{fffd}',
            character => character,
        });
    }

    if truncated {
        rendered.push('…');
    }
    if count == 0 {
        rendered.push(' ');
    }
    rendered.push('`');
    rendered
}

/// Neutralise un domaine ou une URL (`https[:]//exemple[.]com`) : même copié
/// hors du bloc de code, il ne forme plus un lien.
fn defang(value: &str) -> String {
    value.replace("://", "[:]//").replace('.', "[.]")
}

/// Caractères invisibles ou qui modifient l'affichage du texte qui suit :
/// format Unicode (Cf), direction, balises, remplissages Hangul. Les liants
/// U+200C et U+200D sont conservés : ils composent des émojis et certaines
/// écritures.
fn is_hidden_character(character: char) -> bool {
    matches!(
        character as u32,
        0x00ad
            | 0x034f
            | 0x061c
            | 0x115f
            | 0x1160
            | 0x17b4
            | 0x17b5
            | 0x180b..=0x180f
            | 0x200b
            | 0x200e
            | 0x200f
            | 0x2028..=0x202e
            | 0x205f..=0x206f
            | 0x3164
            | 0xfeff
            | 0xffa0
            | 0xfff9..=0xfffb
            | 0xe0000..=0xe0fff
    )
}

fn is_combining_mark(character: char) -> bool {
    matches!(
        character as u32,
        0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff | 0x20d0..=0x20ff | 0xfe20..=0xfe2f
    )
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
