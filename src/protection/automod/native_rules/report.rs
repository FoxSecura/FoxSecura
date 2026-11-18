// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Textes de `/config` pour les règles natives : état lu sur Discord,
//! rapport de synchronisation et de suppression, sans effet Discord.
//!
//! Les noms de règles lus sur Discord passent par `inline_literal` : un
//! modérateur peut renommer une règle avec du Markdown ou des mentions.

use crate::i18n::{Language, TextKey, text};
use crate::logs::inline_literal;

use super::reconciler::ExistingAutoModRule;
use super::spec::{AutoModRuleKey, AutoModRuleSkipReason};
use super::sync::{CleanupOutcome, ReconcileOutcome, RuleSyncReport, RuleSyncStatus};

/// Longueur maximale d'un nom de règle affiché (Discord : 100).
const RULE_NAME_MAX_CHARS: usize = 100;

fn rule_name(name: &str) -> String {
    inline_literal(name, RULE_NAME_MAX_CHARS)
}

/// Règle FoxSecura existante pour une clé (nom actuel prioritaire).
pub fn find_rule(
    rules: &[ExistingAutoModRule],
    key: AutoModRuleKey,
) -> Option<&ExistingAutoModRule> {
    rules
        .iter()
        .find(|rule| rule.name == key.rule_name())
        .or_else(|| {
            rules
                .iter()
                .find(|rule| key.legacy_names().contains(&rule.name.as_str()))
        })
}

/// État des six règles, une par ligne ; `None` (lecture impossible) donne
/// « état inconnu ».
pub fn rule_state_lines(language: Language, rules: Option<&[ExistingAutoModRule]>) -> String {
    let Some(rules) = rules else {
        return text(language, TextKey::ConfigAutomodRulesUnknown).to_owned();
    };
    AutoModRuleKey::ALL
        .into_iter()
        .map(|key| match find_rule(rules, key) {
            Some(rule) => format!(
                "{} : {}",
                rule_name(&rule.name),
                text(
                    language,
                    if rule.enabled {
                        TextKey::ConfigAutomodRuleActive
                    } else {
                        TextKey::ConfigAutomodRuleInactive
                    }
                )
            ),
            None => format!(
                "{} : {}",
                rule_name(key.rule_name()),
                text(language, TextKey::ConfigAutomodRuleAbsent)
            ),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const fn status_key(status: &RuleSyncStatus) -> TextKey {
    match status {
        RuleSyncStatus::Created { enabled: true } => TextKey::ConfigAutomodReportCreated,
        RuleSyncStatus::Created { enabled: false } => TextKey::ConfigAutomodReportCreatedDisabled,
        RuleSyncStatus::Updated { enabled: true } => TextKey::ConfigAutomodReportUpdated,
        RuleSyncStatus::Updated { enabled: false } => TextKey::ConfigAutomodReportDisabled,
        RuleSyncStatus::Missing => TextKey::ConfigAutomodReportMissing,
        RuleSyncStatus::Skipped(AutoModRuleSkipReason::NoKeywords) => {
            TextKey::ConfigAutomodReportNoKeywords
        }
        RuleSyncStatus::Skipped(
            AutoModRuleSkipReason::KeywordPresetConflict
            | AutoModRuleSkipReason::TriggerTypeConflict,
        ) => TextKey::ConfigAutomodReportConflict,
        RuleSyncStatus::Failed(_) => TextKey::ConfigAutomodReportFailed,
    }
}

/// Une ligne par règle, puis les mots écartés par les limites Discord.
fn report_line(language: Language, report: &RuleSyncReport) -> String {
    let mut line = format!(
        "{} : {}",
        rule_name(report.key.rule_name()),
        text(language, status_key(&report.status))
    );
    if let RuleSyncStatus::Failed(failure) = &report.status {
        line.push_str(&format!(" ({})", inline_literal(&failure.details, 80)));
    }
    if report.removed > 0 {
        line.push_str(&format!(
            " ; {} : {}",
            text(language, TextKey::ConfigAutomodReportRemoved),
            report.removed
        ));
    }
    if !report.failures.is_empty() {
        line.push_str(&format!(
            " ; {} : {}",
            text(language, TextKey::ConfigAutomodReportFailed),
            report.failures.len()
        ));
    }
    if !report.limits.too_long.is_empty() {
        line.push_str(&format!(
            "\n  {} : {}",
            text(language, TextKey::ConfigAutomodReportTooLong),
            report.limits.too_long.len()
        ));
    }
    if report.limits.truncated > 0 {
        line.push_str(&format!(
            "\n  {} : {}",
            text(language, TextKey::ConfigAutomodReportTruncated),
            report.limits.truncated
        ));
    }
    line
}

/// Rapport de réconciliation, au plus 2000 caractères (message Discord).
pub fn reconcile_report(language: Language, outcome: &ReconcileOutcome) -> String {
    let body = match outcome {
        ReconcileOutcome::MissingPermission => {
            text(language, TextKey::ConfigAutomodMissingPermission).to_owned()
        }
        ReconcileOutcome::ReadFailed(_) => {
            text(language, TextKey::ConfigAutomodReadFailed).to_owned()
        }
        ReconcileOutcome::Synced(reports) => reports
            .iter()
            .map(|report| report_line(language, report))
            .collect::<Vec<_>>()
            .join("\n"),
    };
    truncate(format!(
        "**{}**\n{body}",
        text(language, TextKey::ConfigAutomodReportTitle)
    ))
}

/// Rapport de la réconciliation déclenchée par un interrupteur : `None` si
/// tout s'est bien passé (le tableau de bord suffit).
pub fn toggle_report(language: Language, outcome: &ReconcileOutcome) -> Option<String> {
    let quiet = match outcome {
        ReconcileOutcome::Synced(reports) => reports.iter().all(|report| {
            matches!(
                report.status,
                RuleSyncStatus::Created { .. }
                    | RuleSyncStatus::Updated { .. }
                    | RuleSyncStatus::Missing
            ) && report.failures.is_empty()
                && report.limits.is_empty()
        }),
        _ => false,
    };
    (!quiet).then(|| reconcile_report(language, outcome))
}

/// Rapport de la suppression des règles FoxSecura.
pub fn cleanup_report(language: Language, outcome: &CleanupOutcome) -> String {
    truncate(match outcome {
        CleanupOutcome::MissingPermission => {
            text(language, TextKey::ConfigAutomodMissingPermission).to_owned()
        }
        CleanupOutcome::ReadFailed(_) => {
            text(language, TextKey::ConfigAutomodReadFailed).to_owned()
        }
        CleanupOutcome::Done { deleted, failures } => {
            let mut lines = vec![format!(
                "{} : {deleted}",
                text(language, TextKey::ConfigAutomodDeleteDone)
            )];
            if !failures.is_empty() {
                lines.push(format!(
                    "{} : {}",
                    text(language, TextKey::ConfigAutomodDeleteFailed),
                    failures
                        .iter()
                        .map(|(name, _)| rule_name(name))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            lines.join("\n")
        }
    })
}

fn truncate(value: String) -> String {
    const MAX: usize = 2000;
    if value.chars().count() <= MAX {
        return value;
    }
    let mut truncated: String = value.chars().take(MAX - 1).collect();
    truncated.push('…');
    truncated
}
