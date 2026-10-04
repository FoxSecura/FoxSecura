// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-raid : rafale d'arrivées sur une guilde (V1).
//!
//! - **Fenêtre glissante par guilde** : seuil par défaut 5 (2 à 50), fenêtre
//!   par défaut 20 s (5 à 120), réglables dans `/config`. Déclenchement quand
//!   `nombre >= seuil` : c'est l'arrivée courante qui déclenche, puis chaque
//!   arrivée suivante dans la fenêtre.
//! - **Action** : verrouillage temporaire du serveur (sauté s'il est déjà
//!   actif) **et** quarantaine du membre qui arrive, avec repli timeout
//!   ([`ANTI_RAID_QUARANTINE`]). Les deux sont lancés en parallèle par le
//!   runtime : sur un gros serveur, le verrouillage fait un appel par salon.
//! - **Limite V1** : les membres arrivés **avant** le seuil ne sont pas mis
//!   en quarantaine ; l'incident rappelle de vérifier les arrivées récentes.
//! - Incident `critical` avec l'état du verrouillage (salons modifiés, en
//!   échec, total) et les actions de la quarantaine. Résultat terminal si une
//!   quarantaine ou un timeout a été appliqué.
//! - Un faux positif (vague d'arrivées légitimes après une annonce) verrouille
//!   le serveur 10 minutes : la levée manuelle est dans `/config`.

use super::{MemberRef, ModuleResponse, ModuleResult, member_incident, removed_roles_evidence};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{LogSeverity, SecurityEvidence, ThresholdUnit};
use crate::protection::anti_raid::join_burst::{JoinBurstLimits, JoinBurstResult};
use crate::protection::lockdown::{LockdownOutcome, LockdownReason, LockdownStart};
use crate::protection::quarantine::{QuarantineOutcome, QuarantineRequest};
use crate::protection::shared::{ProtectionModule, audit_reason};

/// Quarantaine du membre qui arrive pendant une rafale : avec repli timeout,
/// sans retrait des rôles dangereux (un membre qui arrive n'en a pas).
pub const ANTI_RAID_QUARANTINE: QuarantineRequest = QuarantineRequest {
    allow_timeout_fallback: true,
    ..QuarantineRequest::ROLE_ONLY
};

/// Raison d'audit log de la quarantaine (`FoxSecura Anti-Raid: join burst`).
pub fn anti_raid_audit_reason() -> String {
    audit_reason(LockdownReason::AntiRaid.audit_label(), "join burst")
}

/// Incident `critical` et résultat : terminal si le membre est contenu.
///
/// Actions : verrouillage, puis étapes de la quarantaine.
pub fn anti_raid_response(
    language: Language,
    member: MemberRef,
    burst: &JoinBurstResult,
    limits: JoinBurstLimits,
    lockdown: &LockdownOutcome,
    quarantine: &QuarantineOutcome,
) -> ModuleResponse {
    let contained = quarantine.contained();
    let mut incident = member_incident(
        ProtectionModule::AntiRaid.key(),
        LogSeverity::Critical,
        text(language, TextKey::AntiRaidSummary),
        member,
        lockdown.action_outcome(),
    );
    incident.actions.extend(quarantine.action_outcomes());
    incident.evidence.extend([
        SecurityEvidence::Threshold {
            observed: burst.join_count as u64,
            threshold: burst.threshold as u64,
            window_seconds: Some(u64::from(limits.window_seconds)),
            unit: ThresholdUnit::Joins,
        },
        SecurityEvidence::Text {
            label: text(language, TextKey::AntiRaidEvidenceLockdown).to_owned(),
            value: lockdown_state(language, lockdown),
        },
    ]);
    incident
        .evidence
        .extend(removed_roles_evidence(language, quarantine));
    incident.recommendation = Some(
        text(
            language,
            if contained {
                TextKey::AntiRaidRecommendationQuarantined
            } else {
                TextKey::AntiRaidRecommendationFailed
            },
        )
        .to_owned(),
    );

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: contained || lockdown.applied(),
            terminal: contained,
        },
        incident,
    }
}

/// État du verrouillage, rendu dans le log.
fn lockdown_state(language: Language, lockdown: &LockdownOutcome) -> String {
    let key = if lockdown.applied() {
        TextKey::AntiRaidLockdownApplied
    } else {
        match lockdown.start {
            LockdownStart::AlreadyActive => TextKey::AntiRaidLockdownAlreadyActive,
            _ => TextKey::AntiRaidLockdownFailed,
        }
    };
    text(language, key)
        .replace("{locked}", &lockdown.locked.to_string())
        .replace("{failed}", &lockdown.failed.to_string())
        .replace("{total}", &lockdown.total.to_string())
}
