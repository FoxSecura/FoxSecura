// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Pseudos hoistés : un nom affiché qui commence par des caractères qui ne
//! sont ni des lettres ni des chiffres Unicode (règle V1) est renommé.
//!
//! - Nouveau pseudo : le nom nettoyé, tronqué à 32 caractères ; « Member »
//!   s'il ne reste rien.
//! - C'est une **correction, pas une sanction** : elle s'applique aussi aux
//!   membres de la liste blanche (V1). Le propriétaire et les membres
//!   au-dessus du bot ne sont pas modifiables (`role_hierarchy`).
//! - **Aucune boucle** : le pseudo posé commence par une lettre ou un chiffre,
//!   il n'est plus hoisté ; la mise à jour de membre qu'il provoque ne
//!   déclenche donc rien.

use super::{MemberRef, ModuleResponse, ModuleResult, member_incident};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{ActionCode, LogSeverity, SecurityEvidence};
use crate::protection::anti_raid::anti_nickname_hoisting::detect_hoisted_name;
use crate::protection::shared::{AUDIT_REASON_PREFIX, ProtectionModule, SanctionOutcome};

/// Nom du module dans les raisons d'audit log
/// (`FoxSecura Anti-Nickname Hoisting`).
pub const ANTI_HOISTING_AUDIT_LABEL: &str = "Anti-Nickname Hoisting";

/// Longueur maximale d'un pseudo Discord.
///
/// Comptée en unités UTF-16, la mesure la plus stricte : un pseudo qui la
/// respecte fait aussi au plus 32 caractères.
pub const MAX_NICKNAME_LENGTH: usize = 32;

/// Pseudo posé quand le nom ne contient ni lettre ni chiffre.
pub const FALLBACK_NICKNAME: &str = "Member";

/// Renommage à appliquer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicknameFix {
    /// Nom affiché hoisté (brut, non fiable).
    pub old: String,
    pub new: String,
}

/// Renommage d'un nom affiché hoisté ; `None` s'il ne l'est pas.
pub fn plan_nickname_fix(display_name: &str) -> Option<NicknameFix> {
    let detection = detect_hoisted_name(display_name);
    if !detection.triggered {
        return None;
    }

    let new = truncate_nickname(&detection.cleaned);
    Some(NicknameFix {
        old: display_name.to_owned(),
        new: if new.is_empty() {
            FALLBACK_NICKNAME.to_owned()
        } else {
            new
        },
    })
}

/// Tronque à [`MAX_NICKNAME_LENGTH`] unités UTF-16 sans couper un caractère,
/// puis retire les espaces finaux (Discord les supprimerait).
fn truncate_nickname(name: &str) -> String {
    let mut length = 0;
    let truncated: String = name
        .chars()
        .take_while(|character| {
            length += character.len_utf16();
            length <= MAX_NICKNAME_LENGTH
        })
        .collect();
    truncated.trim_end().to_owned()
}

/// Raison d'audit log du renommage (libellé V1, sans détail) ; elle suit la
/// convention du socle (`is_foxsecura_audit_reason`).
pub fn anti_hoisting_audit_reason() -> String {
    format!("{AUDIT_REASON_PREFIX} {ANTI_HOISTING_AUDIT_LABEL}")
}

/// Résultat du renommage : `warning` s'il est appliqué, `critical` sinon (le
/// nom hoisté reste visible en tête de la liste des membres). Jamais
/// terminal : une correction n'arrête pas la chaîne.
pub fn hoisting_response(
    language: Language,
    member: MemberRef,
    fix: &NicknameFix,
    outcome: &SanctionOutcome,
) -> ModuleResponse {
    let renamed = outcome.is_applied();
    let mut incident = member_incident(
        ProtectionModule::AntiNicknameHoisting.key(),
        if renamed {
            LogSeverity::Warning
        } else {
            LogSeverity::Critical
        },
        text(language, TextKey::HoistingSummary),
        member,
        outcome.action_outcome_as(ActionCode::NormalizeNickname),
    );
    // Rendus par `inline_literal` : un pseudo ne peut ni notifier, ni
    // injecter de formatage.
    incident.evidence.extend([
        SecurityEvidence::Text {
            label: text(language, TextKey::HoistingEvidenceOldName).to_owned(),
            value: fix.old.clone(),
        },
        SecurityEvidence::Text {
            label: text(language, TextKey::HoistingEvidenceNewName).to_owned(),
            value: fix.new.clone(),
        },
    ]);
    if !renamed {
        incident.recommendation =
            Some(text(language, TextKey::HoistingRecommendationCheckPermissions).to_owned());
    }

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: renamed,
            terminal: false,
        },
        incident,
    }
}
