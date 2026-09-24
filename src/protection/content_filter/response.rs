// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Vérification de révision et incident des filtres de contenu, sans effet
//! Discord.

use super::{ContentDetection, ContentFinding, MessageContent, MessageEvent};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{FailureCode, SecurityEvidence, SecurityIncident, ThresholdUnit};
use crate::protection::shared::{
    DeleteMessageOutcome, GuildMessage, ProtectionModule, message_incident,
};

/// Longueur maximale de l'extrait conservé dans l'incident, en caractères.
///
/// L'extrait est brut : c'est le formateur des logs qui le neutralise
/// (mentions, formatage, caractères invisibles) avant l'envoi.
pub const EXCERPT_MAX_CHARS: usize = 120;

/// État de la version analysée au moment de supprimer après une modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionCheck {
    /// La version courante est celle qui a été analysée : suppression.
    Current,
    /// Le message a été modifié depuis : la nouvelle version sera analysée par
    /// son propre événement ; aucune suppression ni incident ici.
    Superseded,
    /// Le message n'existe plus : rien à faire.
    Deleted,
}

impl RevisionCheck {
    pub const fn allows_deletion(self) -> bool {
        matches!(self, Self::Current)
    }
}

/// Compare la version analysée à la version courante (`None` si le message a
/// disparu).
///
/// Évite d'effacer une version déjà corrigée : un membre peut modifier deux
/// fois son message avant que la suppression ne parte.
pub fn check_revision(
    analyzed: &MessageContent,
    current: Option<&MessageContent>,
) -> RevisionCheck {
    match current {
        None => RevisionCheck::Deleted,
        Some(current) if current == analyzed => RevisionCheck::Current,
        Some(_) => RevisionCheck::Superseded,
    }
}

/// Classe l'échec de lecture de la version courante.
///
/// `None` pour un `404` (message déjà supprimé : rien à faire). Sinon la
/// suppression n'est pas tentée, faute de pouvoir vérifier la version : le
/// résultat `failed` produit un incident critique pour que l'équipe vérifie
/// le message elle-même.
pub fn revision_fetch_failure(
    status: Option<u16>,
    details: impl Into<String>,
) -> Option<DeleteMessageOutcome> {
    let failure_code = match status {
        Some(404) => return None,
        Some(403) => FailureCode::MissingPermission,
        Some(429 | 500..=599) | None => FailureCode::DiscordUnavailable,
        Some(_) => FailureCode::Unknown,
    };

    Some(DeleteMessageOutcome::Failed {
        failure_code,
        details: details.into(),
    })
}

/// Extrait brut tronqué à [`EXCERPT_MAX_CHARS`] caractères.
pub fn excerpt(content: &str) -> String {
    let mut characters = content.chars();
    let mut excerpt: String = characters.by_ref().take(EXCERPT_MAX_CHARS).collect();
    if characters.next().is_some() {
        excerpt.push('…');
    }
    excerpt
}

/// Construit l'incident : preuve propre au module, extrait du message et, pour
/// une modification, la nature de l'événement.
pub fn build_incident(
    language: Language,
    message: &GuildMessage,
    detection: &ContentDetection,
    event: MessageEvent,
    content: &MessageContent,
    outcome: &DeleteMessageOutcome,
) -> SecurityIncident {
    let mut incident = message_incident(
        detection.module.key(),
        text(language, summary_key(detection.module)),
        message,
        outcome,
    );

    incident
        .evidence
        .push(finding_evidence(language, &detection.finding));
    if event == MessageEvent::Edited {
        incident.evidence.push(SecurityEvidence::Text {
            label: text(language, TextKey::ContentFilterEvidenceEvent).to_owned(),
            value: text(language, TextKey::ContentFilterEventEdited).to_owned(),
        });
    }
    if !content.content.is_empty() {
        incident.evidence.push(SecurityEvidence::Content {
            excerpt: excerpt(&content.content),
        });
    }
    incident.recommendation = Some(text(language, outcome.recommendation_key()).to_owned());

    incident
}

fn finding_evidence(language: Language, finding: &ContentFinding) -> SecurityEvidence {
    match finding {
        ContentFinding::Obfuscation { reason } => SecurityEvidence::Text {
            label: text(language, TextKey::ContentFilterEvidenceObfuscation).to_owned(),
            value: reason.clone(),
        },
        ContentFinding::MaliciousLink { pattern, reason } => SecurityEvidence::Domain {
            domain: pattern.clone(),
            signals: vec![reason.clone()],
            score: None,
        },
        ContentFinding::AdultLink { host } => SecurityEvidence::Domain {
            domain: host.clone(),
            signals: Vec::new(),
            score: None,
        },
        ContentFinding::Invite { invite } => SecurityEvidence::Domain {
            domain: invite.clone(),
            signals: Vec::new(),
            score: None,
        },
        ContentFinding::BroadcastMention => SecurityEvidence::Text {
            label: text(language, TextKey::ContentFilterEvidenceMention).to_owned(),
            value: "@everyone / @here".to_owned(),
        },
        ContentFinding::MassMention { count, threshold } => SecurityEvidence::Threshold {
            observed: *count as u64,
            threshold: *threshold as u64,
            window_seconds: None,
            unit: ThresholdUnit::Mentions,
        },
    }
}

const fn summary_key(module: ProtectionModule) -> TextKey {
    match module {
        ProtectionModule::InvisibleCharFilter => TextKey::ContentFilterSummaryInvisibleChar,
        ProtectionModule::MaliciousLink => TextKey::ContentFilterSummaryMaliciousLink,
        ProtectionModule::AdultLink => TextKey::ContentFilterSummaryAdultLink,
        ProtectionModule::AntiInvite => TextKey::ContentFilterSummaryInvite,
        ProtectionModule::AntiEveryone => TextKey::ContentFilterSummaryEveryone,
        ProtectionModule::AntiMassMention => TextKey::ContentFilterSummaryMassMention,
    }
}
