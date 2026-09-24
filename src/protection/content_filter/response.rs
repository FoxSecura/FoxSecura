// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Vérification de révision, réponse graduée et incident des filtres de
//! contenu, sans effet Discord.

use std::time::Duration;

use super::{ContentDetection, ContentFinding, MessageContent, MessageEvent};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, ActionStatus, FailureCode, LogSeverity, SecurityActionOutcome, SecurityEvidence,
    SecurityIncident, ThresholdUnit,
};
use crate::protection::anti_spam::anti_scam::ScamConfidence;
use crate::protection::shared::{
    DeleteMessageOutcome, GuildMessage, MessageScope, ProtectionModule, SanctionKind,
    SanctionOutcome, audit_reason, exempt_member_action, message_incident,
};

/// Timeout appliqué pour une arnaque de confiance haute.
pub const ANTI_SCAM_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Purge des messages lors d'un ban pour une arnaque de confiance critique.
pub const ANTI_SCAM_BAN_PURGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Nombre maximal de signaux d'arnaque cités dans l'incident.
pub const MAX_SCAM_SIGNALS: usize = 6;

/// Nom du module dans les raisons d'audit log (`FoxSecura Anti-Scam: …`).
pub const ANTI_SCAM_AUDIT_LABEL: &str = "Anti-Scam";

/// Suite donnée à une détection, après la suppression du message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowUp {
    /// Suppression seule (tous les filtres sauf l'anti-arnaque).
    None,
    /// Arnaque de confiance moyenne : l'équipe tranche.
    StaffReview,
    /// Arnaque de confiance haute ou critique.
    Sanction(SanctionKind),
    /// Sanction prévue, mais l'auteur est sur la liste blanche : jamais
    /// appliquée.
    ExemptMember(SanctionKind),
}

/// Choisit la suite d'une détection selon le module, la confiance et la
/// portée du message.
///
/// Anti-arnaque : moyenne → revue ; haute → timeout d'une heure ; critique →
/// ban avec purge de 7 jours. Un auteur exempté n'est jamais sanctionné.
pub fn plan_follow_up(detection: &ContentDetection, scope: MessageScope) -> FollowUp {
    let ContentFinding::Scam { confidence, .. } = &detection.finding else {
        return FollowUp::None;
    };

    let sanction = match confidence {
        ScamConfidence::Critical => SanctionKind::Ban {
            purge: ANTI_SCAM_BAN_PURGE,
        },
        ScamConfidence::High => SanctionKind::Timeout {
            duration: ANTI_SCAM_TIMEOUT,
        },
        ScamConfidence::Medium => return FollowUp::StaffReview,
        ScamConfidence::None | ScamConfidence::Low => return FollowUp::None,
    };

    match scope {
        MessageScope::Enforce => FollowUp::Sanction(sanction),
        MessageScope::ExemptAuthor | MessageScope::IgnoredChannel => {
            FollowUp::ExemptMember(sanction)
        }
    }
}

/// Raison d'audit log d'une sanction anti-arnaque. Ne contient que des
/// valeurs produites par FoxSecura (confiance, score), jamais le message.
pub fn anti_scam_audit_reason(detection: &ContentDetection) -> String {
    let detail = match &detection.finding {
        ContentFinding::Scam {
            confidence, score, ..
        } => format!("{} confidence scam (score {score})", confidence.as_str()),
        _ => "scam".to_owned(),
    };
    audit_reason(ANTI_SCAM_AUDIT_LABEL, &detail)
}

/// Résultat de la suite donnée, pour l'incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowUpOutcome {
    None,
    StaffReview,
    Sanction {
        kind: SanctionKind,
        outcome: SanctionOutcome,
    },
    ExemptMember(SanctionKind),
}

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
/// fois son message avant que la suppression ne parte. Seuls les champs
/// présents dans l'événement analysé sont comparés
/// ([`MessageContent::same_revision`]).
pub fn check_revision(
    analyzed: &MessageContent,
    current: Option<&MessageContent>,
) -> RevisionCheck {
    match current {
        None => RevisionCheck::Deleted,
        Some(current) if analyzed.same_revision(current) => RevisionCheck::Current,
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
        .extend(finding_evidence(language, &detection.finding));
    if event == MessageEvent::Edited {
        incident.evidence.push(SecurityEvidence::Text {
            label: text(language, TextKey::ContentFilterEvidenceEvent).to_owned(),
            value: text(language, TextKey::ContentFilterEventEdited).to_owned(),
        });
    }
    // L'extrait d'une arnaque contiendrait l'URL complète : jamais conservé.
    if detection.module != ProtectionModule::AntiScam && !content.content.is_empty() {
        incident.evidence.push(SecurityEvidence::Content {
            excerpt: excerpt(&content.content),
        });
    }
    incident.recommendation = Some(text(language, outcome.recommendation_key()).to_owned());

    incident
}

/// Complète l'incident avec la suite donnée : action, sévérité et
/// recommandation.
///
/// - Sévérité critique pour une arnaque de confiance haute ou critique, même
///   si tout a réussi : un compte a été sanctionné (ou aurait dû l'être).
/// - Recommandation, par priorité : message resté visible → permissions de
///   suppression ; auteur exempté → revoir la liste blanche ; sanction non
///   appliquée → vérifier la hiérarchie ; ban appliqué → vérifier le faux
///   positif.
pub fn record_follow_up(
    incident: &mut SecurityIncident,
    language: Language,
    deletion: &DeleteMessageOutcome,
    follow_up: &FollowUpOutcome,
) {
    let recommendation = match follow_up {
        FollowUpOutcome::None => return,
        FollowUpOutcome::StaffReview => {
            incident.actions.push(SecurityActionOutcome {
                action: ActionCode::RequestStaffReview,
                status: ActionStatus::Success,
                details: None,
                failure_code: None,
            });
            TextKey::AntiScamRecommendationReview
        }
        FollowUpOutcome::Sanction { kind, outcome } => {
            incident.severity = LogSeverity::Critical;
            incident.actions.push(outcome.action_outcome(*kind));
            match (outcome.is_applied(), kind) {
                (false, _) => TextKey::AntiScamRecommendationCheckHierarchy,
                // `plan_follow_up` n'expulse jamais : une expulsion, qui retire
                // aussi le membre, suivrait le ban.
                (true, SanctionKind::Ban { .. } | SanctionKind::Kick) => {
                    TextKey::AntiScamRecommendationBanFalsePositive
                }
                (true, SanctionKind::Timeout { .. }) => {
                    TextKey::AntiScamRecommendationTimeoutFalsePositive
                }
            }
        }
        FollowUpOutcome::ExemptMember(_) => {
            incident.severity = LogSeverity::Critical;
            incident.actions.push(exempt_member_action());
            TextKey::RecommendationReviewWhitelist
        }
    };

    let key = if matches!(deletion, DeleteMessageOutcome::Deleted) {
        recommendation
    } else {
        deletion.recommendation_key()
    };
    incident.recommendation = Some(text(language, key).to_owned());
}

fn finding_evidence(language: Language, finding: &ContentFinding) -> Vec<SecurityEvidence> {
    let evidence = match finding {
        ContentFinding::DangerousAttachment {
            file_name,
            extension,
        } => {
            return vec![
                SecurityEvidence::Text {
                    label: text(language, TextKey::ContentFilterEvidenceFile).to_owned(),
                    value: file_name.clone(),
                },
                SecurityEvidence::Text {
                    label: text(language, TextKey::ContentFilterEvidenceExtension).to_owned(),
                    value: extension.clone(),
                },
            ];
        }
        ContentFinding::Scam {
            host,
            score,
            signals,
            confidence,
        } => {
            let mut evidence = Vec::with_capacity(4);
            if let Some(host) = host {
                evidence.push(SecurityEvidence::Domain {
                    domain: host.clone(),
                    signals: Vec::new(),
                    score: None,
                });
            }
            evidence.extend([
                SecurityEvidence::Text {
                    label: text(language, TextKey::AntiScamEvidenceSignals).to_owned(),
                    value: signals
                        .iter()
                        .take(MAX_SCAM_SIGNALS)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", "),
                },
                SecurityEvidence::Text {
                    label: text(language, TextKey::AntiScamEvidenceScore).to_owned(),
                    value: score.to_string(),
                },
                SecurityEvidence::Text {
                    label: text(language, TextKey::AntiScamEvidenceConfidence).to_owned(),
                    value: confidence.as_str().to_owned(),
                },
            ]);
            return evidence;
        }
        ContentFinding::BadWord { word } => SecurityEvidence::Text {
            label: text(language, TextKey::ContentFilterEvidenceWord).to_owned(),
            value: word.clone(),
        },
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
    };
    vec![evidence]
}

const fn summary_key(module: ProtectionModule) -> TextKey {
    match module {
        ProtectionModule::InvisibleCharFilter => TextKey::ContentFilterSummaryInvisibleChar,
        ProtectionModule::MaliciousLink => TextKey::ContentFilterSummaryMaliciousLink,
        ProtectionModule::AdultLink => TextKey::ContentFilterSummaryAdultLink,
        ProtectionModule::AntiInvite => TextKey::ContentFilterSummaryInvite,
        ProtectionModule::AntiEveryone => TextKey::ContentFilterSummaryEveryone,
        ProtectionModule::AntiMassMention => TextKey::ContentFilterSummaryMassMention,
        ProtectionModule::AttachmentFilter => TextKey::ContentFilterSummaryAttachment,
        ProtectionModule::AntiScam => TextKey::ContentFilterSummaryScam,
        ProtectionModule::BadWords => TextKey::ContentFilterSummaryBadWord,
        ProtectionModule::AntiBot => TextKey::AntiBotSummaryUnauthorized,
        ProtectionModule::AntiNewAccount => TextKey::NewAccountSummary,
    }
}
