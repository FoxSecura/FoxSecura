// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Filtres de contenu des messages : suppression, incident et, pour
//! l'anti-arnaque seulement, une sanction graduée.
//!
//! Chaîne pure utilisée par le runtime : [`route_message`] (portée, ordre et
//! court-circuit) → suppression par le binaire → [`plan_follow_up`]
//! (sanction ou revue) → [`build_incident`] et [`record_follow_up`].
//!
//! Ordre de la spécification V1 : pièces jointes → caractères invisibles →
//! anti-arnaque → liens malveillants → liens adultes → invitations →
//! `@everyone`/`@here` → mentions de masse → mots interdits. Le premier module
//! activé qui déclenche arrête la chaîne : un message ne produit jamais deux
//! suppressions ni deux incidents. L'anti-arnaque passe avant les liens
//! malveillants : c'est lui qui gradue la réponse (un lien malveillant est
//! l'un de ses signaux). Les filtres passent avant l'anti-spam ; un message
//! qu'ils retiennent n'est pas compté dans la fenêtre anti-spam.

mod response;

use std::time::Duration;

use crate::protection::anti_spam::anti_everyone::detect_everyone_mention;
use crate::protection::anti_spam::anti_mass_mention::{
    DEFAULT_MASS_MENTION_THRESHOLD, detect_mass_mention,
};
use crate::protection::anti_spam::anti_scam::{
    AntiScamContext, AntiScamObservation, ScamConfidence, detect_scam_message,
};
use crate::protection::anti_spam::attachment_filter::detect_dangerous_attachment;
use crate::protection::anti_spam::invisible_char_filter::detect_obfuscated_text;
use crate::protection::anti_spam::malicious_link::{MaliciousLinkContext, detect_malicious_link};
use crate::protection::automod::adult_link::detect_adult_link;
use crate::protection::automod::anti_invite::detect_invite_link;
use crate::protection::automod::bad_words::BadWordsMatcher;
use crate::protection::shared::{
    MessageScope, ModuleSet, ProtectionDecision, ProtectionModule, extract_url_signals,
};

pub use response::{
    ANTI_SCAM_AUDIT_LABEL, ANTI_SCAM_BAN_PURGE, ANTI_SCAM_TIMEOUT, EXCERPT_MAX_CHARS, FollowUp,
    FollowUpOutcome, MAX_SCAM_SIGNALS, RevisionCheck, anti_scam_audit_reason, build_incident,
    check_revision, excerpt, plan_follow_up, record_follow_up, revision_fetch_failure,
};

/// Filtres de contenu, dans l'ordre d'évaluation.
pub const CONTENT_FILTERS: [ProtectionModule; 9] = [
    ProtectionModule::AttachmentFilter,
    ProtectionModule::InvisibleCharFilter,
    ProtectionModule::AntiScam,
    ProtectionModule::MaliciousLink,
    ProtectionModule::AdultLink,
    ProtectionModule::AntiInvite,
    ProtectionModule::AntiEveryone,
    ProtectionModule::AntiMassMention,
    ProtectionModule::BadWords,
];

/// Seuil de l'anti-mentions de masse (utilisateurs et rôles mentionnés),
/// celui de la V1 : non réglable dans cette version.
pub const MASS_MENTION_THRESHOLD: usize = DEFAULT_MASS_MENTION_THRESHOLD;

/// Version analysée d'un message : tout ce dont dépendent les filtres.
///
/// Sert aussi de révision : après une modification, le message n'est supprimé
/// que si sa version courante est encore celle-ci, sur les champs réellement
/// fournis par l'événement analysé (voir [`MissingFields`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageContent {
    pub content: String,
    /// Indicateur Discord : le message mentionne réellement `@everyone` ou
    /// `@here` (auteur autorisé). Un texte « @everyone » sans ce droit ne
    /// notifie personne et n'est pas retenu.
    pub mentions_everyone: bool,
    /// Utilisateurs et rôles mentionnés (dédoublonnés par Discord).
    pub mention_count: usize,
    /// Noms des pièces jointes, tels que fournis par Discord.
    pub attachments: Vec<String>,
    /// Champs absents de l'événement analysé (modification partielle). Vide
    /// pour un message complet.
    pub missing: MissingFields,
}

/// Champs qu'une modification partielle (`MESSAGE_UPDATE`) peut omettre.
///
/// Un champ absent vaut sa valeur par défaut pour les filtres (aucune mention,
/// aucune pièce jointe : les filtres qui en dépendent ne déclenchent pas), et
/// n'est pas comparé lors de la vérification de révision : sinon la version
/// relue, complète, différerait toujours et un lien ajouté par modification
/// ne serait jamais supprimé.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MissingFields {
    pub mentions_everyone: bool,
    /// Mentions d'utilisateurs ou de rôles (l'une des deux listes manque).
    pub mentions: bool,
    pub attachments: bool,
}

/// Champs d'une modification tels que reçus : `None` = absent de l'événement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageUpdate {
    pub content: String,
    pub mentions_everyone: Option<bool>,
    pub user_mentions: Option<usize>,
    pub role_mentions: Option<usize>,
    pub attachments: Option<Vec<String>>,
}

impl MessageContent {
    /// Version analysée d'une modification, en notant les champs absents.
    pub fn from_update(update: MessageUpdate) -> Self {
        let mentions = update.user_mentions.zip(update.role_mentions);
        Self {
            content: update.content,
            mentions_everyone: update.mentions_everyone.unwrap_or(false),
            mention_count: mentions.map_or(0, |(users, roles)| users + roles),
            missing: MissingFields {
                mentions_everyone: update.mentions_everyone.is_none(),
                mentions: mentions.is_none(),
                attachments: update.attachments.is_none(),
            },
            attachments: update.attachments.unwrap_or_default(),
        }
    }

    /// Même révision que `current` sur les champs présents ici.
    pub fn same_revision(&self, current: &Self) -> bool {
        self.content == current.content
            && (self.missing.mentions_everyone
                || self.mentions_everyone == current.mentions_everyone)
            && (self.missing.mentions || self.mention_count == current.mention_count)
            && (self.missing.attachments || self.attachments == current.attachments)
    }
}

/// Contexte temporel de l'auteur, pour les liens risqués des comptes récents.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthorContext {
    /// Instant de l'analyse (création ou modification du message).
    pub now: Option<Duration>,
    pub account_created_at: Option<Duration>,
    pub member_joined_at: Option<Duration>,
}

/// Création ou modification d'un message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageEvent {
    Created,
    Edited,
}

/// Preuve propre à chaque module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentFinding {
    /// Explication technique du détecteur (point de code, type d'obfuscation).
    Obfuscation {
        reason: String,
    },
    MaliciousLink {
        pattern: String,
        reason: String,
    },
    AdultLink {
        host: String,
    },
    Invite {
        invite: String,
    },
    BroadcastMention,
    MassMention {
        count: usize,
        threshold: usize,
    },
    DangerousAttachment {
        file_name: String,
        extension: String,
    },
    /// Arnaque probable. Jamais d'URL complète : seulement l'hôte, sans
    /// chemin, requête ni identifiants.
    Scam {
        host: Option<String>,
        score: u8,
        signals: Vec<&'static str>,
        confidence: ScamConfidence,
    },
    BadWord {
        word: String,
    },
}

/// Premier filtre qui a déclenché.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDetection {
    pub module: ProtectionModule,
    pub finding: ContentFinding,
}

/// Décision du pipeline pour un message retenu par les gardes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageRoute {
    /// Aucune protection ne s'applique.
    Skip,
    /// Un filtre de contenu a déclenché : suppression et incident ; le message
    /// ne passe pas par l'anti-spam.
    Filter(ContentDetection),
    /// Aucun filtre n'a déclenché : le message est confié à l'anti-spam (qui
    /// vérifie lui-même s'il est activé).
    AntiSpam,
}

/// Choisit le traitement d'un message selon sa portée.
///
/// - Salon ignoré : rien.
/// - Auteur exempté : filtres de contenu seulement (suppression, jamais de
///   sanction, comme les corrections de contenu de la V1, mots interdits
///   compris), pas d'anti-spam.
/// - Sinon : filtres de contenu, puis anti-spam pour les créations seulement :
///   une modification n'est pas un nouveau message.
pub fn route_message(
    scope: MessageScope,
    event: MessageEvent,
    enabled: ModuleSet,
    message: &MessageContent,
    author: AuthorContext,
    bad_words: Option<&BadWordsMatcher>,
) -> MessageRoute {
    if scope == MessageScope::IgnoredChannel {
        return MessageRoute::Skip;
    }

    if let Some(detection) = detect_content(enabled, message, author, bad_words) {
        return MessageRoute::Filter(detection);
    }

    match (scope, event) {
        (MessageScope::Enforce, MessageEvent::Created) => MessageRoute::AntiSpam,
        _ => MessageRoute::Skip,
    }
}

/// Évalue les filtres activés dans l'ordre et s'arrête au premier qui
/// déclenche.
///
/// `bad_words` : liste compilée de la guilde (intégrée et personnalisée) ;
/// `None` si elle n'est pas chargée, les mots interdits ne déclenchent alors
/// jamais.
pub fn detect_content(
    enabled: ModuleSet,
    message: &MessageContent,
    author: AuthorContext,
    bad_words: Option<&BadWordsMatcher>,
) -> Option<ContentDetection> {
    CONTENT_FILTERS
        .into_iter()
        .filter(|module| enabled.contains(*module))
        .find_map(|module| {
            detect_module(module, message, author, bad_words)
                .map(|finding| ContentDetection { module, finding })
        })
}

fn detect_module(
    module: ProtectionModule,
    message: &MessageContent,
    author: AuthorContext,
    bad_words: Option<&BadWordsMatcher>,
) -> Option<ContentFinding> {
    let content = message.content.as_str();

    match module {
        ProtectionModule::AttachmentFilter => {
            let names = attachment_names(message);
            let result = detect_dangerous_attachment(&names);
            result
                .matched_file
                .zip(result.matched_extension)
                .filter(|_| result.triggered)
                .map(
                    |(file_name, extension)| ContentFinding::DangerousAttachment {
                        file_name,
                        extension,
                    },
                )
        }
        ProtectionModule::AntiScam => {
            let names = attachment_names(message);
            let link_context = link_context(author);
            let result = detect_scam_message(
                AntiScamObservation {
                    content,
                    attachment_names: &names,
                },
                AntiScamContext { link_context },
            );
            (result.decision == ProtectionDecision::Block).then(|| ContentFinding::Scam {
                host: scam_host(content, link_context),
                score: result.score,
                signals: result.signals.into_iter().take(MAX_SCAM_SIGNALS).collect(),
                confidence: result.confidence,
            })
        }
        ProtectionModule::BadWords => bad_words
            .and_then(|matcher| matcher.detect(content).matched_word)
            .map(|word| ContentFinding::BadWord { word }),
        ProtectionModule::InvisibleCharFilter => {
            let result = detect_obfuscated_text(content);
            result.triggered.then_some(ContentFinding::Obfuscation {
                reason: result.reason,
            })
        }
        ProtectionModule::MaliciousLink => {
            let result = detect_malicious_link(content, link_context(author));
            result
                .matched_pattern
                .filter(|_| result.triggered)
                .map(|pattern| ContentFinding::MaliciousLink {
                    pattern,
                    reason: result.reason.to_owned(),
                })
        }
        ProtectionModule::AdultLink => {
            let result = detect_adult_link(content);
            (result.decision == ProtectionDecision::Block).then(|| ContentFinding::AdultLink {
                host: result.matched_domain.unwrap_or_default(),
            })
        }
        ProtectionModule::AntiInvite => {
            let result = detect_invite_link(content);
            (result.decision == ProtectionDecision::Block).then(|| ContentFinding::Invite {
                invite: result.matched_invite.unwrap_or_default(),
            })
        }
        ProtectionModule::AntiEveryone => {
            detect_everyone_mention(content, Some(message.mentions_everyone))
                .triggered
                .then_some(ContentFinding::BroadcastMention)
        }
        ProtectionModule::AntiMassMention => {
            let result = detect_mass_mention(message.mention_count, Some(MASS_MENTION_THRESHOLD));
            result.triggered.then_some(ContentFinding::MassMention {
                count: result.mention_count,
                threshold: result.threshold,
            })
        }
    }
}

fn attachment_names(message: &MessageContent) -> Vec<&str> {
    message.attachments.iter().map(String::as_str).collect()
}

/// Contexte « compte récent » : âge du compte et date d'arrivée.
fn link_context(author: AuthorContext) -> MaliciousLinkContext {
    MaliciousLinkContext {
        now: author.now,
        account_created_at: author.account_created_at,
        member_joined_at: author.member_joined_at,
        ..MaliciousLinkContext::default()
    }
}

/// Hôte à citer comme preuve : celui du lien malveillant s'il y en a un,
/// sinon le premier lien du message. Seul le nom d'hôte est conservé (ni
/// chemin, ni requête, ni identifiants).
fn scam_host(content: &str, context: MaliciousLinkContext) -> Option<String> {
    let signals = extract_url_signals(content);
    let pattern = detect_malicious_link(content, context).matched_pattern;

    pattern
        .and_then(|pattern| signals.iter().find(|signal| signal.searchable() == pattern))
        .or_else(|| signals.first())
        .map(|signal| signal.hostname.clone())
}
