// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Filtres de contenu des messages : suppression et incident, sans sanction.
//!
//! Chaîne pure utilisée par le runtime : [`route_message`] (portée, ordre et
//! court-circuit) → suppression par le binaire → [`build_incident`].
//!
//! Ordre de la spécification V1 : caractères invisibles → liens malveillants
//! → liens adultes → invitations → `@everyone`/`@here` → mentions de masse.
//! Le premier module activé qui déclenche arrête la chaîne : un message ne
//! produit jamais deux suppressions ni deux incidents. Les filtres passent
//! avant l'anti-spam ; un message qu'ils retiennent n'est pas compté dans la
//! fenêtre anti-spam.

mod response;

use std::time::Duration;

use crate::protection::anti_spam::anti_everyone::detect_everyone_mention;
use crate::protection::anti_spam::anti_mass_mention::{
    DEFAULT_MASS_MENTION_THRESHOLD, detect_mass_mention,
};
use crate::protection::anti_spam::invisible_char_filter::detect_obfuscated_text;
use crate::protection::anti_spam::malicious_link::{MaliciousLinkContext, detect_malicious_link};
use crate::protection::automod::adult_link::detect_adult_link;
use crate::protection::automod::anti_invite::detect_invite_link;
use crate::protection::shared::{MessageScope, ModuleSet, ProtectionDecision, ProtectionModule};

pub use response::{
    EXCERPT_MAX_CHARS, RevisionCheck, build_incident, check_revision, excerpt,
    revision_fetch_failure,
};

/// Filtres de contenu, dans l'ordre d'évaluation.
pub const CONTENT_FILTERS: [ProtectionModule; 6] = [
    ProtectionModule::InvisibleCharFilter,
    ProtectionModule::MaliciousLink,
    ProtectionModule::AdultLink,
    ProtectionModule::AntiInvite,
    ProtectionModule::AntiEveryone,
    ProtectionModule::AntiMassMention,
];

/// Seuil de l'anti-mentions de masse (utilisateurs et rôles mentionnés),
/// celui de la V1 : non réglable dans cette version.
pub const MASS_MENTION_THRESHOLD: usize = DEFAULT_MASS_MENTION_THRESHOLD;

/// Version analysée d'un message : tout ce dont dépendent les filtres.
///
/// Sert aussi de révision : après une modification, le message n'est supprimé
/// que si sa version courante est encore celle-ci.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageContent {
    pub content: String,
    /// Indicateur Discord : le message mentionne réellement `@everyone` ou
    /// `@here` (auteur autorisé). Un texte « @everyone » sans ce droit ne
    /// notifie personne et n'est pas retenu.
    pub mentions_everyone: bool,
    /// Utilisateurs et rôles mentionnés (dédoublonnés par Discord).
    pub mention_count: usize,
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
///   sanction, comme les corrections de contenu de la V1), pas d'anti-spam.
/// - Sinon : filtres de contenu, puis anti-spam pour les créations seulement :
///   une modification n'est pas un nouveau message.
pub fn route_message(
    scope: MessageScope,
    event: MessageEvent,
    enabled: ModuleSet,
    message: &MessageContent,
    author: AuthorContext,
) -> MessageRoute {
    if scope == MessageScope::IgnoredChannel {
        return MessageRoute::Skip;
    }

    if let Some(detection) = detect_content(enabled, message, author) {
        return MessageRoute::Filter(detection);
    }

    match (scope, event) {
        (MessageScope::Enforce, MessageEvent::Created) => MessageRoute::AntiSpam,
        _ => MessageRoute::Skip,
    }
}

/// Évalue les filtres activés dans l'ordre et s'arrête au premier qui
/// déclenche.
pub fn detect_content(
    enabled: ModuleSet,
    message: &MessageContent,
    author: AuthorContext,
) -> Option<ContentDetection> {
    CONTENT_FILTERS
        .into_iter()
        .filter(|module| enabled.contains(*module))
        .find_map(|module| {
            detect_module(module, message, author)
                .map(|finding| ContentDetection { module, finding })
        })
}

fn detect_module(
    module: ProtectionModule,
    message: &MessageContent,
    author: AuthorContext,
) -> Option<ContentFinding> {
    let content = message.content.as_str();

    match module {
        ProtectionModule::InvisibleCharFilter => {
            let result = detect_obfuscated_text(content);
            result.triggered.then_some(ContentFinding::Obfuscation {
                reason: result.reason,
            })
        }
        ProtectionModule::MaliciousLink => {
            let context = MaliciousLinkContext {
                now: author.now,
                account_created_at: author.account_created_at,
                member_joined_at: author.member_joined_at,
                ..MaliciousLinkContext::default()
            };
            let result = detect_malicious_link(content, context);
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
