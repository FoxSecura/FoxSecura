// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Étape « mentions » de la chaîne des messages (V1) : anti-ping du
//! propriétaire, puis anti-spam de mentions.
//!
//! Contrairement aux filtres de contenu, ces deux modules comptent des
//! rafales en mémoire : ils ne s'appliquent qu'aux **créations** (une
//! modification n'est pas un nouveau ping) et jamais à un auteur exempté (ce
//! ne sont pas des corrections de contenu). Seuils fixes de la V1, non
//! réglables : seul l'interrupteur du module est exposé dans `/config`.
//!
//! Les mentions sont celles que Discord a réellement résolues (listes des
//! mentions d'utilisateurs et de rôles), jamais le texte du message.
//!
//! État mono-instance, borné par les détecteurs de rafales du socle.

use std::time::Duration;

use crate::protection::anti_spam::anti_ping_owner::{AntiPingOwnerDetector, AntiPingOwnerInput};
use crate::protection::shared::{ModuleSet, ProtectionDecision, ProtectionModule};

use super::{ContentDetection, ContentFinding};

/// Anti-ping du propriétaire : 3 messages qui le mentionnent…
pub const OWNER_PING_THRESHOLD: usize = 3;
/// … en 30 secondes, par auteur.
pub const OWNER_PING_WINDOW: Duration = Duration::from_secs(30);

/// Mentions d'un message créé, telles que résolues par Discord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MentionFacts<'a> {
    pub guild_id: u64,
    pub author_id: u64,
    /// Horodatage du message.
    pub timestamp: Duration,
    /// Propriétaire du serveur ; `None` s'il n'est pas en cache : l'anti-ping
    /// du propriétaire ne déclenche alors jamais.
    pub owner_id: Option<u64>,
    /// Utilisateurs mentionnés.
    pub users: &'a [u64],
    /// Rôles mentionnés.
    pub roles: &'a [u64],
}

/// Rafales des deux modules, par guilde et par auteur.
#[derive(Debug, Default)]
pub struct MentionBursts {
    ping_owner: AntiPingOwnerDetector,
}

impl MentionBursts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Évalue les modules activés dans l'ordre de la V1 et s'arrête au premier
    /// qui déclenche. Un module désactivé ne compte rien.
    pub fn detect(
        &mut self,
        enabled: ModuleSet,
        facts: &MentionFacts<'_>,
    ) -> Option<ContentDetection> {
        if enabled.contains(ProtectionModule::AntiPingOwner)
            && let Some(finding) = self.detect_owner_ping(facts)
        {
            return Some(ContentDetection {
                module: ProtectionModule::AntiPingOwner,
                finding,
            });
        }
        None
    }

    fn detect_owner_ping(&mut self, facts: &MentionFacts<'_>) -> Option<ContentFinding> {
        let mentions_owner = facts
            .owner_id
            .is_some_and(|owner| facts.users.contains(&owner));
        let result = self.ping_owner.detect(AntiPingOwnerInput {
            enabled: true,
            author_is_bot: false,
            author_is_owner: facts.owner_id == Some(facts.author_id),
            mentions_owner,
            guild_id: facts.guild_id,
            author_id: facts.author_id,
            timestamp: facts.timestamp,
            threshold: Some(OWNER_PING_THRESHOLD),
            window: Some(OWNER_PING_WINDOW),
        });
        (result.decision == ProtectionDecision::Block).then_some(ContentFinding::OwnerPing {
            count: result.ping_count,
            threshold: result.threshold,
            window: result.window,
        })
    }

    /// Clés suivies (bornées), pour les tests et la supervision.
    pub fn tracked_key_count(&self) -> usize {
        self.ping_owner.tracked_key_count()
    }
}
