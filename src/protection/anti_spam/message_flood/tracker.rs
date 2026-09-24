// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::MessageFloodConfig;
use crate::protection::shared::{
    ActionBurstDetector, ActionBurstDetectorConfig, ActionBurstInput, GuildMessage,
    ProtectionDecision,
};

/// Clé d'action utilisée dans le détecteur de rafales partagé.
const MESSAGE_FLOOD_ACTION: &str = "message_flood";

/// Résultat de l'observation d'un message par l'anti-spam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageFloodDetection {
    pub decision: ProtectionDecision,
    /// Nombre de messages du membre dans la fenêtre, message courant inclus.
    pub observed: u32,
    pub threshold: u32,
    pub window_seconds: u32,
}

impl MessageFloodDetection {
    pub fn is_triggered(&self) -> bool {
        self.decision == ProtectionDecision::Block
    }
}

/// État temporel de l'anti-spam.
///
/// - clé `(guild_id, user_id)` ;
/// - déclenchement quand `count >= message_threshold` dans la fenêtre ;
/// - au plus 10 000 clés suivies, fenêtres expirées balayées périodiquement.
///
/// L'état vit en mémoire d'un seul processus : il est perdu au redémarrage et
/// n'est pas partagé entre plusieurs instances du bot.
#[derive(Debug, Default)]
pub struct MessageFloodTracker {
    detector: ActionBurstDetector,
}

impl MessageFloodTracker {
    pub fn new(config: ActionBurstDetectorConfig) -> Self {
        Self {
            detector: ActionBurstDetector::new(config),
        }
    }

    /// Enregistre le message et indique si la rafale est atteinte.
    ///
    /// Retourne `None` si la protection est désactivée : rien n'est alors
    /// enregistré, afin qu'une activation ultérieure parte d'un état vierge.
    pub fn observe(
        &mut self,
        config: &MessageFloodConfig,
        message: &GuildMessage,
    ) -> Option<MessageFloodDetection> {
        if !config.enabled {
            return None;
        }

        let result = self.detector.detect(ActionBurstInput::new(
            message.guild_id,
            message.author_id,
            MESSAGE_FLOOD_ACTION,
            config.message_threshold as usize,
            config.window(),
            message.timestamp,
        ));

        Some(MessageFloodDetection {
            decision: result.decision,
            observed: u32::try_from(result.count).unwrap_or(u32::MAX),
            threshold: u32::try_from(result.threshold).unwrap_or(u32::MAX),
            window_seconds: config.window_seconds,
        })
    }

    pub fn tracked_key_count(&self) -> usize {
        self.detector.tracked_key_count()
    }
}
