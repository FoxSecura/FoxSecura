// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Rafales par auteur : fenêtre glissante par `(guilde, auteur, clé
//! d'action)`, sur le détecteur partagé [`ActionBurstDetector`].
//!
//! Déclenchement quand `nombre >= seuil`. Après un déclenchement, la clé est
//! remise à zéro et mise en **pause** [`BURST_COOLDOWN`] : les actions
//! suivantes de la même rafale ne produisent pas un incident chacune (V1,
//! expulsions et exclusions temporaires). Une rafale qui continue après la
//! pause recommence à compter et peut déclencher de nouveau.
//!
//! Les clés sont isolées : un auteur ne cumule jamais avec un autre, et les
//! bans ne cumulent pas avec les expulsions. Les emojis et les stickers
//! partagent une seule clé.

use std::collections::HashMap;
use std::time::Duration;

use crate::protection::shared::{ActionBurstDetector, ActionBurstInput, ProtectionDecision};

use super::NukeActionSpec;
use super::audit::NukeAction;
use super::member_actions::{anti_mass_ban, anti_mass_kick, anti_mass_timeout, anti_mass_unban};
use super::resource_actions::{
    anti_emoji_sticker_nuke, anti_mass_channel_create, anti_mass_role_create, anti_mass_role_grant,
};

/// Pause après un déclenchement, pour la même clé.
pub const BURST_COOLDOWN: Duration = Duration::from_secs(30);

/// Pauses retenues au plus ; au-delà, les pauses expirées sont oubliées.
const MAX_TRACKED_COOLDOWNS: usize = 10_000;

impl NukeAction {
    /// Clé de comptage, seuil par défaut et fenêtre (V1).
    pub const fn spec(self) -> NukeActionSpec {
        match self {
            Self::Ban => anti_mass_ban::SPEC,
            Self::Kick => anti_mass_kick::SPEC,
            Self::Timeout => anti_mass_timeout::SPEC,
            Self::Unban => anti_mass_unban::SPEC,
            Self::ChannelCreate => anti_mass_channel_create::SPEC,
            Self::RoleCreate => anti_mass_role_create::SPEC,
            Self::EmojiSticker => anti_emoji_sticker_nuke::SPEC,
            Self::RoleGrant => anti_mass_role_grant::SPEC,
        }
    }

    pub const fn window(self) -> Duration {
        self.spec().window
    }
}

/// Rafale détectée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NukeBurst {
    pub action: NukeAction,
    pub count: usize,
    pub threshold: usize,
    pub window: Duration,
}

/// Résultat d'une action comptée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurstVerdict {
    /// Sous le seuil.
    Counted { count: usize, threshold: usize },
    /// Seuil atteint : la clé passe en pause.
    Triggered(NukeBurst),
    /// Clé en pause après un déclenchement : rien n'est compté.
    CoolingDown,
}

type CooldownKey = (u64, u64, NukeAction);

/// Comptage des actions par auteur, avec pause après un déclenchement.
#[derive(Debug, Default)]
pub struct NukeBurstTracker {
    detector: ActionBurstDetector,
    cooldowns: HashMap<CooldownKey, Duration>,
}

impl NukeBurstTracker {
    pub fn new(detector: ActionBurstDetector) -> Self {
        Self {
            detector,
            cooldowns: HashMap::new(),
        }
    }

    /// Compte une action de `author_id` à l'instant `now`.
    ///
    /// `threshold` : seuil réglé de la guilde (au moins 1).
    pub fn record(
        &mut self,
        guild_id: u64,
        author_id: u64,
        action: NukeAction,
        threshold: usize,
        now: Duration,
    ) -> BurstVerdict {
        let key = (guild_id, author_id, action);
        if self.cooldowns.get(&key).is_some_and(|until| now < *until) {
            return BurstVerdict::CoolingDown;
        }
        self.cooldowns.remove(&key);

        let spec = action.spec();
        let result = self.detector.detect(ActionBurstInput::new(
            guild_id,
            author_id,
            spec.action,
            threshold.max(1),
            spec.window,
            now,
        ));
        if result.decision != ProtectionDecision::Block {
            return BurstVerdict::Counted {
                count: result.count,
                threshold: result.threshold,
            };
        }

        self.detector.forget(guild_id, author_id, spec.action);
        if self.cooldowns.len() >= MAX_TRACKED_COOLDOWNS {
            self.cooldowns.retain(|_, until| now < *until);
        }
        self.cooldowns
            .insert(key, now.saturating_add(BURST_COOLDOWN));
        BurstVerdict::Triggered(NukeBurst {
            action,
            count: result.count,
            threshold: result.threshold,
            window: spec.window,
        })
    }

    pub fn reset(&mut self) {
        self.detector.reset();
        self.cooldowns.clear();
    }
}
