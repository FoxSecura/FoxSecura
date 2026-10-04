// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Mode panique (V1) : corrélation, par guilde, des signaux des incidents
//! critiques de l'anti-nuke.
//!
//! - Fenêtre de [`DEFAULT_CORRELATION_WINDOW`] (30 s) par guilde.
//! - On compte les **types de modules distincts**, pas le nombre brut de
//!   signaux : c'est ce qui sépare une prise de contrôle coordonnée (bans,
//!   créations de rôles, attributions…) d'un seul module bruyant.
//! - Seuil par défaut 3, réglable de 2 à 10 (migration 9).
//! - Au seuil, si aucun verrouillage n'est déjà actif : verrouillage
//!   temporaire de 15 minutes avec un mode lent de 30 s, puis remise à zéro
//!   des signaux de la guilde. Un verrouillage déjà actif (anti-raid, panique
//!   précédente) n'est ni relancé ni prolongé, et les signaux sont gardés.
//!
//! L'état vit dans le processus (mono-instance) : il est perdu au
//! redémarrage et n'est pas partagé entre plusieurs instances.

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    time::Duration,
};

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityEvidence,
    SecurityIncident, ThresholdUnit,
};
use crate::protection::lockdown::{
    LockdownOutcome, LockdownStart, PANIC_LOCKDOWN_DURATION, PANIC_LOCKDOWN_SLOWMODE_SECONDS,
};
use crate::protection::shared::ProtectionModule;

use super::settings::DEFAULT_PANIC_THRESHOLD;

pub const DEFAULT_SIGNAL_THRESHOLD: usize = DEFAULT_PANIC_THRESHOLD as usize;
pub const DEFAULT_CORRELATION_WINDOW: Duration = Duration::from_secs(30);
pub const DEFAULT_LOCKDOWN_DURATION: Duration = PANIC_LOCKDOWN_DURATION;
pub const DEFAULT_LOCKDOWN_SLOWMODE_SECONDS: u16 = PANIC_LOCKDOWN_SLOWMODE_SECONDS;

/// Guildes suivies au plus ; au-delà, celles sans signal récent sont
/// oubliées.
const MAX_TRACKED_GUILDS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanicModeConfig {
    /// Seuil par défaut, quand l'appel n'en précise pas.
    pub signal_threshold: usize,
    pub correlation_window: Duration,
}

impl Default for PanicModeConfig {
    fn default() -> Self {
        Self {
            signal_threshold: DEFAULT_SIGNAL_THRESHOLD,
            correlation_window: DEFAULT_CORRELATION_WINDOW,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PanicSignal {
    kind: String,
    timestamp: Duration,
}

/// Suite donnée à un signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicDecision {
    /// Sous le seuil.
    Below,
    /// Seuil atteint : verrouiller. Les signaux de la guilde sont remis à
    /// zéro.
    Trigger,
    /// Seuil atteint, mais un verrouillage est déjà actif : rien n'est
    /// relancé, les signaux sont gardés.
    LockdownActive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicModeResult {
    pub decision: PanicDecision,
    pub distinct_types: usize,
    pub threshold: usize,
    /// Types distincts dans la fenêtre, triés.
    pub kinds: Vec<String>,
}

impl PanicModeResult {
    pub fn triggered(&self) -> bool {
        self.decision == PanicDecision::Trigger
    }
}

#[derive(Debug, Default)]
pub struct PanicModeDetector {
    config: PanicModeConfig,
    signals_by_guild: HashMap<u64, VecDeque<PanicSignal>>,
}

impl PanicModeDetector {
    pub fn new(mut config: PanicModeConfig) -> Self {
        config.signal_threshold = config.signal_threshold.max(1);
        config.correlation_window = config.correlation_window.max(Duration::from_millis(1));

        Self {
            config,
            signals_by_guild: HashMap::new(),
        }
    }

    /// Enregistre un signal avec le seuil par défaut, sans verrouillage
    /// actif.
    pub fn record(
        &mut self,
        guild_id: u64,
        kind: impl Into<String>,
        timestamp: Duration,
    ) -> PanicModeResult {
        let threshold = self.config.signal_threshold;
        self.record_with(guild_id, kind, timestamp, threshold, false)
    }

    /// Enregistre le signal d'un incident critique de l'anti-nuke.
    ///
    /// `threshold` : seuil réglé de la guilde (au moins 1).
    /// `lockdown_active` : un verrouillage existe déjà pour la guilde.
    pub fn record_with(
        &mut self,
        guild_id: u64,
        kind: impl Into<String>,
        timestamp: Duration,
        threshold: usize,
        lockdown_active: bool,
    ) -> PanicModeResult {
        let threshold = threshold.max(1);
        let window = self.config.correlation_window;
        if !self.signals_by_guild.contains_key(&guild_id)
            && self.signals_by_guild.len() >= MAX_TRACKED_GUILDS
        {
            self.signals_by_guild.retain(|_, signals| {
                signals
                    .back()
                    .is_some_and(|signal| timestamp.saturating_sub(signal.timestamp) <= window)
            });
        }

        let signals = self.signals_by_guild.entry(guild_id).or_default();
        signals.retain(|signal| timestamp.saturating_sub(signal.timestamp) <= window);
        signals.push_back(PanicSignal {
            kind: kind.into(),
            timestamp,
        });

        let kinds: Vec<String> = signals
            .iter()
            .map(|signal| signal.kind.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let distinct_types = kinds.len();
        let decision = if distinct_types < threshold {
            PanicDecision::Below
        } else if lockdown_active {
            PanicDecision::LockdownActive
        } else {
            self.signals_by_guild.remove(&guild_id);
            PanicDecision::Trigger
        };

        PanicModeResult {
            decision,
            distinct_types,
            threshold,
            kinds,
        }
    }

    /// Guildes suivies.
    pub fn tracked_guilds(&self) -> usize {
        self.signals_by_guild.len()
    }

    pub fn reset(&mut self) {
        self.signals_by_guild.clear();
    }
}

/// Incident `critical` du mode panique, de type `server`.
///
/// Preuves : types distincts observés, seuil et fenêtre ; modules corrélés ;
/// état du verrouillage.
pub fn panic_incident(
    language: Language,
    guild_id: u64,
    result: &PanicModeResult,
    lockdown: &LockdownOutcome,
) -> SecurityIncident {
    let mut incident = SecurityIncident::new(
        ProtectionModule::PanicMode.key(),
        LogType::Server,
        LogSeverity::Critical,
        text(language, TextKey::PanicModeSummary),
        vec![lockdown.action_outcome()],
    );
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Server,
        id: Some(guild_id.to_string()),
        name: None,
    });
    incident.evidence.extend([
        SecurityEvidence::Threshold {
            observed: result.distinct_types as u64,
            threshold: result.threshold as u64,
            window_seconds: Some(DEFAULT_CORRELATION_WINDOW.as_secs()),
            unit: ThresholdUnit::Signals,
        },
        SecurityEvidence::Text {
            label: text(language, TextKey::PanicModeEvidenceModules).to_owned(),
            value: result.kinds.join(", "),
        },
    ]);
    incident.recommendation = Some(
        text(
            language,
            if lockdown.start == LockdownStart::Applied {
                TextKey::PanicModeRecommendation
            } else {
                TextKey::PanicModeRecommendationFailed
            },
        )
        .to_owned(),
    );
    incident
}
