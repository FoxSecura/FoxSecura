// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use foxsecura::database::{Database, DatabaseError};
use foxsecura::protection::anti_nuke::audit::{AuditEntryDedup, RecentAuditAuthors};
use foxsecura::protection::anti_nuke::burst::NukeBurstTracker;
use foxsecura::protection::anti_nuke::panic_mode::PanicModeDetector;
use foxsecura::protection::anti_raid::join_burst::JoinBurstDetector;
use foxsecura::protection::anti_spam::anti_ghost_ping::{AntiGhostPingDetector, BotDeletionMarks};
use foxsecura::protection::anti_spam::auto_slowmode::AutoSlowmodeDetector;
use foxsecura::protection::anti_spam::message_flood::MessageFloodTracker;
use foxsecura::protection::automod::bad_words::BadWordsMatcherCache;
use foxsecura::protection::content_filter::MentionBursts;
use foxsecura::protection::lockdown::{GuildLocks, LockdownTimers};
use foxsecura::protection::quarantine::MemberLocks;

use super::Error;
use super::pipeline::auto_slowmode::SlowmodeInFlight;

/// État partagé par les commandes et les événements.
pub struct AppData {
    pub database: Arc<Database>,
    pub protection: ProtectionState,
}

impl AppData {
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            database,
            protection: ProtectionState::default(),
        }
    }
}

/// État en mémoire des protections.
///
/// Mono-instance : perdu au redémarrage et non partagé entre plusieurs
/// processus. Les verrous sont des `std::sync::Mutex` : ils ne doivent être
/// pris que dans du code synchrone, jamais conservés à travers un `.await`.
/// Seules exceptions, les verrous de quarantaine (par membre) et de
/// verrouillage (par guilde), asynchrones et conçus pour être tenus pendant
/// toute une opération.
#[derive(Default)]
pub struct ProtectionState {
    message_flood: Mutex<MessageFloodTracker>,
    mention_bursts: Mutex<MentionBursts>,
    ghost_pings: Mutex<AntiGhostPingDetector>,
    bot_deletions: Mutex<BotDeletionMarks>,
    auto_slowmode: Mutex<AutoSlowmodeDetector>,
    slowmode_in_flight: Arc<SlowmodeInFlight>,
    join_bursts: Mutex<JoinBurstDetector>,
    bad_words: Mutex<BadWordsMatcherCache>,
    quarantine_locks: Arc<MemberLocks>,
    lockdown_locks: Arc<GuildLocks>,
    lockdown_timers: Arc<LockdownTimers>,
    member_prewarm: Arc<tokio::sync::Mutex<()>>,
    audit_dedup: Mutex<AuditEntryDedup>,
    audit_authors: Mutex<RecentAuditAuthors>,
    nuke_bursts: Mutex<NukeBurstTracker>,
    panic_mode: Mutex<PanicModeDetector>,
    audit_permission_warnings: Mutex<HashSet<u64>>,
}

impl ProtectionState {
    /// Accès exclusif au tracker anti-spam.
    ///
    /// Un verrou empoisonné (panique d'un autre thread) est récupéré : l'état
    /// ne contient que des horodatages, toujours cohérents entre deux appels.
    pub fn message_flood(&self) -> MutexGuard<'_, MessageFloodTracker> {
        self.message_flood
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Rafales de l'anti-ping du propriétaire et de l'anti-spam de mentions,
    /// par auteur (bornées).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// horodatages.
    pub fn mention_bursts(&self) -> MutexGuard<'_, MentionBursts> {
        self.mention_bursts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Messages de masse suivis par l'anti-ghost-ping et récidives (bornés).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// identifiants et des horodatages.
    pub fn ghost_pings(&self) -> MutexGuard<'_, AntiGhostPingDetector> {
        self.ghost_pings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Messages que FoxSecura supprime lui-même (bornés) : leur suppression
    /// n'est jamais un ghost ping.
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// identifiants et des horodatages.
    pub fn bot_deletions(&self) -> MutexGuard<'_, BotDeletionMarks> {
        self.bot_deletions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Rafales du mode lent automatique, par salon (bornées).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// horodatages.
    pub fn auto_slowmode(&self) -> MutexGuard<'_, AutoSlowmodeDetector> {
        self.auto_slowmode
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Salons dont une pose de mode lent automatique est en cours.
    pub fn slowmode_in_flight(&self) -> &Arc<SlowmodeInFlight> {
        &self.slowmode_in_flight
    }

    /// Fenêtres glissantes des arrivées, par guilde (bornées).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// horodatages.
    pub fn join_bursts(&self) -> MutexGuard<'_, JoinBurstDetector> {
        self.join_bursts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Matchers de mots interdits compilés, un par liste (cache borné).
    ///
    /// Un verrou empoisonné est récupéré : le cache ne contient que des
    /// matchers immuables, toujours valides.
    pub fn bad_words(&self) -> MutexGuard<'_, BadWordsMatcherCache> {
        self.bad_words
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Verrous par membre des quarantaines et libérations, partagés avec la
    /// maintenance périodique.
    pub fn quarantine_locks(&self) -> &Arc<MemberLocks> {
        &self.quarantine_locks
    }

    /// Verrous par guilde des poses et levées de verrouillage, partagés avec
    /// les minuteries.
    pub fn lockdown_locks(&self) -> &Arc<GuildLocks> {
        &self.lockdown_locks
    }

    /// Tour de rôle du préchauffage du cache des membres : une demande à la
    /// fois, toutes guildes confondues.
    pub fn member_prewarm(&self) -> &Arc<tokio::sync::Mutex<()>> {
        &self.member_prewarm
    }

    /// Entrées du journal d'audit déjà traitées (bornées).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// identifiants.
    pub fn audit_dedup(&self) -> MutexGuard<'_, AuditEntryDedup> {
        self.audit_dedup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Auteurs récents des entrées corrélables à un événement Gateway
    /// (suppressions de salons et de rôles, mises à jour du serveur ; bornés).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// identifiants et des horodatages.
    pub fn audit_authors(&self) -> MutexGuard<'_, RecentAuditAuthors> {
        self.audit_authors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Rafales de l'anti-nuke par auteur, avec leurs pauses (bornées).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// horodatages.
    pub fn nuke_bursts(&self) -> MutexGuard<'_, NukeBurstTracker> {
        self.nuke_bursts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Signaux du mode panique, par guilde (fenêtre de 30 s, bornés).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// horodatages et des clés de modules.
    pub fn panic_mode(&self) -> MutexGuard<'_, PanicModeDetector> {
        self.panic_mode
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Guildes déjà signalées pour l'absence de `VIEW_AUDIT_LOG` depuis le
    /// démarrage (une entrée par guilde au plus).
    pub fn audit_permission_warnings(&self) -> MutexGuard<'_, HashSet<u64>> {
        self.audit_permission_warnings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Minuteries de levée armées (au plus une par guilde).
    pub fn lockdown_timers(&self) -> &Arc<LockdownTimers> {
        &self.lockdown_timers
    }
}

/// Exécute une opération SQLite hors des threads asynchrones.
///
/// `rusqlite` est synchrone et la connexion est protégée par un verrou avec un
/// délai d'attente : l'appel passe donc par `spawn_blocking` pour ne jamais
/// bloquer le runtime Tokio.
pub async fn run_database<T, F>(database: &Arc<Database>, operation: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T, DatabaseError> + Send + 'static,
{
    let database = Arc::clone(database);
    let result = tokio::task::spawn_blocking(move || operation(&database)).await?;
    Ok(result?)
}
