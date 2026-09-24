// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Cache mémoire, par guilde, de ce que lit le pipeline de messages.
//!
//! Sans cache, chaque message relit en SQLite la configuration, le salon
//! ignoré, la liste blanche, les modules activés et les mots personnalisés
//! (jusqu'à six requêtes par message). Avec le cache, une guilde est chargée
//! une fois (six requêtes), puis chaque message est servi depuis la mémoire
//! jusqu'à la prochaine écriture de sa configuration.
//!
//! # Cohérence
//!
//! - Toute écriture passe par [`WriteConnection`](super::client), qui
//!   invalide la guilde **sous le verrou de la connexion**, même si
//!   l'écriture échoue.
//! - Un chargement se fait lui aussi sous ce verrou : il ne peut pas
//!   s'intercaler entre une écriture et son invalidation, donc jamais
//!   remettre en cache un état périmé.
//! - Une lecture servie par le cache pendant une écriture en cours voit l'état
//!   d'avant : elle est ordonnée avant l'écriture.
//!
//! # Limites
//!
//! Mono-instance : le cache vit dans le processus. Une écriture faite par un
//! autre processus (deuxième instance, outil SQLite) n'est vue qu'au
//! redémarrage ou après l'éviction de la guilde. Le cache est borné ; au-delà,
//! la guilde utilisée le moins récemment est oubliée.

use std::collections::HashMap;
use std::sync::Arc;

use crate::protection::shared::ModuleSet;

use super::GuildConfig;

/// Nombre de guildes conservées par défaut.
pub const DEFAULT_GUILD_CACHE_CAPACITY: usize = 1024;

/// Tout ce que le pipeline de messages lit pour une guilde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuildSnapshot {
    /// `None` si la guilde n'a jamais été configurée : rien n'est activé.
    pub guild_config: Option<GuildConfig>,
    /// Listes triées (recherche dichotomique).
    pub ignored_channels: Vec<u64>,
    pub whitelist_users: Vec<u64>,
    pub whitelist_roles: Vec<u64>,
    pub enabled_modules: ModuleSet,
    pub custom_bad_words: Arc<[String]>,
}

/// Compteurs du cache, pour mesurer les lectures SQLite évitées.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuildCacheStats {
    /// Messages servis depuis la mémoire.
    pub hits: u64,
    /// Chargements depuis SQLite.
    pub loads: u64,
    /// Invalidations (une par écriture).
    pub invalidations: u64,
    /// Guildes oubliées faute de place.
    pub evictions: u64,
}

struct Entry {
    snapshot: Arc<GuildSnapshot>,
    last_used: u64,
}

pub(crate) struct GuildCache {
    capacity: usize,
    tick: u64,
    entries: HashMap<u64, Entry>,
    stats: GuildCacheStats,
}

impl GuildCache {
    /// `capacity` vaut au moins 1.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tick: 0,
            entries: HashMap::new(),
            stats: GuildCacheStats::default(),
        }
    }

    pub fn get(&mut self, guild_id: u64) -> Option<Arc<GuildSnapshot>> {
        self.tick += 1;
        let entry = self.entries.get_mut(&guild_id)?;
        entry.last_used = self.tick;
        self.stats.hits += 1;
        Some(Arc::clone(&entry.snapshot))
    }

    /// Enregistre un chargement. Doit être appelé sous le verrou de la
    /// connexion (voir la documentation du module).
    pub fn insert(&mut self, guild_id: u64, snapshot: Arc<GuildSnapshot>) {
        self.tick += 1;
        self.stats.loads += 1;
        if !self.entries.contains_key(&guild_id) && self.entries.len() >= self.capacity {
            self.evict_least_recently_used();
        }
        self.entries.insert(
            guild_id,
            Entry {
                snapshot,
                last_used: self.tick,
            },
        );
    }

    pub fn invalidate(&mut self, guild_id: u64) {
        self.stats.invalidations += 1;
        self.entries.remove(&guild_id);
    }

    pub fn stats(&self) -> GuildCacheStats {
        self.stats
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn evict_least_recently_used(&mut self) {
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(guild_id, _)| *guild_id)
        {
            self.entries.remove(&oldest);
            self.stats.evictions += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Arc<GuildSnapshot> {
        Arc::new(GuildSnapshot {
            guild_config: None,
            ignored_channels: Vec::new(),
            whitelist_users: Vec::new(),
            whitelist_roles: Vec::new(),
            enabled_modules: ModuleSet::empty(),
            custom_bad_words: Arc::from([]),
        })
    }

    #[test]
    fn serves_loaded_guilds_until_invalidated() {
        let mut cache = GuildCache::new(4);
        assert!(cache.get(1).is_none());
        cache.insert(1, snapshot());
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());

        cache.invalidate(1);
        assert!(cache.get(1).is_none());
        assert_eq!(
            cache.stats(),
            GuildCacheStats {
                hits: 1,
                loads: 1,
                invalidations: 1,
                evictions: 0,
            }
        );
    }

    #[test]
    fn is_bounded_and_forgets_the_least_recently_used_guild() {
        let mut cache = GuildCache::new(2);
        cache.insert(1, snapshot());
        cache.insert(2, snapshot());
        cache.get(1);
        cache.insert(3, snapshot());

        assert_eq!(cache.len(), 2);
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());
        assert!(cache.get(3).is_some());
        assert_eq!(cache.stats().evictions, 1);

        // Recharger une guilde présente n'évince personne.
        cache.insert(3, snapshot());
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.stats().evictions, 1);
    }
}
