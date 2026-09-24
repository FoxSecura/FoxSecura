// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Matchers compilés, une fois par liste (langue et mots personnalisés).
//!
//! Comme dans la V1 : les guildes qui partagent la même liste partagent le
//! même matcher, et un message ne recompile jamais la liste. Le cache est
//! borné ; au-delà, la liste utilisée le moins récemment est oubliée.

use std::collections::HashMap;
use std::sync::Arc;

use super::{BadWordsLanguage, BadWordsMatcher, resolve_blocked_words};

/// Nombre de listes compilées conservées par défaut.
pub const DEFAULT_MATCHER_CACHE_CAPACITY: usize = 256;

struct Entry {
    matcher: Arc<BadWordsMatcher>,
    last_used: u64,
}

/// Cache borné des matchers de mots interdits.
pub struct BadWordsMatcherCache {
    capacity: usize,
    tick: u64,
    compilations: u64,
    entries: HashMap<BadWordsLanguage, HashMap<Vec<String>, Entry>>,
}

impl Default for BadWordsMatcherCache {
    fn default() -> Self {
        Self::new(DEFAULT_MATCHER_CACHE_CAPACITY)
    }
}

impl BadWordsMatcherCache {
    /// `capacity` vaut au moins 1.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tick: 0,
            compilations: 0,
            entries: HashMap::new(),
        }
    }

    /// Matcher de la liste intégrée `language` complétée par `custom_words`,
    /// compilé au premier appel seulement.
    pub fn matcher(
        &mut self,
        language: BadWordsLanguage,
        custom_words: &[String],
    ) -> Arc<BadWordsMatcher> {
        self.tick += 1;
        let tick = self.tick;

        if let Some(entry) = self
            .entries
            .get_mut(&language)
            .and_then(|lists| lists.get_mut(custom_words))
        {
            entry.last_used = tick;
            return Arc::clone(&entry.matcher);
        }

        if self.len() >= self.capacity {
            self.evict_least_recently_used();
        }

        self.compilations += 1;
        let matcher = Arc::new(BadWordsMatcher::new(resolve_blocked_words(
            language,
            custom_words,
        )));
        self.entries.entry(language).or_default().insert(
            custom_words.to_vec(),
            Entry {
                matcher: Arc::clone(&matcher),
                last_used: tick,
            },
        );
        matcher
    }

    /// Listes actuellement compilées.
    pub fn len(&self) -> usize {
        self.entries.values().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Nombre total de compilations depuis la création du cache.
    pub fn compilations(&self) -> u64 {
        self.compilations
    }

    fn evict_least_recently_used(&mut self) {
        let oldest = self
            .entries
            .iter()
            .flat_map(|(language, lists)| {
                lists
                    .iter()
                    .map(move |(words, entry)| (entry.last_used, *language, words))
            })
            .min_by_key(|(last_used, ..)| *last_used)
            .map(|(_, language, words)| (language, words.clone()));

        if let Some((language, words)) = oldest
            && let Some(lists) = self.entries.get_mut(&language)
        {
            lists.remove(&words);
            if lists.is_empty() {
                self.entries.remove(&language);
            }
        }
    }
}
