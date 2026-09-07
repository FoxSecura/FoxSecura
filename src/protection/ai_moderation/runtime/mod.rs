// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};

use super::{AiAnalysisRequest, AiClassification, AiFailureReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnalysisKey([u64; 2]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiRuntimeConfig {
    pub cache_ttl_ms: u64,
    pub max_cache_entries: usize,
    pub max_concurrent_analyses: usize,
    pub breaker_failure_threshold: usize,
    pub breaker_cooldown_ms: u64,
}

impl Default for AiRuntimeConfig {
    fn default() -> Self {
        Self {
            cache_ttl_ms: 10 * 60 * 1_000,
            max_cache_entries: 500,
            max_concurrent_analyses: 4,
            breaker_failure_threshold: 5,
            breaker_cooldown_ms: 60 * 1_000,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    classification: AiClassification,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAdmission {
    Granted,
    AlreadyInFlight,
    QueueFull,
    CircuitOpen,
}

#[derive(Debug)]
pub struct AiModerationRuntime {
    config: AiRuntimeConfig,
    cache: HashMap<AnalysisKey, CacheEntry>,
    cache_order: VecDeque<AnalysisKey>,
    in_flight: HashSet<AnalysisKey>,
    consecutive_failures: usize,
    breaker_opened_at_ms: Option<u64>,
}

impl Default for AiModerationRuntime {
    fn default() -> Self {
        Self::new(AiRuntimeConfig::default())
    }
}

impl AiModerationRuntime {
    pub fn new(config: AiRuntimeConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            in_flight: HashSet::new(),
            consecutive_failures: 0,
            breaker_opened_at_ms: None,
        }
    }

    pub fn read_cached(
        &mut self,
        key: AnalysisKey,
        now_ms: u64,
    ) -> Option<AiClassification> {
        let expired = self
            .cache
            .get(&key)
            .is_some_and(|entry| entry.expires_at_ms <= now_ms);
        if expired {
            self.cache.remove(&key);
            self.cache_order.retain(|candidate| *candidate != key);
            return None;
        }
        self.cache.get(&key).map(|entry| entry.classification.clone())
    }

    pub fn write_cached(
        &mut self,
        key: AnalysisKey,
        classification: AiClassification,
        now_ms: u64,
    ) {
        if !self.cache.contains_key(&key) {
            while self.cache.len() >= self.config.max_cache_entries.max(1) {
                if let Some(oldest) = self.cache_order.pop_front() {
                    self.cache.remove(&oldest);
                } else {
                    break;
                }
            }
            self.cache_order.push_back(key);
        }
        self.cache.insert(
            key,
            CacheEntry {
                classification,
                expires_at_ms: now_ms.saturating_add(self.config.cache_ttl_ms),
            },
        );
    }

    pub fn admit(&mut self, key: AnalysisKey, now_ms: u64) -> RuntimeAdmission {
        if self.is_circuit_open(now_ms) {
            return RuntimeAdmission::CircuitOpen;
        }
        if self.in_flight.contains(&key) {
            return RuntimeAdmission::AlreadyInFlight;
        }
        if self.in_flight.len() >= self.config.max_concurrent_analyses {
            return RuntimeAdmission::QueueFull;
        }
        self.in_flight.insert(key);
        RuntimeAdmission::Granted
    }

    pub fn finish(&mut self, key: AnalysisKey) {
        self.in_flight.remove(&key);
    }

    pub fn is_circuit_open(&mut self, now_ms: u64) -> bool {
        if self.consecutive_failures < self.config.breaker_failure_threshold {
            return false;
        }
        let Some(opened_at) = self.breaker_opened_at_ms else {
            return false;
        };
        if now_ms.saturating_sub(opened_at) >= self.config.breaker_cooldown_ms {
            self.consecutive_failures = self.config.breaker_failure_threshold.saturating_sub(1);
            return false;
        }
        true
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.breaker_opened_at_ms = None;
    }

    pub fn record_failure(
        &mut self,
        reason: AiFailureReason,
        status_code: Option<u16>,
        now_ms: u64,
    ) {
        let client_response = status_code.is_some_and(|status| (400..500).contains(&status));
        if reason == AiFailureReason::RateLimited || client_response {
            self.record_success();
            return;
        }
        if matches!(reason, AiFailureReason::SchemaViolation | AiFailureReason::InvalidJson) {
            return;
        }

        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures == self.config.breaker_failure_threshold {
            self.breaker_opened_at_ms = Some(now_ms);
        }
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn reset(&mut self) {
        self.cache.clear();
        self.cache_order.clear();
        self.in_flight.clear();
        self.consecutive_failures = 0;
        self.breaker_opened_at_ms = None;
    }
}

pub fn build_analysis_key(request: &AiAnalysisRequest) -> AnalysisKey {
    fn hash_with_salt(request: &AiAnalysisRequest, salt: u64) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        salt.hash(&mut hasher);
        request.hash(&mut hasher);
        hasher.finish()
    }

    AnalysisKey([
        hash_with_salt(request, 0xF05E_C0DE),
        hash_with_salt(request, 0xA11D_2026),
    ])
}
