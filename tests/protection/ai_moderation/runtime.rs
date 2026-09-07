// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiAnalysisRequest, AiClassification, AiFailureReason, AiMessageSnapshot,
    runtime::{AiModerationRuntime, AiRuntimeConfig, RuntimeAdmission, build_analysis_key},
};

fn request(id: &str) -> AiAnalysisRequest {
    AiAnalysisRequest {
        guild_id: "guild".into(),
        channel_id: "channel".into(),
        revision_id: Some(id.into()),
        message: AiMessageSnapshot { message_id: id.into(), author_id: "user".into(), author_label: "user".into(), content: "hello".into(), created_at_ms: 1 },
        recent_messages: Vec::new(),
        target_user_id: None,
        enabled_categories: foxsecura::protection::ai_moderation::AiModerationCategory::ALL.to_vec(),
    }
}

#[test]
fn cache_expires_after_ttl() {
    let mut runtime = AiModerationRuntime::new(AiRuntimeConfig { cache_ttl_ms: 10, ..AiRuntimeConfig::default() });
    let key = build_analysis_key(&request("1"));
    runtime.write_cached(key, AiClassification::clean(None), 100);
    assert!(runtime.read_cached(key, 109).is_some());
    assert!(runtime.read_cached(key, 110).is_none());
}

#[test]
fn exact_analysis_is_marked_in_flight() {
    let mut runtime = AiModerationRuntime::default();
    let key = build_analysis_key(&request("1"));
    assert_eq!(runtime.admit(key, 0), RuntimeAdmission::Granted);
    assert_eq!(runtime.admit(key, 0), RuntimeAdmission::AlreadyInFlight);
    runtime.finish(key);
    assert_eq!(runtime.admit(key, 0), RuntimeAdmission::Granted);
}

#[test]
fn concurrency_is_bounded() {
    let mut runtime = AiModerationRuntime::new(AiRuntimeConfig { max_concurrent_analyses: 1, ..AiRuntimeConfig::default() });
    assert_eq!(runtime.admit(build_analysis_key(&request("1")), 0), RuntimeAdmission::Granted);
    assert_eq!(runtime.admit(build_analysis_key(&request("2")), 0), RuntimeAdmission::QueueFull);
}

#[test]
fn breaker_opens_after_provider_outages() {
    let mut runtime = AiModerationRuntime::default();
    for _ in 0..5 {
        runtime.record_failure(AiFailureReason::TransportError, None, 100);
    }
    assert!(runtime.is_circuit_open(101));
    assert!(!runtime.is_circuit_open(60_100));
}

#[test]
fn client_errors_do_not_open_breaker() {
    let mut runtime = AiModerationRuntime::default();
    for _ in 0..10 {
        runtime.record_failure(AiFailureReason::ProviderError, Some(403), 100);
    }
    assert!(!runtime.is_circuit_open(101));
}

#[test]
fn cache_is_bounded() {
    let mut runtime = AiModerationRuntime::new(AiRuntimeConfig { max_cache_entries: 2, ..AiRuntimeConfig::default() });
    for id in ["1", "2", "3"] {
        runtime.write_cached(build_analysis_key(&request(id)), AiClassification::clean(None), 0);
    }
    assert_eq!(runtime.cache_len(), 2);
}
