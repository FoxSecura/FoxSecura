// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::runtime::{
    Action, GuildProtectionConfig, MemberInput, MessageInput, PlannedAction, ProtectionEngine,
    audit::AuditContext, parse_config,
};
use poise::serenity_prelude::AuditLogEntry;
use serde_json::json;
use std::{collections::HashSet, time::Duration};

fn settings(modules: &[&str]) -> GuildProtectionConfig {
    GuildProtectionConfig {
        enabled: modules.iter().map(|module| (*module).into()).collect(),
        minimum_account_age_days: 7,
        protected_names: vec!["Administrateur".into()],
        ..Default::default()
    }
}

fn message(id: u64) -> MessageInput {
    MessageInput {
        guild: 1,
        channel: 10,
        id,
        author: 20,
        owner: 99,
        content: "Bonjour à tous".into(),
        ..Default::default()
    }
}

fn has(actions: &[PlannedAction], module: &str) -> bool {
    actions.iter().any(|action| action.module == module)
}

fn evaluate(
    engine: &mut ProtectionEngine,
    config: &GuildProtectionConfig,
    input: &MessageInput,
    seconds: u64,
    edited: bool,
) -> Vec<PlannedAction> {
    engine.message(
        config,
        input,
        Duration::from_secs(seconds),
        Duration::from_secs(2_000_000),
        edited,
    )
}

#[test]
fn config_is_explicit_strict_and_isolated() {
    let configs =
        parse_config(r#"{"1":{"enabled":["message_flood"]},"2":{"enabled":[],"enforce":true}}"#)
            .unwrap();
    assert!(!configs[&1].enforce);
    assert!(configs[&1].enabled("message_flood"));
    assert!(!configs[&2].enabled("message_flood"));
    assert!(parse_config("{}").unwrap().is_empty());
    for invalid in [
        r#"{"1":{"enabled":["unknown"]}}"#,
        r#"{"1":{"enforce":"true"}}"#,
        r#"{"1":{"ignored_channels":[0]}}"#,
        r#"{"0":{}}"#,
        "[]",
        r#"{"1":{"enabeld":[]}}"#,
        r#"{"1":{"enabled":["honeypot"]}}"#,
        r#"{"1":{"enabled":["limit_role"]}}"#,
        r#"{"1":{"enabled":["member_profile"]}}"#,
        r#"{"1":{"enabled":["anti_impersonation"]}}"#,
    ] {
        assert!(parse_config(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn every_available_module_can_be_configured() {
    let keys = foxsecura::runtime::config::MODULES;
    assert_eq!(keys.len(), keys.iter().collect::<HashSet<_>>().len());
    let value = json!({"1": {"enabled": keys, "honeypot_channel": "10",
        "limited_roles": {"30": 2}, "protected_names": ["Administrateur"]}});
    assert_eq!(
        parse_config(&value.to_string()).unwrap()[&1].enabled.len(),
        keys.len()
    );
}

#[test]
fn disabled_bot_dm_ignored_and_exempt_messages_do_not_trigger() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["anti_everyone", "message_flood", "anti_ghost_ping"]);
    let mut input = message(1);
    input.mentions_everyone = true;
    assert!(
        evaluate(
            &mut engine,
            &GuildProtectionConfig::default(),
            &input,
            0,
            false
        )
        .is_empty()
    );
    for i in 0..4 {
        input.id += 1;
        input.exempt = i == 0;
        input.bot = i == 1;
        input.guild = if i == 2 { 0 } else { 1 };
        let mut config = config.clone();
        if i == 3 {
            config.ignored_channels.insert(10);
        }
        assert!(evaluate(&mut engine, &config, &input, 0, false).is_empty());
    }
}

#[test]
fn content_filters_block_matching_content_and_allow_legitimate_or_empty_text() {
    for (module, text) in [
        ("anti_invite", "https://discord.gg/raid"),
        ("adult_link", "https://www.pornhub.com/video"),
        ("bad_words", "Ce connard"),
        ("malicious_link", "https://grabify.link/test"),
        ("anti_scam", "free nitro verify your account"),
        ("invisible_char_filter", "bon\u{200b}jour"),
    ] {
        let mut engine = ProtectionEngine::default();
        let mut input = message(1);
        input.content = text.into();
        assert!(
            has(
                &evaluate(&mut engine, &settings(&[module]), &input, 0, false),
                module
            ),
            "{module}"
        );
        input.id += 1;
        input.content = "Bonjour, https://example.com".into();
        assert!(
            evaluate(&mut engine, &settings(&[module]), &input, 0, false).is_empty(),
            "{module}"
        );
        input.id += 1;
        input.content.clear();
        assert!(
            evaluate(&mut engine, &settings(&[module]), &input, 0, false).is_empty(),
            "{module}"
        );
    }
}

#[test]
fn multiple_detectors_delete_once_and_duplicate_delivery_is_ignored() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["anti_everyone", "anti_mass_mention", "attachment_filter"]);
    let mut input = message(1);
    input.mentions_everyone = true;
    input.mentions = vec![1, 2, 3, 4, 5];
    input.attachments = vec!["photo.EXE".into()];
    let actions = evaluate(&mut engine, &config, &input, 0, false);
    for module in ["anti_everyone", "anti_mass_mention", "attachment_filter"] {
        assert!(has(&actions, module));
    }
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a.action, Action::DeleteMessage { .. }))
            .count(),
        1
    );
    assert!(evaluate(&mut engine, &config, &input, 0, false).is_empty());
}

#[test]
fn flood_boundary_edits_window_and_guild_isolation() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["message_flood"]);
    for id in 1..=5 {
        assert!(evaluate(&mut engine, &config, &message(id), 0, false).is_empty());
    }
    for _ in 0..10 {
        assert!(evaluate(&mut engine, &config, &message(5), 1, true).is_empty());
    }
    assert!(has(
        &evaluate(&mut engine, &config, &message(6), 5, false),
        "message_flood"
    ));
    let mut other = message(7);
    other.guild = 2;
    assert!(evaluate(&mut engine, &config, &other, 5, false).is_empty());
    assert!(evaluate(&mut engine, &config, &message(8), 11, false).is_empty());
}

#[test]
fn mention_counters_reach_their_thresholds_and_expire() {
    for module in ["anti_ping_owner", "anti_spam_ping"] {
        let mut engine = ProtectionEngine::default();
        let config = settings(&[module]);
        for id in 1..=3 {
            let mut input = message(id);
            input.mentions = vec![99];
            assert_eq!(
                has(&evaluate(&mut engine, &config, &input, id, false), module),
                id == 3,
                "{module}"
            );
        }
        let mut input = message(4);
        input.mentions = vec![99];
        assert!(evaluate(&mut engine, &config, &input, 40, false).is_empty());
    }
}

#[test]
fn slowmode_counts_channels_and_webhook_bots_are_analyzed() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["auto_slowmode"]);
    for id in 1..=12 {
        let mut input = message(id);
        input.author = id + 100;
        assert_eq!(
            has(
                &evaluate(&mut engine, &config, &input, 0, false),
                "auto_slowmode"
            ),
            id == 12
        );
    }
    let mut webhook = message(50);
    webhook.bot = true;
    webhook.webhook = Some(60);
    webhook.content = "https://discord.gg/raid".into();
    let actions = evaluate(
        &mut engine,
        &settings(&["webhook_message"]),
        &webhook,
        1,
        false,
    );
    assert!(
        actions
            .iter()
            .any(|a| a.action == Action::RemoveWebhook { webhook: 60 })
    );
}

#[test]
fn ghost_ping_edits_recur_but_bot_deletions_are_discarded() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["anti_ghost_ping"]);
    for id in 1..=2 {
        let mut input = message(id);
        input.mentions = vec![31, 32, 33, 34, 35];
        evaluate(&mut engine, &config, &input, 0, false);
        input.mentions.clear();
        let actions = evaluate(&mut engine, &config, &input, 1, true);
        assert!(has(&actions, "anti_ghost_ping"));
        assert_eq!(
            actions
                .iter()
                .any(|a| matches!(a.action, Action::Timeout { .. })),
            id == 2
        );
    }
    let mut input = message(3);
    input.mentions = vec![31, 32, 33, 34, 35];
    evaluate(&mut engine, &config, &input, 2, false);
    engine.discard_message(1, 3);
    assert!(
        engine
            .message_deleted(&config, 1, 3, Duration::from_secs(3))
            .is_empty()
    );
}

#[test]
fn unattributed_deletion_does_not_count_toward_later_timeout() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["anti_ghost_ping"]);
    let mut input = message(1);
    input.mentions = vec![31, 32, 33, 34, 35];
    evaluate(&mut engine, &config, &input, 0, false);
    let actions = engine.message_deleted(&config, 1, 1, Duration::from_secs(1));
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, Action::Alert);
    input.id = 2;
    evaluate(&mut engine, &config, &input, 2, false);
    input.mentions.clear();
    let actions = evaluate(&mut engine, &config, &input, 3, true);
    assert!(actions.iter().all(|a| a.action == Action::Alert));
}

#[test]
fn honeypot_uses_configured_channel_and_exemptions() {
    let mut engine = ProtectionEngine::default();
    let mut config = settings(&["honeypot"]);
    config.honeypot_channel = Some(10);
    assert!(has(
        &evaluate(&mut engine, &config, &message(1), 0, false),
        "honeypot"
    ));
    let mut legitimate = message(2);
    legitimate.channel = 11;
    assert!(evaluate(&mut engine, &config, &legitimate, 0, false).is_empty());
    legitimate.channel = 10;
    legitimate.exempt = true;
    assert!(evaluate(&mut engine, &config, &legitimate, 0, false).is_empty());
}

fn member(user: u64) -> MemberInput {
    MemberInput {
        guild: 1,
        user,
        display_name: "Membre".into(),
        username: "membre".into(),
        created_at: Duration::ZERO,
        joined_at: Duration::from_secs(30 * 86400),
        ..Default::default()
    }
}

#[test]
fn join_burst_is_shared_but_profile_updates_do_not_count() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["join_burst"]);
    for user in 1..=4 {
        assert!(
            engine
                .member(&config, &member(user), Duration::ZERO, true)
                .is_empty()
        );
    }
    for _ in 0..10 {
        assert!(
            engine
                .member(&config, &member(4), Duration::ZERO, false)
                .is_empty()
        );
    }
    assert!(has(
        &engine.member(&config, &member(5), Duration::ZERO, true),
        "join_burst"
    ));
    assert!(
        engine
            .member(&config, &member(6), Duration::from_secs(21), true)
            .is_empty()
    );
}

#[test]
fn identity_signals_alert_while_hoisting_and_role_limits_plan_actions() {
    let mut engine = ProtectionEngine::default();
    let mut config = settings(&[
        "anti_new_account",
        "anti_double_account",
        "anti_impersonation",
        "anti_nickname_hoisting",
        "limit_role",
    ]);
    config.limited_roles.insert(30, 1);
    let mut input = member(20);
    input.display_name = "  .Administrateur".into();
    input.avatar = Some("avatar".into());
    input
        .identities
        .push((21, input.display_name.clone(), input.avatar.clone()));
    input.joined_at = Duration::from_secs(86400);
    input.role_counts = vec![(30, false, true, 2)];
    let actions = engine.member(&config, &input, Duration::ZERO, true);
    for name in [
        "anti_new_account",
        "anti_double_account",
        "anti_impersonation",
    ] {
        assert!(
            actions
                .iter()
                .any(|a| a.module == name && a.action == Action::Alert)
        );
    }
    assert!(
        actions
            .iter()
            .any(|a| matches!(&a.action, Action::NormalizeNickname { expected, .. } if expected == &input.display_name))
    );
    assert!(
        actions
            .iter()
            .any(|a| a.action == Action::RemoveRole { user: 20, role: 30 })
    );
    input.exempt = true;
    assert!(
        engine
            .member(&config, &input, Duration::ZERO, false)
            .is_empty()
    );
}

#[test]
fn anti_bot_only_kicks_on_arrival() {
    let mut engine = ProtectionEngine::default();
    let mut input = member(20);
    input.bot = true;
    assert!(has(
        &engine.member(&settings(&["anti_bot"]), &input, Duration::ZERO, true),
        "anti_bot"
    ));
    assert!(
        engine
            .member(&settings(&["anti_bot"]), &input, Duration::ZERO, false)
            .is_empty()
    );
}

fn audit(id: u64, action: u8, changes: serde_json::Value) -> AuditLogEntry {
    serde_json::from_value(
        json!({"id": id.to_string(), "user_id": "20", "target_id": "30",
        "action_type": action, "changes": changes, "reason": null, "options": null}),
    )
    .unwrap()
}
fn context() -> AuditContext {
    AuditContext {
        guild: 1,
        owner: 99,
        bot: 98,
        executor_resolved: true,
        ..Default::default()
    }
}

#[test]
fn every_nuke_burst_is_routed_to_its_executor_counter() {
    for (module, action, threshold, changes) in [
        ("anti_mass_ban", 22, 3, json!([])),
        ("anti_mass_kick", 20, 3, json!([])),
        ("anti_mass_unban", 23, 5, json!([])),
        (
            "anti_mass_timeout",
            24,
            3,
            json!([{"key":"communication_disabled_until","new_value":"2026-09-13T15:00:00Z"}]),
        ),
        (
            "anti_mass_role_grant",
            25,
            5,
            json!([{"key":"$add","new_value":[{"id":"40","name":"rôle"}]}]),
        ),
        ("anti_mass_channel_create", 10, 5, json!([])),
        ("anti_mass_role_create", 30, 5, json!([])),
        ("anti_emoji_sticker_nuke", 62, 5, json!([])),
    ] {
        let mut engine = ProtectionEngine::default();
        for id in 1..=threshold {
            let actions = engine.audit(
                &settings(&[module]),
                &audit(id, action, changes.clone()),
                context(),
                Duration::ZERO,
            );
            assert_eq!(has(&actions, module), id == threshold, "{module}");
        }
        assert!(
            engine
                .audit(
                    &settings(&[module]),
                    &audit(threshold, action, changes),
                    context(),
                    Duration::ZERO
                )
                .is_empty()
        );
    }
}

#[test]
fn nuke_exemptions_and_unresolved_executor_prevent_enforcement() {
    let config = settings(&["anti_channel_delete"]);
    for exempt in [true, false] {
        let mut engine = ProtectionEngine::default();
        let ctx = AuditContext {
            executor_exempt: exempt,
            executor_resolved: false,
            ..context()
        };
        let actions = engine.audit(&config, &audit(1, 12, json!([])), ctx, Duration::ZERO);
        assert!(actions.iter().all(|a| a.action == Action::Alert));
        assert_eq!(actions.is_empty(), exempt);
    }
    for user in [99, 98] {
        let mut entry = audit(1, 12, json!([]));
        entry.user_id = poise::serenity_prelude::UserId::new(user);
        assert!(
            ProtectionEngine::default()
                .audit(&config, &entry, context(), Duration::ZERO)
                .is_empty()
        );
    }
}

#[test]
fn removing_roles_and_timeouts_does_not_count_as_granting_them() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&["anti_mass_timeout", "anti_mass_role_grant"]);
    for id in 1..=10 {
        assert!(
            engine
                .audit(
                    &config,
                    &audit(
                        id,
                        24,
                        json!([{"key":"communication_disabled_until",
            "old_value":"2026-09-13T15:00:00Z"}])
                    ),
                    context(),
                    Duration::ZERO
                )
                .is_empty()
        );
        assert!(
            engine
                .audit(
                    &config,
                    &audit(
                        id + 20,
                        25,
                        json!([{"key":"$remove",
            "new_value":[{"id":"40","name":"rôle"}]}])
                    ),
                    context(),
                    Duration::ZERO
                )
                .is_empty()
        );
    }
}

#[test]
fn server_integrity_permissions_webhooks_and_panic_are_connected() {
    let mut engine = ProtectionEngine::default();
    let config = settings(&[
        "anti_role_delete",
        "anti_server_edit",
        "anti_vanity_change",
        "anti_permissions",
        "anti_external_application",
        "webhook_watch",
        "automod_rule_guard",
        "panic_mode",
    ]);
    assert!(has(
        &engine.audit(&config, &audit(1, 32, json!([])), context(), Duration::ZERO),
        "anti_role_delete"
    ));
    let server = engine.audit(
        &config,
        &audit(
            2,
            1,
            json!([
        {"key":"name","old_value":"Serveur","new_value":"Modifié"},
        {"key":"vanity_url_code","old_value":"old","new_value":"new"}]),
        ),
        context(),
        Duration::ZERO,
    );
    for module in ["anti_server_edit", "anti_vanity_change", "panic_mode"] {
        assert!(has(&server, module));
    }
    let permissions = engine.audit(
        &config,
        &audit(
            3,
            31,
            json!([
        {"key":"permissions","old_value":"0","new_value": ((1u64 << 50) | 8).to_string()}]),
        ),
        context(),
        Duration::ZERO,
    );
    assert!(has(&permissions, "anti_external_application"));
    assert!(
        permissions
            .iter()
            .any(|a| matches!(a.action, Action::RollbackPermissions { .. }))
    );
    let webhook = engine.audit(&config, &audit(4, 50, json!([])), context(), Duration::ZERO);
    assert!(
        webhook
            .iter()
            .any(|a| a.action == Action::RemoveWebhook { webhook: 30 })
    );
    let automod = engine.audit(
        &config,
        &audit(5, 142, json!([])),
        AuditContext {
            managed_rule: true,
            ..context()
        },
        Duration::ZERO,
    );
    assert!(automod.iter().any(|a| a.action == Action::SyncAutoMod));
}

#[test]
fn native_profile_rule_payload_preserves_discord_fields_and_exemptions() {
    use foxsecura::protection::automod::native_rules::{AutoModRuleKey, build_rule_specs};
    let mut config = settings(&["native_rules", "member_profile"]);
    config.exempt_roles.insert(30);
    config.ignored_channels.insert(10);
    for spec in build_rule_specs(["mot"]) {
        let payload = foxsecura::runtime::automod::rule_payload(&spec, true, &config);
        assert_eq!(payload["exempt_roles"], json!(["30"]));
        assert_eq!(payload["exempt_channels"], json!(["10"]));
        if spec.key == AutoModRuleKey::MemberProfileFilter {
            assert_eq!(payload["event_type"], 2);
            assert_eq!(payload["trigger_type"], 6);
            assert_eq!(payload["actions"][0]["type"], 4);
        }
    }
}

#[test]
fn temporary_modes_and_managed_rules_are_persistent_and_isolated() {
    use foxsecura::database::{Database, TemporarySlowmode};
    let path = std::env::temp_dir().join(format!(
        "foxsecura-runtime-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mode = TemporarySlowmode {
        guild: 1,
        channel: 10,
        previous_seconds: 2,
        applied_seconds: 10,
        restore_at: 120,
        pending_seconds: Some(2),
    };
    {
        let db = Database::open(&path).unwrap();
        assert!(db.save_temporary_slowmode(&mode).unwrap());
        db.remember_managed_rule(1, 50, "FoxSecura: test").unwrap();
    }
    {
        let db = Database::open(&path).unwrap();
        assert_eq!(db.temporary_slowmodes().unwrap(), vec![mode]);
        assert!(db.is_managed_rule(1, 50).unwrap());
        assert!(!db.is_managed_rule(2, 50).unwrap());
        db.remove_temporary_slowmode(10).unwrap();
        assert!(db.temporary_slowmodes().unwrap().is_empty());
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn panic_mode_upgrades_slowmode_without_losing_original_or_shortening_deadline() {
    use foxsecura::database::{Database, TemporarySlowmode};
    let db = Database::open_in_memory().unwrap();
    let first = TemporarySlowmode {
        guild: 1,
        channel: 10,
        previous_seconds: 2,
        applied_seconds: 10,
        restore_at: 120,
        pending_seconds: Some(2),
    };
    assert!(db.save_temporary_slowmode(&first).unwrap());
    db.confirm_temporary_slowmode(10).unwrap();
    let upgrade = TemporarySlowmode {
        previous_seconds: 10,
        applied_seconds: 30,
        restore_at: 900,
        pending_seconds: Some(10),
        ..first.clone()
    };
    assert!(db.save_temporary_slowmode(&upgrade).unwrap());
    let saved = &db.temporary_slowmodes().unwrap()[0];
    assert_eq!(saved.previous_seconds, 2);
    assert_eq!(saved.applied_seconds, 30);
    assert_eq!(saved.restore_at, 900);
    assert_eq!(saved.pending_seconds, Some(10));
    // Une requête plus faible ou un changement fait par le staff ne réécrit pas le bail.
    assert!(!db.save_temporary_slowmode(&first).unwrap());
    assert!(
        !db.save_temporary_slowmode(&TemporarySlowmode {
            previous_seconds: 5,
            applied_seconds: 60,
            ..upgrade
        })
        .unwrap()
    );
    db.confirm_temporary_slowmode(10).unwrap();
    assert_eq!(db.temporary_slowmodes().unwrap()[0].pending_seconds, None);
}

mod ai {
    use super::*;
    use foxsecura::{
        protection::ai_moderation::{
            AiFailureReason,
            providers::{
                AiCompletionRequest, AiCompletionResult, AiModerationProvider,
                openai::OPENAI_MODERATION_MODEL,
            },
        },
        runtime::ai::AiService,
    };
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Provider {
        calls: AtomicUsize,
        mode: u8,
    }
    impl AiModerationProvider for Provider {
        fn name(&self) -> &str {
            "test"
        }
        fn model(&self) -> &str {
            OPENAI_MODERATION_MODEL
        }
        fn is_configured(&self) -> bool {
            true
        }
        fn complete<'a>(
            &'a self,
            _: AiCompletionRequest,
        ) -> Pin<Box<dyn Future<Output = AiCompletionResult> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if self.mode == 1 {
                    std::future::pending::<()>().await;
                }
                if self.mode == 2 {
                    return AiCompletionResult::Error {
                        reason: AiFailureReason::TransportError,
                        model: self.model().into(),
                        status_code: None,
                        latency_ms: 0,
                    };
                }
                let mut categories = serde_json::Map::new();
                for name in [
                    "sexual",
                    "sexual/minors",
                    "harassment",
                    "harassment/threatening",
                    "hate",
                    "hate/threatening",
                    "illicit",
                    "illicit/violent",
                    "self-harm",
                    "self-harm/intent",
                    "self-harm/instructions",
                    "violence",
                    "violence/graphic",
                ] {
                    categories.insert(name.into(), json!(name == "hate"));
                }
                AiCompletionResult::Ok {
                    content: if self.mode == 3 {
                        "{}".into()
                    } else {
                        json!({"results":[{"flagged":true,"categories":categories}]}).to_string()
                    },
                    model: self.model().into(),
                    latency_ms: 0,
                }
            })
        }
    }

    #[tokio::test]
    async fn ai_opt_in_exemptions_and_cache_precede_provider_calls() {
        let service = AiService::default();
        let provider = Provider {
            calls: AtomicUsize::new(0),
            mode: 0,
        };
        let input = message(1);
        let enabled = settings(&["ai_moderation"]);
        assert!(
            service
                .analyze(&settings(&[]), &input, Some(&provider), 100)
                .await
                .is_none()
        );
        let mut exempt = input.clone();
        exempt.exempt = true;
        assert!(
            service
                .analyze(&enabled, &exempt, Some(&provider), 100)
                .await
                .is_none()
        );
        assert!(service.analyze(&enabled, &input, None, 100).await.is_none());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            service
                .analyze(&enabled, &input, Some(&provider), 100)
                .await
                .unwrap()
                .delete_message
        );
        service
            .analyze(&enabled, &input, Some(&provider), 100)
            .await
            .unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ai_timeout_transport_and_invalid_schema_never_sanction_or_leak_slots() {
        for mode in 1..=3 {
            let service = AiService::default();
            let provider = Provider {
                calls: AtomicUsize::new(0),
                mode,
            };
            for _ in 0..2 {
                assert!(
                    service
                        .analyze(
                            &settings(&["ai_moderation"]),
                            &message(1),
                            Some(&provider),
                            1
                        )
                        .await
                        .is_none()
                );
            }
            assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        }
    }
}

#[test]
fn privileged_members_still_obey_bot_and_role_limits() {
    let mut config = settings(&["anti_bot", "limit_role", "anti_nickname_hoisting"]);
    config.limited_roles.insert(30, 1);
    let mut input = member(20);
    input.profile_exempt = true;
    input.bot = true;
    input.role_counts = vec![(30, false, true, 2)];
    let actions = ProtectionEngine::default().member(&config, &input, Duration::ZERO, true);
    assert!(
        actions
            .iter()
            .any(|a| a.action == Action::Kick { user: 20 })
    );
    assert!(
        actions
            .iter()
            .any(|a| a.action == Action::RemoveRole { user: 20, role: 30 })
    );
    input.exempt = true;
    assert!(
        ProtectionEngine::default()
            .member(&config, &input, Duration::ZERO, true)
            .is_empty()
    );
}

#[test]
fn attachment_only_correction_invalidates_pending_deletion() {
    use foxsecura::runtime::MessageRevision;
    let mut input = message(1);
    input.attachments = vec!["danger.exe".into()];
    let before = MessageRevision::from(&input);
    input.attachments.clear();
    assert_ne!(before, MessageRevision::from(&input));
}

#[test]
fn failed_slowmode_can_retry_without_losing_original_state() {
    use foxsecura::database::{Database, TemporarySlowmode};
    let db = Database::open_in_memory().unwrap();
    let mode = TemporarySlowmode {
        guild: 1,
        channel: 10,
        previous_seconds: 2,
        applied_seconds: 10,
        pending_seconds: Some(2),
        restore_at: 120,
    };
    assert!(db.save_temporary_slowmode(&mode).unwrap());
    assert!(db.save_temporary_slowmode(&mode).unwrap());
    assert_eq!(db.temporary_slowmodes().unwrap(), vec![mode]);
    db.confirm_temporary_slowmode(10).unwrap();
    assert!(
        !db.save_temporary_slowmode(&TemporarySlowmode {
            guild: 1,
            channel: 10,
            previous_seconds: 5,
            applied_seconds: 30,
            pending_seconds: Some(5),
            restore_at: 900
        })
        .unwrap()
    );
}

#[test]
fn renamed_native_rules_can_be_restored_and_disabled_by_persistent_identity() {
    use foxsecura::{database::Database, protection::automod::native_rules::*};
    let db = Database::open_in_memory().unwrap();
    for (index, spec) in build_rule_specs(&["insulte"])
        .into_iter()
        .enumerate()
    {
        let id = 50 + index as u64;
        db.remember_managed_rule(1, id, &spec.name).unwrap();
        let names = db.managed_rule_names(1).unwrap();
        let rule = ExistingAutoModRule::new(
            id,
            foxsecura::runtime::automod::reconciliation_name(id, "renamed by staff", true, &names),
            spec.trigger_type,
        );
        for enabled in [true, false] {
            let plan = plan_reconciliation(&[rule.clone()], &spec, enabled, false);
            assert!(plan.mutations.iter().any(|m| matches!(m, RuleMutation::Update { rule_id, enabled: value, .. } if *rule_id == id && *value == enabled)));
        }
        assert!(db.managed_rule_names(2).unwrap().is_empty());
    }
}

#[test]
fn documented_configuration_is_valid_and_covers_available_modules() {
    let config = parse_config(include_str!("../protection.example.json")).unwrap();
    assert_eq!(config[&123456789012345678].enabled.len(), foxsecura::runtime::config::MODULES.len());
    assert!(!config[&123456789012345678].enforce);
}
