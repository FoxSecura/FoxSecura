// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Exécution de la réconciliation avec un faux client HTTP : ordre des
//! appels, échec isolé, permission manquante, verrou par guilde, suppression
//! limitée au préfixe, correspondance règle → interrupteur et rapports.

use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use foxsecura::i18n::Language;
use foxsecura::protection::automod::native_rules::{
    AUTOMOD_CLEANUP_REASON, AUTOMOD_DUPLICATE_CLEANUP_REASON, AUTOMOD_MIGRATE_REASON,
    AUTOMOD_NO_KEYWORDS_REASON, AUTOMOD_SETUP_REASON, AutoModRuleClient, AutoModRuleKey,
    AutoModRuleSkipReason, AutoModRuleSpec, AutoModRuleTriggerType, CleanupOutcome,
    ExistingAutoModRule, ReconcileOutcome, ReconcileRequest, RuleRequest, RuleSwitch,
    RuleSyncStatus, build_rule_specs, cleanup_report, delete_foxsecura_rules, foxsecura_rules,
    reconcile_guild, reconcile_report, rule_for_module, toggle_report,
};
use foxsecura::protection::lockdown::GuildLocks;
use foxsecura::protection::quarantine::DiscordFailure;
use foxsecura::protection::shared::{ModuleSet, ProtectionModule};
use serde_json::Value;

const GUILD: u64 = 1;

#[derive(Debug, Clone, PartialEq)]
enum Call {
    List,
    Create {
        name: String,
        enabled: bool,
        reason: String,
    },
    Edit {
        rule_id: u64,
        payload: Value,
        reason: String,
    },
    Delete {
        rule_id: u64,
        reason: String,
    },
}

/// Faux Discord : règles en mémoire, appels enregistrés, échecs forcés.
#[derive(Default)]
struct FakeDiscord {
    rules: Mutex<Vec<ExistingAutoModRule>>,
    calls: Mutex<Vec<Call>>,
    /// Noms dont la création échoue, identifiants dont la modification ou la
    /// suppression échoue.
    failing_names: Mutex<HashSet<String>>,
    failing_ids: Mutex<HashSet<u64>>,
    fail_list: bool,
    next_id: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl FakeDiscord {
    fn with_rules(rules: Vec<ExistingAutoModRule>) -> Self {
        Self {
            rules: Mutex::new(rules),
            next_id: AtomicUsize::new(1000),
            ..Self::default()
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn rules(&self) -> Vec<ExistingAutoModRule> {
        self.rules.lock().unwrap().clone()
    }

    fn failure() -> DiscordFailure {
        DiscordFailure::new(Some(500), None, "boom")
    }

    /// Simule la latence réseau : rend la main au runtime, et mesure les
    /// appels concurrents sur la guilde.
    async fn network(&self) {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(current, Ordering::SeqCst);
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AutoModRuleClient for FakeDiscord {
    async fn list_rules(&self, _guild_id: u64) -> Result<Vec<ExistingAutoModRule>, DiscordFailure> {
        self.calls.lock().unwrap().push(Call::List);
        let snapshot = self.rules();
        self.network().await;
        if self.fail_list {
            return Err(Self::failure());
        }
        Ok(snapshot)
    }

    async fn create_rule(
        &self,
        _guild_id: u64,
        payload: &Value,
        reason: &str,
    ) -> Result<u64, DiscordFailure> {
        let name = payload["name"].as_str().unwrap().to_owned();
        let enabled = payload["enabled"].as_bool().unwrap();
        self.calls.lock().unwrap().push(Call::Create {
            name: name.clone(),
            enabled,
            reason: reason.to_owned(),
        });
        self.network().await;
        if self.failing_names.lock().unwrap().contains(&name) {
            return Err(Self::failure());
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u64;
        let trigger_type = foxsecura::protection::automod::native_rules::trigger_type_from_code(
            payload["trigger_type"].as_u64().unwrap() as u8,
        );
        self.rules
            .lock()
            .unwrap()
            .push(ExistingAutoModRule::new(id, name, trigger_type).with_enabled(enabled));
        Ok(id)
    }

    async fn edit_rule(
        &self,
        _guild_id: u64,
        rule_id: u64,
        payload: &Value,
        reason: &str,
    ) -> Result<(), DiscordFailure> {
        self.calls.lock().unwrap().push(Call::Edit {
            rule_id,
            payload: payload.clone(),
            reason: reason.to_owned(),
        });
        self.network().await;
        if self.failing_ids.lock().unwrap().contains(&rule_id) {
            return Err(Self::failure());
        }
        if let Some(rule) = self
            .rules
            .lock()
            .unwrap()
            .iter_mut()
            .find(|rule| rule.id == rule_id)
        {
            rule.name = payload["name"].as_str().unwrap().to_owned();
            rule.enabled = payload["enabled"].as_bool().unwrap();
        }
        Ok(())
    }

    async fn delete_rule(
        &self,
        _guild_id: u64,
        rule_id: u64,
        reason: &str,
    ) -> Result<(), DiscordFailure> {
        self.calls.lock().unwrap().push(Call::Delete {
            rule_id,
            reason: reason.to_owned(),
        });
        self.network().await;
        if self.failing_ids.lock().unwrap().contains(&rule_id) {
            return Err(Self::failure());
        }
        self.rules.lock().unwrap().retain(|rule| rule.id != rule_id);
        Ok(())
    }
}

fn spec_with(words: &[&str], key: AutoModRuleKey) -> AutoModRuleSpec {
    build_rule_specs(words)
        .into_iter()
        .find(|spec| spec.key == key)
        .unwrap()
}

fn spec(key: AutoModRuleKey) -> AutoModRuleSpec {
    spec_with(&["merde"], key)
}

fn request(rules: Vec<RuleRequest>, create_when_disabled: bool) -> ReconcileRequest {
    ReconcileRequest {
        guild_id: GUILD,
        rules,
        create_when_disabled,
        manage_guild: Some(true),
    }
}

fn reports(
    outcome: ReconcileOutcome,
) -> Vec<foxsecura::protection::automod::native_rules::RuleSyncReport> {
    match outcome {
        ReconcileOutcome::Synced(reports) => reports,
        other => panic!("synchronisation attendue : {other:?}"),
    }
}

#[tokio::test]
async fn duplicates_are_removed_before_the_primary_update() {
    let discord = FakeDiscord::with_rules(vec![
        ExistingAutoModRule::new(
            11,
            "FoxSecura • Invite Links",
            AutoModRuleTriggerType::Keyword,
        ),
        ExistingAutoModRule::new(
            10,
            AutoModRuleKey::InviteLinkBlocking.rule_name(),
            AutoModRuleTriggerType::Keyword,
        ),
    ]);
    let locks = GuildLocks::new();

    let outcome = reconcile_guild(
        &locks,
        &discord,
        request(
            vec![RuleRequest::new(
                spec(AutoModRuleKey::InviteLinkBlocking),
                true,
            )],
            false,
        ),
    )
    .await;

    let reports = reports(outcome);
    assert_eq!(reports[0].status, RuleSyncStatus::Updated { enabled: true });
    assert_eq!(reports[0].removed, 1);
    let calls = discord.calls();
    assert_eq!(calls[0], Call::List);
    assert_eq!(
        calls[1],
        Call::Delete {
            rule_id: 11,
            reason: AUTOMOD_DUPLICATE_CLEANUP_REASON.to_owned()
        }
    );
    let Call::Edit {
        rule_id,
        payload,
        reason,
    } = &calls[2]
    else {
        panic!("modification attendue : {calls:?}");
    };
    assert_eq!(*rule_id, 10);
    assert_eq!(reason, AUTOMOD_SETUP_REASON);
    assert!(payload.get("trigger_type").is_none());
    assert_eq!(calls.len(), 3);
}

#[tokio::test]
async fn trigger_migration_deletes_then_creates() {
    let discord = FakeDiscord::with_rules(vec![ExistingAutoModRule::new(
        10,
        AutoModRuleKey::MemberProfileFilter.rule_name(),
        AutoModRuleTriggerType::Keyword,
    )]);

    let outcome = reconcile_guild(
        &GuildLocks::new(),
        &discord,
        request(
            vec![RuleRequest::new(
                spec(AutoModRuleKey::MemberProfileFilter),
                true,
            )],
            false,
        ),
    )
    .await;

    assert_eq!(
        reports(outcome)[0].status,
        RuleSyncStatus::Created { enabled: true }
    );
    assert_eq!(
        discord.calls()[1..],
        [
            Call::Delete {
                rule_id: 10,
                reason: AUTOMOD_MIGRATE_REASON.to_owned()
            },
            Call::Create {
                name: AutoModRuleKey::MemberProfileFilter.rule_name().to_owned(),
                enabled: true,
                reason: AUTOMOD_MIGRATE_REASON.to_owned()
            },
        ]
    );
    assert_eq!(
        discord.rules()[0].trigger_type,
        AutoModRuleTriggerType::MemberProfile
    );
}

#[tokio::test]
async fn failed_migration_delete_does_not_create_a_duplicate() {
    let discord = FakeDiscord::with_rules(vec![ExistingAutoModRule::new(
        10,
        AutoModRuleKey::MemberProfileFilter.rule_name(),
        AutoModRuleTriggerType::Keyword,
    )]);
    discord.failing_ids.lock().unwrap().insert(10);

    let outcome = reconcile_guild(
        &GuildLocks::new(),
        &discord,
        request(
            vec![RuleRequest::new(
                spec(AutoModRuleKey::MemberProfileFilter),
                true,
            )],
            false,
        ),
    )
    .await;

    assert!(matches!(
        reports(outcome)[0].status,
        RuleSyncStatus::Failed(_)
    ));
    assert!(
        !discord
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Create { .. }))
    );
}

#[tokio::test]
async fn one_failed_rule_does_not_stop_the_others() {
    let discord = FakeDiscord::with_rules(Vec::new());
    discord
        .failing_names
        .lock()
        .unwrap()
        .insert(AutoModRuleKey::InviteLinkBlocking.rule_name().to_owned());
    let rules = AutoModRuleKey::ALL
        .into_iter()
        .map(|key| RuleRequest::new(spec(key), true))
        .collect();

    let reports =
        reports(reconcile_guild(&GuildLocks::new(), &discord, request(rules, true)).await);

    assert_eq!(reports.len(), 6);
    assert!(matches!(reports[0].status, RuleSyncStatus::Failed(_)));
    for report in &reports[1..] {
        assert_eq!(
            report.status,
            RuleSyncStatus::Created { enabled: true },
            "{:?}",
            report.key
        );
    }
    assert_eq!(discord.rules().len(), 5);
    // Ordre de la synchronisation : celui de `AutoModRuleKey::ALL`.
    let created: Vec<String> = discord
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Create { name, .. } => Some(name),
            _ => None,
        })
        .collect();
    let expected: Vec<String> = AutoModRuleKey::ALL
        .into_iter()
        .map(|key| key.rule_name().to_owned())
        .collect();
    assert_eq!(created, expected);
}

#[tokio::test]
async fn missing_manage_guild_makes_no_call() {
    let discord = FakeDiscord::with_rules(vec![ExistingAutoModRule::new(
        10,
        AutoModRuleKey::GenericSpamBlocking.rule_name(),
        AutoModRuleTriggerType::Spam,
    )]);
    let mut request = request(
        vec![RuleRequest::new(
            spec(AutoModRuleKey::GenericSpamBlocking),
            false,
        )],
        true,
    );
    request.manage_guild = Some(false);

    let outcome = reconcile_guild(&GuildLocks::new(), &discord, request).await;

    assert_eq!(outcome, ReconcileOutcome::MissingPermission);
    assert!(discord.calls().is_empty());
    assert_eq!(
        delete_foxsecura_rules(&GuildLocks::new(), &discord, GUILD, Some(false)).await,
        CleanupOutcome::MissingPermission
    );
    assert!(discord.calls().is_empty());
}

#[tokio::test]
async fn unreadable_rules_touch_nothing() {
    let discord = FakeDiscord {
        fail_list: true,
        ..FakeDiscord::default()
    };
    let outcome = reconcile_guild(
        &GuildLocks::new(),
        &discord,
        request(
            vec![RuleRequest::new(spec(AutoModRuleKey::BadWordsFilter), true)],
            true,
        ),
    )
    .await;
    assert!(matches!(outcome, ReconcileOutcome::ReadFailed(_)));
    assert_eq!(discord.calls(), vec![Call::List]);
}

#[tokio::test]
async fn disabled_toggle_does_not_create_but_sync_does() {
    let discord = FakeDiscord::with_rules(Vec::new());
    let locks = GuildLocks::new();
    let toggle = reconcile_guild(
        &locks,
        &discord,
        request(
            vec![RuleRequest::new(
                spec(AutoModRuleKey::AdultLinksFiltering),
                false,
            )],
            false,
        ),
    )
    .await;
    assert_eq!(reports(toggle)[0].status, RuleSyncStatus::Missing);
    assert_eq!(discord.calls(), vec![Call::List]);

    let sync = reconcile_guild(
        &locks,
        &discord,
        request(
            vec![RuleRequest::new(
                spec(AutoModRuleKey::AdultLinksFiltering),
                false,
            )],
            true,
        ),
    )
    .await;
    assert_eq!(
        reports(sync)[0].status,
        RuleSyncStatus::Created { enabled: false }
    );
    assert!(!discord.rules()[0].enabled);
}

#[tokio::test]
async fn empty_word_list_deletes_the_rule_with_its_reason() {
    let discord = FakeDiscord::with_rules(vec![ExistingAutoModRule::new(
        10,
        AutoModRuleKey::BadWordsFilter.rule_name(),
        AutoModRuleTriggerType::Keyword,
    )]);
    let outcome = reconcile_guild(
        &GuildLocks::new(),
        &discord,
        request(
            vec![RuleRequest::new(
                spec_with(&[], AutoModRuleKey::BadWordsFilter),
                true,
            )],
            true,
        ),
    )
    .await;

    let report = &reports(outcome)[0];
    assert_eq!(
        report.status,
        RuleSyncStatus::Skipped(AutoModRuleSkipReason::NoKeywords)
    );
    assert_eq!(report.removed, 1);
    assert_eq!(
        discord.calls()[1],
        Call::Delete {
            rule_id: 10,
            reason: AUTOMOD_NO_KEYWORDS_REASON.to_owned()
        }
    );
}

#[tokio::test]
async fn foreign_singleton_rule_is_left_alone() {
    let discord = FakeDiscord::with_rules(vec![ExistingAutoModRule::new(
        99,
        "Autre bot • Spam",
        AutoModRuleTriggerType::Spam,
    )]);
    let outcome = reconcile_guild(
        &GuildLocks::new(),
        &discord,
        request(
            vec![RuleRequest::new(
                spec(AutoModRuleKey::GenericSpamBlocking),
                true,
            )],
            true,
        ),
    )
    .await;

    assert_eq!(
        reports(outcome)[0].status,
        RuleSyncStatus::Skipped(AutoModRuleSkipReason::TriggerTypeConflict)
    );
    assert_eq!(discord.calls(), vec![Call::List]);
}

#[tokio::test]
async fn too_long_words_are_reported_and_left_out() {
    let long = "x".repeat(61);
    let discord = FakeDiscord::with_rules(Vec::new());
    let outcome = reconcile_guild(
        &GuildLocks::new(),
        &discord,
        request(
            vec![RuleRequest::new(
                spec_with(&["court", &long], AutoModRuleKey::BadWordsFilter),
                true,
            )],
            true,
        ),
    )
    .await;

    let report = &reports(outcome.clone())[0];
    assert_eq!(report.status, RuleSyncStatus::Created { enabled: true });
    assert_eq!(report.limits.too_long, vec![long]);
    let summary = toggle_report(Language::French, &outcome).expect("mots écartés signalés");
    assert!(summary.contains("plus de 60 caractères"));
}

/// Basculement et restauration concurrents : sans le verrou, les deux
/// liraient « absente » et créeraient chacun la règle.
#[tokio::test]
async fn guild_lock_prevents_interleaved_reconciliations() {
    let discord = FakeDiscord::with_rules(Vec::new());
    let locks = GuildLocks::new();
    let first = request(
        vec![RuleRequest::new(
            spec(AutoModRuleKey::InviteLinkBlocking),
            true,
        )],
        false,
    );
    let second = first.clone();

    let (a, b) = tokio::join!(
        reconcile_guild(&locks, &discord, first),
        reconcile_guild(&locks, &discord, second),
    );

    assert_eq!(
        reports(a)[0].status,
        RuleSyncStatus::Created { enabled: true }
    );
    assert_eq!(
        reports(b)[0].status,
        RuleSyncStatus::Updated { enabled: true }
    );
    assert_eq!(discord.rules().len(), 1);
    assert_eq!(discord.max_in_flight.load(Ordering::SeqCst), 1);
    assert!(locks.is_empty());
}

#[tokio::test]
async fn adopted_rule_is_renamed_back_and_enabled() {
    // Règle renommée puis désactivée par un modérateur.
    let discord = FakeDiscord::with_rules(vec![
        ExistingAutoModRule::new(10, "Ma règle", AutoModRuleTriggerType::Spam).with_enabled(false),
    ]);
    let mut rule = RuleRequest::new(spec(AutoModRuleKey::GenericSpamBlocking), true);
    rule.adopt_rule_id = Some(10);

    let outcome = reconcile_guild(&GuildLocks::new(), &discord, request(vec![rule], false)).await;

    assert_eq!(
        reports(outcome)[0].status,
        RuleSyncStatus::Updated { enabled: true }
    );
    let rules = discord.rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(
        rules[0].name,
        AutoModRuleKey::GenericSpamBlocking.rule_name()
    );
    assert!(rules[0].enabled);
}

#[tokio::test]
async fn owner_cleanup_only_deletes_prefixed_rules() {
    let discord = FakeDiscord::with_rules(vec![
        ExistingAutoModRule::new(
            1,
            AutoModRuleKey::BadWordsFilter.rule_name(),
            AutoModRuleTriggerType::Keyword,
        ),
        ExistingAutoModRule::new(
            2,
            "FoxSecura • Sexual Content",
            AutoModRuleTriggerType::KeywordPreset,
        ),
        ExistingAutoModRule::new(3, "Règle du staff", AutoModRuleTriggerType::Keyword),
        ExistingAutoModRule::new(4, "FoxSecura Spam", AutoModRuleTriggerType::Spam),
        ExistingAutoModRule::new(5, "foxsecura • minuscule", AutoModRuleTriggerType::Keyword),
    ]);
    assert_eq!(
        foxsecura_rules(&discord.rules())
            .iter()
            .map(|rule| rule.id)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );

    let outcome = delete_foxsecura_rules(&GuildLocks::new(), &discord, GUILD, Some(true)).await;

    assert_eq!(
        outcome,
        CleanupOutcome::Done {
            deleted: 2,
            failures: Vec::new()
        }
    );
    assert!(discord.calls().iter().all(|call| match call {
        Call::Delete { reason, .. } => reason == AUTOMOD_CLEANUP_REASON,
        _ => true,
    }));
    assert_eq!(
        discord
            .rules()
            .iter()
            .map(|rule| rule.id)
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
}

#[test]
fn cleanup_report_renders_discord_names_as_inline_code() {
    let report = cleanup_report(
        Language::English,
        &CleanupOutcome::Done {
            deleted: 1,
            failures: vec![(
                "FoxSecura • `@everyone` **x**".to_owned(),
                DiscordFailure::new(Some(403), None, "denied"),
            )],
        },
    );
    assert!(report.contains("FoxSecura rules deleted : 1"));
    assert!(!report.contains("`@everyone`"));
    assert!(report.contains("Not deleted : `"));
}

#[test]
fn rules_map_to_their_config_switch() {
    use AutoModRuleKey as Key;
    assert_eq!(
        Key::InviteLinkBlocking.switch(),
        RuleSwitch::Module(ProtectionModule::AntiInvite)
    );
    assert_eq!(
        Key::AdultLinksFiltering.switch(),
        RuleSwitch::Module(ProtectionModule::AdultLink)
    );
    assert_eq!(
        Key::BadWordsFilter.switch(),
        RuleSwitch::Module(ProtectionModule::BadWords)
    );
    assert_eq!(
        Key::MentionSpamBlocking.switch(),
        RuleSwitch::Module(ProtectionModule::AntiMassMention)
    );
    assert_eq!(Key::GenericSpamBlocking.switch(), RuleSwitch::AntiSpam);
    assert_eq!(
        Key::MemberProfileFilter.switch(),
        RuleSwitch::Module(ProtectionModule::MemberProfileFilter)
    );
    for key in Key::ALL {
        if let RuleSwitch::Module(module) = key.switch() {
            assert_eq!(rule_for_module(module), Some(key));
        }
    }
    assert_eq!(rule_for_module(ProtectionModule::MaliciousLink), None);
    assert_eq!(rule_for_module(ProtectionModule::AutoModRuleGuard), None);

    let modules: ModuleSet = [ProtectionModule::AntiInvite].into_iter().collect();
    assert!(Key::InviteLinkBlocking.is_switched_on(modules, false));
    assert!(!Key::BadWordsFilter.is_switched_on(modules, false));
    assert!(Key::GenericSpamBlocking.is_switched_on(ModuleSet::empty(), true));
    assert!(!Key::GenericSpamBlocking.is_switched_on(modules, false));
}

#[test]
fn sync_report_summarises_every_rule() {
    use foxsecura::protection::automod::native_rules::{KeywordLimitReport, RuleSyncReport};
    let report = |key, status| RuleSyncReport {
        key,
        status,
        removed: 0,
        failures: Vec::new(),
        limits: KeywordLimitReport::default(),
    };
    let outcome = ReconcileOutcome::Synced(vec![
        report(
            AutoModRuleKey::InviteLinkBlocking,
            RuleSyncStatus::Created { enabled: true },
        ),
        report(
            AutoModRuleKey::BadWordsFilter,
            RuleSyncStatus::Updated { enabled: false },
        ),
        report(
            AutoModRuleKey::GenericSpamBlocking,
            RuleSyncStatus::Skipped(AutoModRuleSkipReason::TriggerTypeConflict),
        ),
    ]);
    let text = reconcile_report(Language::French, &outcome);
    assert!(text.starts_with("**Synchronisation AutoMod**"));
    assert!(text.contains("`FoxSecura • Invite Link Blocking` : créée"));
    assert!(text.contains("`FoxSecura • Bad Words Filter` : désactivée"));
    assert!(text.contains("`FoxSecura • Spam Blocking` : ignorée : une règle de ce type unique"));
    // Un basculement réussi reste silencieux ; une règle ignorée est signalée.
    assert!(toggle_report(Language::French, &outcome).is_some());
    let quiet = ReconcileOutcome::Synced(vec![report(
        AutoModRuleKey::InviteLinkBlocking,
        RuleSyncStatus::Missing,
    )]);
    assert_eq!(toggle_report(Language::French, &quiet), None);
    assert!(
        reconcile_report(Language::English, &ReconcileOutcome::MissingPermission)
            .contains("Manage Server")
    );
}
