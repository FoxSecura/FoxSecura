// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Correspondance règle native → interrupteur de `/config` (V1
//! `AUTOMOD_CONFIG_KEYS`), sans effet Discord.

use crate::protection::shared::{ModuleSet, ProtectionModule};

use super::spec::AutoModRuleKey;

/// Interrupteur qui active une règle native.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSwitch {
    /// Module de `guild_protection_modules`.
    Module(ProtectionModule),
    /// Anti-spam par rafales (colonnes `anti_spam_*` de `guild_configs`).
    AntiSpam,
}

impl AutoModRuleKey {
    /// Interrupteur lié à la règle.
    pub const fn switch(self) -> RuleSwitch {
        match self {
            Self::InviteLinkBlocking => RuleSwitch::Module(ProtectionModule::AntiInvite),
            Self::AdultLinksFiltering => RuleSwitch::Module(ProtectionModule::AdultLink),
            Self::BadWordsFilter => RuleSwitch::Module(ProtectionModule::BadWords),
            Self::MentionSpamBlocking => RuleSwitch::Module(ProtectionModule::AntiMassMention),
            Self::GenericSpamBlocking => RuleSwitch::AntiSpam,
            Self::MemberProfileFilter => RuleSwitch::Module(ProtectionModule::MemberProfileFilter),
        }
    }

    /// La règle doit-elle être active d'après la configuration ?
    pub const fn is_switched_on(self, modules: ModuleSet, anti_spam_enabled: bool) -> bool {
        match self.switch() {
            RuleSwitch::Module(module) => modules.contains(module),
            RuleSwitch::AntiSpam => anti_spam_enabled,
        }
    }
}

/// Règle liée à un module ; `None` si le module n'a pas de règle native.
pub fn rule_for_module(module: ProtectionModule) -> Option<AutoModRuleKey> {
    AutoModRuleKey::ALL
        .into_iter()
        .find(|key| key.switch() == RuleSwitch::Module(module))
}
