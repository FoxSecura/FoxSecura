// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use crate::protection::automod::{
    anti_invite::INVITE_PATTERNS,
    member_profile::profile_filter_keywords,
};

pub const AUTOMOD_RULE_PREFIX: &str = "FoxSecura •";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoModRuleKey {
    InviteLinkBlocking,
    AdultLinksFiltering,
    BadWordsFilter,
    MentionSpamBlocking,
    GenericSpamBlocking,
    MemberProfileFilter,
}

impl AutoModRuleKey {
    pub const fn config_key(self) -> &'static str {
        match self {
            Self::InviteLinkBlocking => "antiInviteEnabled",
            Self::AdultLinksFiltering => "adultLinkFilterEnabled",
            Self::BadWordsFilter => "badWordsFilterEnabled",
            Self::MentionSpamBlocking => "antiMassMentionEnabled",
            Self::GenericSpamBlocking => "antiSpamEnabled",
            Self::MemberProfileFilter => "memberProfileFilterEnabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoModRuleTriggerType {
    Keyword,
    KeywordPreset,
    Spam,
    MentionSpam,
    MemberProfile,
}

impl AutoModRuleTriggerType {
    pub const fn is_singleton(self) -> bool {
        matches!(
            self,
            Self::KeywordPreset | Self::Spam | Self::MentionSpam | Self::MemberProfile
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeywordPreset {
    SexualContent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoModRuleTriggerMetadata {
    None,
    KeywordFilter(Vec<String>),
    KeywordPreset(Vec<KeywordPreset>),
    MentionSpam {
        total_limit: u8,
        raid_protection_enabled: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoModEventType {
    MessageSend,
    MemberUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoModActionType {
    BlockMessage,
    BlockMemberInteraction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoModRuleSkipReason {
    NoKeywords,
    KeywordPresetConflict,
    TriggerTypeConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoModRuleSpec {
    pub key: AutoModRuleKey,
    pub label: &'static str,
    pub name: &'static str,
    pub trigger_type: AutoModRuleTriggerType,
    pub trigger_metadata: AutoModRuleTriggerMetadata,
    pub legacy_names: &'static [&'static str],
}

impl AutoModRuleSpec {
    pub const fn event_type(&self) -> AutoModEventType {
        if matches!(self.trigger_type, AutoModRuleTriggerType::MemberProfile) {
            AutoModEventType::MemberUpdate
        } else {
            AutoModEventType::MessageSend
        }
    }

    pub const fn action_type(&self) -> AutoModActionType {
        if matches!(self.trigger_type, AutoModRuleTriggerType::MemberProfile) {
            AutoModActionType::BlockMemberInteraction
        } else {
            AutoModActionType::BlockMessage
        }
    }

    pub fn is_empty_keyword_spec(&self) -> bool {
        matches!(
            (&self.trigger_type, &self.trigger_metadata),
            (
                AutoModRuleTriggerType::Keyword,
                AutoModRuleTriggerMetadata::KeywordFilter(words)
            ) if words.is_empty()
        )
    }
}

pub fn build_rule_specs<I, S>(blocked_words: I) -> Vec<AutoModRuleSpec>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let blocked_words = normalize_words(blocked_words);

    vec![
        AutoModRuleSpec {
            key: AutoModRuleKey::InviteLinkBlocking,
            label: "Invite Link Blocking",
            name: "FoxSecura • Invite Link Blocking",
            trigger_type: AutoModRuleTriggerType::Keyword,
            trigger_metadata: AutoModRuleTriggerMetadata::KeywordFilter(
                INVITE_PATTERNS.iter().map(|pattern| (*pattern).to_owned()).collect(),
            ),
            legacy_names: &["FoxSecura • Invite Links"],
        },
        AutoModRuleSpec {
            key: AutoModRuleKey::AdultLinksFiltering,
            label: "Adult Links Filtering",
            name: "FoxSecura • Adult Links Filtering",
            trigger_type: AutoModRuleTriggerType::KeywordPreset,
            trigger_metadata: AutoModRuleTriggerMetadata::KeywordPreset(vec![
                KeywordPreset::SexualContent,
            ]),
            legacy_names: &["FoxSecura • Sexual Content"],
        },
        AutoModRuleSpec {
            key: AutoModRuleKey::BadWordsFilter,
            label: "Bad Words Filter",
            name: "FoxSecura • Bad Words Filter",
            trigger_type: AutoModRuleTriggerType::Keyword,
            trigger_metadata: AutoModRuleTriggerMetadata::KeywordFilter(blocked_words),
            legacy_names: &["FoxSecura • Bad Words"],
        },
        AutoModRuleSpec {
            key: AutoModRuleKey::MentionSpamBlocking,
            label: "Mention Spam Blocking",
            name: "FoxSecura • Mention Spam Blocking",
            trigger_type: AutoModRuleTriggerType::MentionSpam,
            trigger_metadata: AutoModRuleTriggerMetadata::MentionSpam {
                total_limit: 5,
                raid_protection_enabled: true,
            },
            legacy_names: &[],
        },
        AutoModRuleSpec {
            key: AutoModRuleKey::GenericSpamBlocking,
            label: "Spam Blocking",
            name: "FoxSecura • Spam Blocking",
            trigger_type: AutoModRuleTriggerType::Spam,
            trigger_metadata: AutoModRuleTriggerMetadata::None,
            legacy_names: &[],
        },
        AutoModRuleSpec {
            key: AutoModRuleKey::MemberProfileFilter,
            label: "Member Profile Filter",
            name: "FoxSecura • Member Profile Filter",
            trigger_type: AutoModRuleTriggerType::MemberProfile,
            trigger_metadata: AutoModRuleTriggerMetadata::KeywordFilter(profile_filter_keywords()),
            legacy_names: &[],
        },
    ]
}

pub fn rule_name_matches_spec(name: &str, spec: &AutoModRuleSpec) -> bool {
    name == spec.name || spec.legacy_names.contains(&name)
}

fn normalize_words<I, S>(words: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut normalized_words = Vec::new();

    for word in words {
        let word = word.as_ref().trim();
        if word.is_empty() {
            continue;
        }

        let normalized = word.to_lowercase();
        if seen.insert(normalized) {
            normalized_words.push(word.to_owned());
        }
    }

    normalized_words
}
