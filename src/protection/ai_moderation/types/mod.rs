// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Vocabulaire stable partagé par les composants AI Moderation.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiModerationCategory {
    Toxicity,
    Insults,
    Cyberbullying,
    TargetedHarassment,
    Threats,
    Intimidation,
    HateSpeech,
    SexualContent,
    SexualExplicit,
    SexualSolicitation,
    Doxxing,
    DangerousBehavior,
    OtherHarmful,
}

impl AiModerationCategory {
    pub const ALL: [Self; 13] = [
        Self::Toxicity,
        Self::Insults,
        Self::Cyberbullying,
        Self::TargetedHarassment,
        Self::Threats,
        Self::Intimidation,
        Self::HateSpeech,
        Self::SexualContent,
        Self::SexualExplicit,
        Self::SexualSolicitation,
        Self::Doxxing,
        Self::DangerousBehavior,
        Self::OtherHarmful,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Toxicity => "TOXICITY",
            Self::Insults => "INSULTS",
            Self::Cyberbullying => "CYBERBULLYING",
            Self::TargetedHarassment => "TARGETED_HARASSMENT",
            Self::Threats => "THREATS",
            Self::Intimidation => "INTIMIDATION",
            Self::HateSpeech => "HATE_SPEECH",
            Self::SexualContent => "SEXUAL_CONTENT",
            Self::SexualExplicit => "SEXUAL_EXPLICIT",
            Self::SexualSolicitation => "SEXUAL_SOLICITATION",
            Self::Doxxing => "DOXXING",
            Self::DangerousBehavior => "DANGEROUS_BEHAVIOR",
            Self::OtherHarmful => "OTHER_HARMFUL",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|category| category.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AiSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AiSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiRecommendedAction {
    None,
    Log,
    Warn,
    Delete,
    DeleteWarn,
    Escalate,
}

impl AiRecommendedAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Log => "LOG",
            Self::Warn => "WARN",
            Self::Delete => "DELETE",
            Self::DeleteWarn => "DELETE_WARN",
            Self::Escalate => "ESCALATE",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "NONE" => Some(Self::None),
            "LOG" => Some(Self::Log),
            "WARN" => Some(Self::Warn),
            "DELETE" => Some(Self::Delete),
            "DELETE_WARN" => Some(Self::DeleteWarn),
            "ESCALATE" => Some(Self::Escalate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiClassification {
    pub violation: bool,
    pub categories: Vec<AiModerationCategory>,
    pub severity: AiSeverity,
    pub recommended_action: Option<AiRecommendedAction>,
    pub reason: Option<String>,
}

impl AiClassification {
    pub fn clean(reason: Option<String>) -> Self {
        Self {
            violation: false,
            categories: Vec::new(),
            severity: AiSeverity::Low,
            recommended_action: Some(AiRecommendedAction::None),
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiSafetyTaxonomy {
    OpenAiModeration,
}

impl AiSafetyTaxonomy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiModeration => "openai-moderation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiSafetyVerdict {
    pub taxonomy: AiSafetyTaxonomy,
    pub unsafe_content: bool,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiProviderVerdict {
    PolicyClassification(AiClassification),
    SafetyVerdict(AiSafetyVerdict),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiSkipReason {
    Disabled,
    NoCategoriesEnabled,
    NotConfigured,
    IgnoredChannel,
    IgnoredRole,
    AuthorExempt,
    Prefiltered,
    QueueFull,
    CircuitOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiFailureReason {
    Timeout,
    TransportError,
    ProviderError,
    RateLimited,
    EmptyResponse,
    InvalidJson,
    SchemaViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AiMessageSnapshot {
    pub message_id: String,
    pub author_id: String,
    pub author_label: String,
    pub content: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AiAnalysisRequest {
    pub guild_id: String,
    pub channel_id: String,
    pub revision_id: Option<String>,
    pub message: AiMessageSnapshot,
    pub recent_messages: Vec<AiMessageSnapshot>,
    pub target_user_id: Option<String>,
    pub enabled_categories: Vec<AiModerationCategory>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiAnalysisOutcome {
    Classified {
        classification: AiClassification,
        model: String,
        latency_ms: u64,
    },
    Skipped {
        reason: AiSkipReason,
    },
    Failed {
        reason: AiFailureReason,
        model: String,
    },
}
