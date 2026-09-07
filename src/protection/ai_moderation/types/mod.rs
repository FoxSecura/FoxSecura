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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiClassification {
    pub violation: bool,
    pub categories: Vec<AiModerationCategory>,
    pub severity: AiSeverity,
    pub recommended_action: Option<AiRecommendedAction>,
    pub reason: Option<String>,
}
