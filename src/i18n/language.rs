// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    English,
    French,
    German,
}

pub const DEFAULT_LANGUAGE: Language = Language::French;
pub const SUPPORTED_LANGUAGES: &[Language] = &[
    Language::English,
    Language::French,
    Language::German,
];

impl Language {
    pub const fn code(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::French => "fr",
            Self::German => "de",
        }
    }

    pub const fn native_name(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::French => "Français",
            Self::German => "Deutsch",
        }
    }

    pub fn from_locale(locale: &str) -> Option<Self> {
        let primary = locale
            .split(|character| character == '-' || character == '_')
            .next()?
            .to_ascii_lowercase();

        match primary.as_str() {
            "en" => Some(Self::English),
            "fr" => Some(Self::French),
            "de" => Some(Self::German),
            _ => None,
        }
    }

    pub fn resolve(locale: Option<&str>) -> Self {
        locale
            .and_then(Self::from_locale)
            .unwrap_or(DEFAULT_LANGUAGE)
    }
}
