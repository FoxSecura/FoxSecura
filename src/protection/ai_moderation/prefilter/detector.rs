// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

pub const MAX_ANALYZABLE_LENGTH: usize = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefilterVerdict {
    Analyze,
    Skip,
}

pub fn prefilter_message(content: &str) -> PrefilterVerdict {
    let trimmed = content.trim();

    if trimmed.is_empty() || trimmed.chars().count() > MAX_ANALYZABLE_LENGTH {
        return PrefilterVerdict::Skip;
    }

    if is_entirely_non_textual(trimmed) {
        return PrefilterVerdict::Skip;
    }

    PrefilterVerdict::Analyze
}

fn is_entirely_non_textual(content: &str) -> bool {
    let mut offset = 0;

    while offset < content.len() {
        let rest = &content[offset..];
        let character = rest.chars().next().expect("offset must stay on a character boundary");

        if character.is_whitespace() {
            offset += character.len_utf8();
            continue;
        }

        if let Some(length) = discord_markup_length(rest) {
            offset += length;
            continue;
        }

        if rest.starts_with("https://") || rest.starts_with("http://") {
            offset += rest.find(char::is_whitespace).unwrap_or(rest.len());
            continue;
        }

        if is_emoji_component(character) {
            offset += character.len_utf8();
            continue;
        }

        return false;
    }

    true
}

fn discord_markup_length(input: &str) -> Option<usize> {
    if !input.starts_with('<') {
        return None;
    }

    let end = input.find('>')?;
    let inner = &input[1..end];

    if is_mention(inner) || is_custom_emoji(inner) {
        Some(end + 1)
    } else {
        None
    }
}

fn is_mention(inner: &str) -> bool {
    if let Some(id) = inner.strip_prefix('#') {
        return is_snowflake(id);
    }

    let Some(user_or_role) = inner.strip_prefix('@') else {
        return false;
    };

    let id = user_or_role
        .strip_prefix('!')
        .or_else(|| user_or_role.strip_prefix('&'))
        .unwrap_or(user_or_role);

    is_snowflake(id)
}

fn is_custom_emoji(inner: &str) -> bool {
    let inner = inner.strip_prefix("a:").or_else(|| inner.strip_prefix(':'));
    let Some(inner) = inner else {
        return false;
    };

    let Some((name, id)) = inner.rsplit_once(':') else {
        return false;
    };

    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        && is_snowflake(id)
}

fn is_snowflake(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|character| character.is_ascii_digit())
}

fn is_emoji_component(character: char) -> bool {
    matches!(
        character as u32,
        0x200D
            | 0x20E3
            | 0xFE0E..=0xFE0F
            | 0x2600..=0x27BF
            | 0x1F1E6..=0x1F1FF
            | 0x1F300..=0x1FAFF
            | 0x1F3FB..=0x1F3FF
    )
}
