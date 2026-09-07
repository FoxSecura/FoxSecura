// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiEveryoneDetectionResult {
    pub triggered: bool,
    pub reason: &'static str,
}

pub fn detect_everyone_mention(
    content: &str,
    mentions_everyone: Option<bool>,
) -> AntiEveryoneDetectionResult {
    let triggered = mentions_everyone.unwrap_or_else(|| contains_broadcast_mention(content));

    AntiEveryoneDetectionResult {
        triggered,
        reason: if triggered {
            "Broadcast mention abuse detected"
        } else {
            "No broadcast mention detected"
        },
    }
}

fn contains_broadcast_mention(content: &str) -> bool {
    let lower = content.to_lowercase();
    ["@everyone", "@here"]
        .into_iter()
        .any(|marker| contains_marker(&lower, marker))
}

fn contains_marker(content: &str, marker: &str) -> bool {
    let mut offset = 0;

    while let Some(relative) = content[offset..].find(marker) {
        let start = offset + relative;
        let end = start + marker.len();
        let before = content[..start].chars().next_back();
        let after = content[end..].chars().next();
        let before_ok = before.is_none_or(|character| !is_word_character(character));
        let after_ok = after.is_none_or(|character| !is_word_character(character));

        if before_ok && after_ok {
            return true;
        }

        offset = end;
    }

    false
}

fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}
