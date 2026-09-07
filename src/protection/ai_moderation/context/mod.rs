// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};

use super::AiMessageSnapshot;

pub const MAX_CONTEXT_MESSAGES: usize = 8;
pub const CONTEXT_WINDOW_MS: u64 = 10 * 60 * 1_000;
pub const MAX_SNAPSHOT_LENGTH: usize = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MentionCandidate {
    pub user_id: String,
    pub is_bot: bool,
}

pub fn truncate_snapshot_content(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.chars().count() <= MAX_SNAPSHOT_LENGTH {
        return trimmed.to_owned();
    }

    let shortened: String = trimmed.chars().take(MAX_SNAPSHOT_LENGTH).collect();
    format!("{shortened}...")
}

pub fn resolve_target_user_id(
    current_author_id: &str,
    replied_to_author_id: Option<&str>,
    mentions: &[MentionCandidate],
) -> Option<String> {
    if let Some(author_id) = replied_to_author_id {
        if author_id != current_author_id {
            return Some(author_id.to_owned());
        }
    }

    let mut candidates = mentions
        .iter()
        .filter(|candidate| !candidate.is_bot && candidate.user_id != current_author_id);
    let first = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }

    Some(first.user_id.clone())
}

pub fn collect_relevant_context(
    current: &AiMessageSnapshot,
    candidates: &[AiMessageSnapshot],
    target_user_id: Option<&str>,
    now_ms: u64,
) -> Vec<AiMessageSnapshot> {
    let mut participants = HashSet::from([current.author_id.as_str()]);
    if let Some(target) = target_user_id {
        participants.insert(target);
    }

    let mut relevant: Vec<AiMessageSnapshot> = candidates
        .iter()
        .filter(|candidate| {
            candidate.message_id != current.message_id
                && participants.contains(candidate.author_id.as_str())
                && !candidate.content.trim().is_empty()
                && candidate.created_at_ms <= now_ms
                && now_ms - candidate.created_at_ms <= CONTEXT_WINDOW_MS
        })
        .cloned()
        .collect();

    relevant.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.created_at_ms));
    relevant.truncate(MAX_CONTEXT_MESSAGES);
    relevant.sort_by_key(|snapshot| snapshot.created_at_ms);
    relevant
}

pub fn render_analysis_prompt(
    current: &AiMessageSnapshot,
    recent_messages: &[AiMessageSnapshot],
    target_user_id: Option<&str>,
) -> String {
    let mut aliases = HashMap::<String, String>::new();
    aliases.insert(current.author_id.clone(), "AUTHOR".to_owned());

    fn alias_for(aliases: &mut HashMap<String, String>, author_id: &str) -> String {
        if let Some(alias) = aliases.get(author_id) {
            return alias.clone();
        }
        let alias = format!("USER_{}", aliases.len());
        aliases.insert(author_id.to_owned(), alias.clone());
        alias
    }

    let target = target_user_id
        .map(|id| alias_for(&mut aliases, id))
        .unwrap_or_else(|| "none identified".to_owned());

    let history = recent_messages
        .iter()
        .map(|snapshot| {
            format!(
                "{}: {}",
                alias_for(&mut aliases, &snapshot.author_id),
                snapshot.content
            )
        })
        .collect::<Vec<_>>();

    let mut lines = vec![format!("APPARENT TARGET: {target}"), String::new()];
    if history.is_empty() {
        lines.push("RECENT CONTEXT: none".to_owned());
    } else {
        lines.push("RECENT CONTEXT (oldest first, do not classify):".to_owned());
        lines.extend(history);
    }
    lines.push(String::new());
    lines.push("CURRENT MESSAGE (classify only this):".to_owned());
    lines.push(format!("AUTHOR: {}", current.content));
    lines.join("\n")
}
