// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSignal {
    pub raw: String,
    pub hostname: String,
    pub path: String,
    pub has_credentials: bool,
}

impl UrlSignal {
    pub fn searchable(&self) -> String {
        format!("{}{}", self.hostname, self.path).to_ascii_lowercase()
    }
}

pub fn extract_url_signals(content: &str) -> Vec<UrlSignal> {
    content
        .split_whitespace()
        .filter_map(parse_url_signal)
        .collect()
}

pub fn host_matches(hostname: &str, domain: &str) -> bool {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_matches('.').to_ascii_lowercase();

    hostname == domain
        || hostname
            .strip_suffix(&domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn parse_url_signal(token: &str) -> Option<UrlSignal> {
    let candidate = isolate_candidate(token).trim_matches(is_surrounding_punctuation);
    if candidate.is_empty() {
        return None;
    }

    let lower = candidate.to_ascii_lowercase();
    let without_scheme = if lower.starts_with("https://") {
        &candidate[8..]
    } else if lower.starts_with("http://") {
        &candidate[7..]
    } else {
        candidate
    };

    let authority_end = without_scheme
        .find(|character: char| matches!(character, '/' | '?' | '#'))
        .unwrap_or(without_scheme.len());
    let authority = &without_scheme[..authority_end];
    let has_credentials = authority.contains('@');
    let host_with_port = authority.rsplit('@').next().unwrap_or(authority);
    let hostname = host_with_port
        .split(':')
        .next()
        .unwrap_or(host_with_port)
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if !is_host_like(&hostname) {
        return None;
    }

    Some(UrlSignal {
        raw: candidate.to_owned(),
        hostname,
        path: without_scheme[authority_end..].to_owned(),
        has_credentials,
    })
}

fn isolate_candidate(token: &str) -> &str {
    let lower = token.to_ascii_lowercase();
    let https = lower.find("https://");
    let http = lower.find("http://");

    let scheme_start = match (https, http) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(index), None) | (None, Some(index)) => Some(index),
        (None, None) => None,
    };

    if let Some(index) = scheme_start {
        return &token[index..];
    }

    if let Some(index) = token.rfind('(') {
        let suffix = &token[index + 1..];
        if suffix.contains('.') {
            return suffix;
        }
    }

    token
}

fn is_surrounding_punctuation(character: char) -> bool {
    matches!(
        character,
        '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '!' | '?' | ':' | '.'
    )
}

fn is_host_like(hostname: &str) -> bool {
    hostname.contains('.')
        && hostname.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
        })
}
