// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::shared::{ProtectionDecision, UrlSignal, extract_url_signals, host_matches};

const ADULT_HOST_LABELS: &[&str] = &[
    "pornhub",
    "xvideos",
    "xnxx",
    "redtube",
    "youporn",
    "xhamster",
    "spankbang",
    "tube8",
    "tnaflix",
    "erome",
    "rule34",
    "nhentai",
    "hanime",
    "hentaihaven",
    "onlyfans",
    "fansly",
    "chaturbate",
    "stripchat",
    "bongacams",
    "cam4",
    "manyvids",
    "clips4sale",
    "livejasmin",
    "brazzers",
    "bangbros",
    "naughtyamerica",
    "porn",
    "sex",
];

const ADULT_TLDS: &[&str] = &["adult", "porn", "sex", "xxx"];

const COMPOUND_ADULT_MARKERS: &[&str] = &[
    "pornhub",
    "porntube",
    "pornvideo",
    "pornvideos",
    "pornclip",
    "pornclips",
    "pornpic",
    "pornpics",
    "pornhd",
    "pornsite",
    "pornstar",
    "pornstars",
    "sextube",
    "sexcam",
    "sexcams",
    "sexchat",
    "sexvideo",
    "sexvideos",
    "hentaihaven",
    "hentaitube",
    "hentaivideo",
    "hentaivideos",
    "xxxvideo",
    "xxxvideos",
    "xxxtube",
    "xxxpic",
    "xxxpics",
];

const ADULT_PATH_TOKENS: &[&str] = &[
    "porn",
    "porno",
    "xxx",
    "nsfw",
    "hentai",
    "nude",
    "nudes",
    "onlyfans",
    "fansly",
    "erome",
    "camgirl",
    "camgirls",
    "webcam",
    "webcams",
    "sexcam",
    "sexcams",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdultLinkDetectionResult {
    pub decision: ProtectionDecision,
    pub matched_domain: Option<String>,
}

pub fn detect_adult_link(content: &str) -> AdultLinkDetectionResult {
    let matched = extract_url_signals(content)
        .into_iter()
        .find(is_adult_url_signal);

    AdultLinkDetectionResult {
        decision: if matched.is_some() {
            ProtectionDecision::Block
        } else {
            ProtectionDecision::Allow
        },
        matched_domain: matched.map(|signal| signal.hostname),
    }
}

fn is_adult_url_signal(signal: &UrlSignal) -> bool {
    has_known_adult_domain(&signal.hostname)
        || has_known_adult_host_label(&signal.hostname)
        || has_adult_top_level_domain(&signal.hostname)
        || has_adult_host_tokens(&signal.hostname)
        || has_adult_path_signal(signal)
}

fn has_known_adult_domain(hostname: &str) -> bool {
    [
        "pornhub.com",
        "xvideos.com",
        "xnxx.com",
        "redtube.com",
        "youporn.com",
        "onlyfans.com",
        "fansly.com",
        "chaturbate.com",
        "stripchat.com",
    ]
    .iter()
    .any(|domain| host_matches(hostname, domain))
}

fn has_known_adult_host_label(hostname: &str) -> bool {
    hostname
        .split('.')
        .any(|label| ADULT_HOST_LABELS.contains(&label))
}

fn has_adult_top_level_domain(hostname: &str) -> bool {
    hostname
        .rsplit('.')
        .next()
        .is_some_and(|tld| ADULT_TLDS.contains(&tld))
}

fn has_adult_host_tokens(hostname: &str) -> bool {
    hostname
        .split('.')
        .flat_map(|label| label.split('-'))
        .any(|token| {
            ADULT_HOST_LABELS.contains(&token)
                || (!token.starts_with("not")
                    && COMPOUND_ADULT_MARKERS
                        .iter()
                        .any(|marker| token.contains(marker)))
        })
}

fn has_adult_path_signal(signal: &UrlSignal) -> bool {
    signal
        .path
        .to_ascii_lowercase()
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(|token| ADULT_PATH_TOKENS.contains(&token))
}
