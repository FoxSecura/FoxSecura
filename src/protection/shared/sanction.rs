// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Sanctions d'un membre (timeout, expulsion, ban) : décision et classement
//! des échecs, sans effet Discord.
//!
//! Le runtime relève l'état du cache ([`SanctionContext`]), demande à
//! [`precheck_sanction`] s'il faut appeler Discord, puis classe la réponse de
//! l'API avec [`classify_sanction_http_failure`]. Aucune sanction n'est jamais
//! tentée contre :
//!
//! - le propriétaire du serveur, ni le bot lui-même ;
//! - un auteur de la liste blanche (décidé en amont par la portée du message :
//!   l'incident porte alors l'action `ignore_exempt_member`).
//!
//! Les vérifications faites d'après le cache (permission, hiérarchie,
//! administrateur non « timeoutable ») évitent des `403` en rafale : Discord
//! limite le volume de requêtes invalides d'un bot.
//!
//! # Raison d'audit log
//!
//! Toute raison d'audit log posée par FoxSecura commence par
//! [`AUDIT_REASON_PREFIX`] (`FoxSecura Anti-Scam: …`). Un futur anti-nuke
//! pourra ainsi reconnaître, avec [`is_foxsecura_audit_reason`], les
//! sanctions du bot lui-même et ne pas les compter comme une attaque. Cette
//! convention ne doit pas changer sans migrer ce contrôle.

use std::time::Duration;

use crate::logs::{ActionCode, ActionStatus, FailureCode, SecurityActionOutcome};

/// Préfixe de toute raison d'audit log posée par FoxSecura.
pub const AUDIT_REASON_PREFIX: &str = "FoxSecura";

/// Longueur maximale d'une raison d'audit log acceptée par Discord, en
/// caractères.
pub const AUDIT_REASON_MAX_CHARS: usize = 512;

/// Durée maximale d'un timeout Discord (28 jours).
pub const MAX_TIMEOUT: Duration = Duration::from_secs(28 * 24 * 60 * 60);

/// Purge maximale des messages lors d'un ban (7 jours).
pub const MAX_BAN_PURGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Sanction à appliquer à un membre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanctionKind {
    /// Exclusion temporaire (`communication_disabled_until`).
    Timeout { duration: Duration },
    /// Expulsion : le membre peut revenir avec une invitation.
    Kick,
    /// Bannissement, avec purge des messages récents (7 jours au plus).
    Ban { purge: Duration },
}

impl SanctionKind {
    pub const fn action_code(self) -> ActionCode {
        match self {
            Self::Timeout { .. } => ActionCode::TimeoutMember,
            Self::Kick => ActionCode::KickMember,
            Self::Ban { .. } => ActionCode::BanMember,
        }
    }

    /// Permission Discord exigée (au niveau du serveur).
    pub const fn required_permission(self) -> SanctionPermission {
        match self {
            Self::Timeout { .. } => SanctionPermission::ModerateMembers,
            Self::Kick => SanctionPermission::KickMembers,
            Self::Ban { .. } => SanctionPermission::BanMembers,
        }
    }

    /// Durée du timeout, bornée à 28 jours.
    pub fn timeout_duration(self) -> Option<Duration> {
        match self {
            Self::Timeout { duration } => Some(duration.min(MAX_TIMEOUT)),
            Self::Kick | Self::Ban { .. } => None,
        }
    }

    /// Jours de messages purgés par un ban, bornés à 7 (paramètre de l'API).
    pub fn ban_purge_days(self) -> Option<u8> {
        match self {
            Self::Ban { purge } => {
                Some((purge.min(MAX_BAN_PURGE).as_secs() / (24 * 60 * 60)) as u8)
            }
            Self::Timeout { .. } | Self::Kick => None,
        }
    }
}

/// Permission Discord nécessaire à une sanction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanctionPermission {
    ModerateMembers,
    KickMembers,
    BanMembers,
}

impl SanctionPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModerateMembers => "MODERATE_MEMBERS",
            Self::KickMembers => "KICK_MEMBERS",
            Self::BanMembers => "BAN_MEMBERS",
        }
    }
}

/// Permissions du bot dans le serveur, d'après le cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BotPermissions {
    pub administrator: bool,
    pub moderate_members: bool,
    pub kick_members: bool,
    pub ban_members: bool,
}

impl BotPermissions {
    pub const fn allows(self, permission: SanctionPermission) -> bool {
        self.administrator
            || match permission {
                SanctionPermission::ModerateMembers => self.moderate_members,
                SanctionPermission::KickMembers => self.kick_members,
                SanctionPermission::BanMembers => self.ban_members,
            }
    }
}

/// Position du bot dans le serveur, d'après le cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotStanding {
    /// Position de son rôle le plus haut (0 : seulement `@everyone`).
    pub top_role_position: u16,
    pub permissions: BotPermissions,
}

/// Position du membre visé, d'après ses rôles et le cache des rôles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetStanding {
    /// Position de son rôle le plus haut ; `None` si les rôles du serveur ne
    /// sont pas en cache.
    pub top_role_position: Option<u16>,
    /// Le membre a `ADMINISTRATOR` ; `None` si inconnu.
    pub administrator: Option<bool>,
}

/// Résolution du membre visé : membre joint à l'événement, sinon lecture par
/// l'API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetLookup {
    Found(TargetStanding),
    /// Le membre n'est plus sur le serveur (`404 Unknown Member`).
    NotFound,
    /// La lecture a échoué pour une autre raison.
    Unavailable {
        details: String,
    },
}

/// Tout ce que le runtime sait avant d'appeler Discord.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanctionContext {
    pub target_id: u64,
    pub bot_id: u64,
    /// Propriétaire du serveur ; `None` si le serveur n'est pas en cache.
    /// Discord refuse de toute façon de sanctionner le propriétaire.
    pub owner_id: Option<u64>,
    /// `None` si le cache ne permet pas de conclure : l'appel est tenté et un
    /// refus est classé d'après la réponse HTTP.
    pub bot: Option<BotStanding>,
    pub target: TargetLookup,
}

/// Raison pour laquelle une sanction n'a pas été tentée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanctionSkip {
    /// Le propriétaire du serveur n'est jamais sanctionné.
    GuildOwner,
    /// Le bot ne se sanctionne jamais lui-même.
    BotItself,
    /// Le membre n'est plus sur le serveur.
    MemberMissing,
    /// Le membre n'a pas pu être résolu : la suppression n'est pas bloquée.
    MemberUnavailable { details: String },
    /// Le bot n'a pas la permission exigée.
    MissingPermission(SanctionPermission),
    /// Le membre est au-dessus ou au niveau du rôle le plus haut du bot.
    RoleHierarchy { target: u16, bot: u16 },
    /// Discord refuse le timeout d'un membre `ADMINISTRATOR`.
    AdministratorTimeout,
}

/// Résultat d'une sanction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanctionOutcome {
    Applied,
    /// Non tentée : garde de sécurité ou vérification d'après le cache.
    Skipped(SanctionSkip),
    /// Refusée ou échouée côté Discord.
    Failed {
        failure_code: FailureCode,
        details: String,
    },
}

impl SanctionOutcome {
    pub const fn is_applied(&self) -> bool {
        matches!(self, Self::Applied)
    }

    /// Résultat d'action journalisé dans l'incident.
    pub fn action_outcome(&self, kind: SanctionKind) -> SecurityActionOutcome {
        let (status, failure_code, details) = match self {
            Self::Applied => (ActionStatus::Success, None, None),
            Self::Skipped(skip) => {
                let (failure_code, details) = skip_details(skip);
                (ActionStatus::Skipped, failure_code, Some(details))
            }
            Self::Failed {
                failure_code,
                details,
            } => (
                ActionStatus::Failed,
                Some(*failure_code),
                Some(details.clone()),
            ),
        };

        SecurityActionOutcome {
            action: kind.action_code(),
            status,
            details,
            failure_code,
        }
    }
}

fn skip_details(skip: &SanctionSkip) -> (Option<FailureCode>, String) {
    match skip {
        SanctionSkip::GuildOwner => (None, "guild_owner".to_owned()),
        SanctionSkip::BotItself => (None, "bot_itself".to_owned()),
        SanctionSkip::MemberMissing => (
            Some(FailureCode::ResourceMissing),
            "member_missing".to_owned(),
        ),
        SanctionSkip::MemberUnavailable { details } => {
            (Some(FailureCode::DiscordUnavailable), details.clone())
        }
        SanctionSkip::MissingPermission(permission) => (
            Some(FailureCode::MissingPermission),
            permission.as_str().to_owned(),
        ),
        SanctionSkip::RoleHierarchy { target, bot } => (
            Some(FailureCode::RoleHierarchy),
            format!("target_top_role={target} bot_top_role={bot}"),
        ),
        SanctionSkip::AdministratorTimeout => (
            Some(FailureCode::RoleHierarchy),
            "administrator_cannot_be_timed_out".to_owned(),
        ),
    }
}

/// Action journalisée pour un auteur exempté : la sanction prévue n'est pas
/// appliquée, le message a tout de même été traité.
pub fn exempt_member_action() -> SecurityActionOutcome {
    SecurityActionOutcome {
        action: ActionCode::IgnoreExemptMember,
        status: ActionStatus::Skipped,
        details: Some("whitelist".to_owned()),
        failure_code: None,
    }
}

/// Décide, d'après le cache, s'il faut appeler Discord.
///
/// `Ok(())` : tenter la sanction. `Err(outcome)` : ne rien appeler.
///
/// Ordre : propriétaire → bot lui-même → résolution du membre → permission
/// → administrateur (timeout seulement) → hiérarchie. Si l'état du bot est
/// inconnu, les trois dernières vérifications sont laissées à Discord.
pub fn precheck_sanction(
    kind: SanctionKind,
    context: &SanctionContext,
) -> Result<(), SanctionOutcome> {
    let skip = |reason| Err(SanctionOutcome::Skipped(reason));

    if context.owner_id == Some(context.target_id) {
        return skip(SanctionSkip::GuildOwner);
    }
    if context.target_id == context.bot_id {
        return skip(SanctionSkip::BotItself);
    }

    let target = match &context.target {
        TargetLookup::Found(target) => *target,
        TargetLookup::NotFound => return skip(SanctionSkip::MemberMissing),
        TargetLookup::Unavailable { details } => {
            return skip(SanctionSkip::MemberUnavailable {
                details: details.clone(),
            });
        }
    };

    let Some(bot) = context.bot else {
        return Ok(());
    };

    let permission = kind.required_permission();
    if !bot.permissions.allows(permission) {
        return skip(SanctionSkip::MissingPermission(permission));
    }

    if matches!(kind, SanctionKind::Timeout { .. }) && target.administrator == Some(true) {
        return skip(SanctionSkip::AdministratorTimeout);
    }

    if let Some(position) = target.top_role_position
        && position >= bot.top_role_position
    {
        return skip(SanctionSkip::RoleHierarchy {
            target: position,
            bot: bot.top_role_position,
        });
    }

    Ok(())
}

/// Classe l'échec HTTP d'une sanction tentée.
///
/// - `403` : permission ou hiérarchie insuffisante (Discord ne distingue pas
///   les deux, code 50013) → `missing_permission` ;
/// - `404` : membre parti entre-temps → `skipped` + `resource_missing` ;
/// - `429` et `5xx`, ou pas de réponse → `discord_unavailable`.
pub fn classify_sanction_http_failure(
    status: Option<u16>,
    details: impl Into<String>,
) -> SanctionOutcome {
    let failure_code = match status {
        Some(403) => FailureCode::MissingPermission,
        Some(404) => return SanctionOutcome::Skipped(SanctionSkip::MemberMissing),
        Some(429 | 500..=599) | None => FailureCode::DiscordUnavailable,
        Some(_) => FailureCode::Unknown,
    };

    SanctionOutcome::Failed {
        failure_code,
        details: details.into(),
    }
}

/// Raison d'audit log : `FoxSecura <module>: <détail>`, bornée à
/// [`AUDIT_REASON_MAX_CHARS`] caractères.
///
/// Le détail doit venir de FoxSecura (niveau, score), jamais du message : une
/// raison d'audit log est visible par tous les modérateurs.
pub fn audit_reason(module_label: &str, detail: &str) -> String {
    format!("{AUDIT_REASON_PREFIX} {module_label}: {detail}")
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(AUDIT_REASON_MAX_CHARS)
        .collect()
}

/// Indique si une raison d'audit log suit la convention de FoxSecura.
///
/// N'importe quel modérateur peut écrire la même raison : ce contrôle ne vaut
/// que combiné à l'exécuteur de l'entrée d'audit log (le bot lui-même).
pub fn is_foxsecura_audit_reason(reason: &str) -> bool {
    reason
        .strip_prefix(AUDIT_REASON_PREFIX)
        .is_some_and(|rest| rest.starts_with(' '))
}
