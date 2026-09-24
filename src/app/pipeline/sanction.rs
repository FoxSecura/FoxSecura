// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Exécution d'une sanction (timeout, expulsion, ban) contre un membre.
//!
//! La décision et le classement des échecs sont dans
//! `foxsecura::protection::shared::sanction` ; ce module relève l'état du
//! cache, résout le membre et appelle l'API.

use std::time::{SystemTime, UNIX_EPOCH};

use foxsecura::logs::FailureCode;
use foxsecura::protection::shared::{
    BotPermissions, BotStanding, SanctionContext, SanctionKind, SanctionOutcome, TargetLookup,
    TargetStanding, classify_sanction_http_failure, precheck_sanction,
};
use poise::serenity_prelude as serenity;

use super::delete;

/// Sanction à exécuter.
pub struct SanctionRequest<'a> {
    pub guild_id: u64,
    pub user_id: u64,
    /// Rôles du membre joints à l'événement ; `None` : lecture du membre
    /// (cache, puis API).
    pub member_roles: Option<&'a [u64]>,
    pub kind: SanctionKind,
    /// Raison d'audit log, construite par `audit_reason`.
    pub reason: &'a str,
}

/// Exécute la sanction et classe le résultat. Ne panique jamais et ne bloque
/// rien : un échec est un résultat journalisé.
pub async fn execute(ctx: &serenity::Context, request: &SanctionRequest<'_>) -> SanctionOutcome {
    let guild_id = serenity::GuildId::new(request.guild_id);
    let user_id = serenity::UserId::new(request.user_id);

    let roles = match request.member_roles {
        Some(roles) => Ok(roles.to_vec()),
        None => match guild_id.member(ctx, user_id).await {
            Ok(member) => Ok(member.roles.iter().map(|role| role.get()).collect()),
            Err(error) => Err(match delete::http_status(&error) {
                Some(404) => TargetLookup::NotFound,
                _ => TargetLookup::Unavailable {
                    details: error.to_string(),
                },
            }),
        },
    };

    let context = sanction_context(ctx, request, roles);
    if let Err(outcome) = precheck_sanction(request.kind, &context) {
        return outcome;
    }

    let result = match request.kind {
        SanctionKind::Timeout { .. } => {
            let Some(until) = request
                .kind
                .timeout_duration()
                .and_then(|duration| timeout_deadline(SystemTime::now(), duration))
            else {
                return SanctionOutcome::Failed {
                    failure_code: FailureCode::Unknown,
                    details: "invalid timeout deadline".to_owned(),
                };
            };
            guild_id
                .edit_member(
                    &ctx.http,
                    user_id,
                    serenity::EditMember::new()
                        .disable_communication_until_datetime(until)
                        .audit_log_reason(request.reason),
                )
                .await
                .map(|_| ())
        }
        SanctionKind::Kick => {
            guild_id
                .kick_with_reason(&ctx.http, user_id, request.reason)
                .await
        }
        SanctionKind::Ban { .. } => {
            guild_id
                .ban_with_reason(
                    &ctx.http,
                    user_id,
                    request.kind.ban_purge_days().unwrap_or(0),
                    request.reason,
                )
                .await
        }
    };

    match result {
        Ok(()) => SanctionOutcome::Applied,
        Err(serenity::Error::Http(error)) => classify_sanction_http_failure(
            error.status_code().map(|status| status.as_u16()),
            error.to_string(),
        ),
        // Erreur locale de serenity (paramètre refusé avant l'envoi) : ce
        // n'est pas une indisponibilité de Discord.
        Err(error) => SanctionOutcome::Failed {
            failure_code: FailureCode::Unknown,
            details: error.to_string(),
        },
    }
}

/// Échéance d'un timeout : maintenant + durée.
fn timeout_deadline(now: SystemTime, duration: std::time::Duration) -> Option<serenity::Timestamp> {
    let deadline = now.checked_add(duration)?.duration_since(UNIX_EPOCH).ok()?;
    serenity::Timestamp::from_unix_timestamp(i64::try_from(deadline.as_secs()).ok()?).ok()
}

/// Relève l'état du cache. Le verrou du cache est relâché avant tout `.await`.
fn sanction_context(
    ctx: &serenity::Context,
    request: &SanctionRequest<'_>,
    roles: Result<Vec<u64>, TargetLookup>,
) -> SanctionContext {
    let bot_id = ctx.cache.current_user().id;
    let mut context = SanctionContext {
        target_id: request.user_id,
        bot_id: bot_id.get(),
        owner_id: None,
        bot: None,
        target: match &roles {
            Ok(_) => TargetLookup::Found(TargetStanding {
                top_role_position: None,
                administrator: None,
            }),
            Err(lookup) => lookup.clone(),
        },
    };

    let Some(guild) = ctx.cache.guild(serenity::GuildId::new(request.guild_id)) else {
        return context;
    };
    context.owner_id = Some(guild.owner_id.get());

    if let Ok(roles) = &roles {
        context.target = TargetLookup::Found(standing(&guild, roles.iter().copied()));
    }

    if let Some(bot_member) = guild.members.get(&bot_id) {
        let permissions = guild.member_permissions(bot_member);
        let bot_roles = bot_member.roles.iter().map(|role| role.get());
        context.bot = Some(BotStanding {
            top_role_position: standing(&guild, bot_roles).top_role_position.unwrap_or(0),
            permissions: BotPermissions {
                administrator: permissions.administrator(),
                moderate_members: permissions.moderate_members(),
                kick_members: permissions.kick_members(),
                ban_members: permissions.ban_members(),
                manage_nicknames: permissions.manage_nicknames(),
            },
        });
    }

    context
}

/// Position du rôle le plus haut et `ADMINISTRATOR`, d'après les rôles du
/// serveur en cache (`@everyone` compris).
fn standing(guild: &serenity::Guild, roles: impl Iterator<Item = u64>) -> TargetStanding {
    let everyone = guild
        .roles
        .get(&serenity::RoleId::new(guild.id.get()))
        .map(|role| role.permissions)
        .unwrap_or_default();

    let mut top = 0;
    let mut permissions = everyone;
    for role_id in roles {
        if let Some(role) = guild.roles.get(&serenity::RoleId::new(role_id)) {
            top = top.max(role.position);
            permissions |= role.permissions;
        }
    }

    TargetStanding {
        top_role_position: Some(top),
        administrator: Some(permissions.administrator()),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn timeout_deadline_adds_the_duration() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let deadline = timeout_deadline(now, Duration::from_secs(3600)).unwrap();
        assert_eq!(deadline.unix_timestamp(), 1_700_003_600);
    }
}
