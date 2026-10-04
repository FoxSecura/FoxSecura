// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Honeypot : un message posté dans le salon piège trahit un compte
//! automatisé (V1).
//!
//! Le salon piège doit être **caché aux vrais membres** sans leur être
//! interdit : placé à l'écart (catégorie repliée, nom explicite), mais
//! lisible et ouvert à l'écriture pour `@everyone`. Un refus de
//! `VIEW_CHANNEL` ou de `SEND_MESSAGES` empêcherait aussi les comptes
//! automatisés d'y écrire. Seuls les comptes qui écrivent partout sans lire
//! y postent.
//!
//! # Place dans le pipeline des messages
//!
//! **Après** les gardes salon ignoré, webhook et bot, et **avant** tous les
//! filtres de contenu. Un salon piège ignoré n'est donc jamais surveillé. Un
//! message piégé est traité ici et le pipeline s'arrête : aucun filtre de
//! contenu ni anti-spam ne le voit. Seules les créations de message sont
//! analysées (une modification suppose un message déjà traité).
//!
//! # Décision
//!
//! - **Exemptés** (V1) : propriétaire, membres `ADMINISTRATOR` ou
//!   `MANAGE_GUILD`, membres de la liste blanche. Leur message suit le
//!   pipeline normal.
//! - **Sinon** : message supprimé, auteur mis en quarantaine **avec retrait
//!   des rôles dangereux et sans repli timeout** ([`HONEYPOT_QUARANTINE`]).
//! - **Permissions inconnues** (membre ou rôles absents du cache) : le
//!   message est supprimé et l'incident signalé, **sans quarantaine**. Un
//!   modérateur dont les rôles ne sont pas en cache ne doit pas perdre ses
//!   rôles sur un faux positif ; l'équipe tranche à la lecture du log.
//!
//! Incident `critical`, de type `member`, avec l'extrait du message rendu par
//! `inline_literal` (ni mention, ni formatage).

use poise::serenity_prelude::Permissions;

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, ActionStatus, AffectedResource, AffectedResourceType, LogSeverity, LogType,
    SecurityActionOutcome, SecurityEvidence, SecurityIncident,
};
use crate::protection::content_filter::excerpt;
use crate::protection::quarantine::{QuarantineOutcome, QuarantineRequest};
use crate::protection::shared::{
    DeleteMessageOutcome, GuildMessage, MessageScope, ModuleSet, ProtectionModule, audit_reason,
    message_incident,
};

/// Nom du module dans les raisons d'audit log (`FoxSecura Honeypot: …`).
pub const HONEYPOT_AUDIT_LABEL: &str = "Honeypot";

/// Quarantaine avec retrait des rôles dangereux, sans repli timeout (V1).
pub const HONEYPOT_QUARANTINE: QuarantineRequest = QuarantineRequest {
    remove_dangerous_roles: true,
    ..QuarantineRequest::ROLE_ONLY
};

/// Auteur d'un message dans le salon piège, d'après le cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoneypotAuthor {
    pub is_guild_owner: bool,
    /// Exempté par la liste blanche (identifiant ou rôle listé).
    pub whitelisted: bool,
    /// Permissions de l'auteur dans la guilde ; `None` si le cache ne permet
    /// pas de les établir (membre, rôles ou guilde absents).
    pub permissions: Option<Permissions>,
}

/// Raison pour laquelle l'auteur n'est pas sanctionné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotExemption {
    GuildOwner,
    Whitelist,
    /// `ADMINISTRATOR` ou `MANAGE_GUILD`.
    Staff,
}

/// Suite donnée à un message du salon piège.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotPlan {
    /// Auteur exempté : le message suit le pipeline normal.
    Exempt(HoneypotExemption),
    /// Supprimer le message et mettre l'auteur en quarantaine.
    Quarantine,
    /// Permissions inconnues : supprimer et signaler, sans quarantaine.
    DeleteOnly,
}

/// Décide du sort d'un message ; `None` hors du salon piège (ou sans salon
/// piège configuré).
///
/// Propriétaire → liste blanche → permissions : la liste blanche ne dépend
/// pas des permissions, elle exempte même quand elles sont inconnues.
pub fn plan_honeypot(
    channel_id: u64,
    honeypot_channel_id: Option<u64>,
    author: HoneypotAuthor,
) -> Option<HoneypotPlan> {
    if honeypot_channel_id != Some(channel_id) {
        return None;
    }
    Some(if author.is_guild_owner {
        HoneypotPlan::Exempt(HoneypotExemption::GuildOwner)
    } else if author.whitelisted {
        HoneypotPlan::Exempt(HoneypotExemption::Whitelist)
    } else {
        match author.permissions {
            None => HoneypotPlan::DeleteOnly,
            Some(permissions) if permissions.administrator() || permissions.manage_guild() => {
                HoneypotPlan::Exempt(HoneypotExemption::Staff)
            }
            Some(_) => HoneypotPlan::Quarantine,
        }
    })
}

/// Contexte du pipeline des messages pour le honeypot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoneypotRoute {
    /// Création de message (les modifications ne sont pas analysées).
    pub created: bool,
    pub scope: MessageScope,
    pub enabled_modules: ModuleSet,
    pub channel_id: u64,
    pub honeypot_channel_id: Option<u64>,
}

/// Le honeypot prend-il le message ? `Some` arrête le pipeline : aucun
/// filtre de contenu ni anti-spam ne s'exécute ensuite.
///
/// Salon ignoré prioritaire, module désactivé, modification de message ou
/// auteur exempté : `None`, le pipeline continue normalement.
pub fn route_honeypot(route: HoneypotRoute, author: HoneypotAuthor) -> Option<HoneypotPlan> {
    if !route.created
        || route.scope == MessageScope::IgnoredChannel
        || !route.enabled_modules.contains(ProtectionModule::Honeypot)
    {
        return None;
    }
    plan_honeypot(route.channel_id, route.honeypot_channel_id, author)
        .filter(|plan| !matches!(plan, HoneypotPlan::Exempt(_)))
}

/// Raison d'audit log de la suppression et de la quarantaine.
pub fn honeypot_audit_reason() -> String {
    audit_reason(HONEYPOT_AUDIT_LABEL, "message in the honeypot channel")
}

/// Incident `critical` de type `member`.
///
/// `quarantine` à `None` : permissions inconnues, quarantaine non tentée.
pub fn honeypot_incident(
    language: Language,
    message: &GuildMessage,
    content: &str,
    deletion: &DeleteMessageOutcome,
    quarantine: Option<&QuarantineOutcome>,
) -> SecurityIncident {
    let mut incident = message_incident(
        ProtectionModule::Honeypot.key(),
        text(language, TextKey::HoneypotSummary),
        message,
        deletion,
    );
    incident.log_type = LogType::Member;
    incident.severity = LogSeverity::Critical;
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Member,
        id: Some(message.author_id.to_string()),
        name: None,
    });

    match quarantine {
        Some(outcome) => incident.actions.extend(outcome.action_outcomes()),
        None => incident.actions.push(SecurityActionOutcome {
            action: ActionCode::QuarantineMember,
            status: ActionStatus::Skipped,
            details: Some("permissions_unknown".to_owned()),
            failure_code: None,
        }),
    }

    // Rendu par `inline_literal` : ni mention, ni formatage, ni lien.
    incident.evidence.push(SecurityEvidence::Content {
        excerpt: excerpt(content),
    });
    if let Some(outcome) = quarantine
        && !outcome.removed_roles().is_empty()
    {
        incident.evidence.push(SecurityEvidence::Text {
            label: text(language, TextKey::QuarantineEvidenceRemovedRoles).to_owned(),
            value: outcome
                .removed_roles()
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    let recommendation = match quarantine {
        None => TextKey::HoneypotRecommendationUnknownPermissions,
        Some(outcome) if outcome.contained() => TextKey::HoneypotRecommendationQuarantined,
        Some(_) => TextKey::QuarantineRecommendationFailed,
    };
    incident.recommendation = Some(text(language, recommendation).to_owned());
    incident
}
