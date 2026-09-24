// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Mise en quarantaine d'un membre : enchaînement des étapes (V1).
//!
//! 1. **Jamais** le propriétaire, le bot lui-même, ni un membre de la liste
//!    blanche ([`QuarantineSkip`]).
//! 2. Si demandé, retrait **d'abord** des rôles dangereux gérables (hors
//!    `@everyone` et rôles gérés). Un rôle non gérable est ignoré sans faire
//!    échouer la quarantaine. Les rôles retirés **ne sont pas rendus** à la
//!    libération (V1) : l'incident les liste pour l'équipe.
//! 3. Pose du rôle de quarantaine ; chaque échec est distingué
//!    ([`RoleStatus`]). Une libération en attente devient obsolète.
//! 4. Rôle posé : verrou au niveau du membre sur chaque salon verrouillable,
//!    avec l'état d'origine enregistré avant chaque modification.
//! 5. Rôle non posé : timeout de repli, **seulement** si la requête
//!    l'autorise.
//!
//! Les effets (Discord, SQLite) passent par [`QuarantineEffects`] : le
//! runtime les exécute, les tests les simulent. L'appelant tient le verrou du
//! membre (`MemberLocks`) pendant toute l'opération.

use std::future::Future;
use std::time::Duration;

use crate::logs::{ActionCode, ActionStatus, FailureCode, SecurityActionOutcome};
use crate::protection::shared::{SanctionOutcome, exempt_member_action, is_everyone_role};

use super::channels::OverwriteBits;
use super::failure::{DiscordFailure, UNKNOWN_MEMBER, UNKNOWN_ROLE};
use super::overwrite::{MemberLockPlan, RecordedOverwrite, plan_member_lock};
use super::role::{BotRoleStanding, RoleFacts};

/// Durée du timeout de repli par défaut (V1).
pub const DEFAULT_QUARANTINE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Ce que le module demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantineRequest {
    /// Timeout si le rôle de quarantaine n'a pas pu être posé.
    pub allow_timeout_fallback: bool,
    /// Retrait préalable des rôles dangereux gérables (non rendus).
    pub remove_dangerous_roles: bool,
    pub timeout: Duration,
}

impl QuarantineRequest {
    /// Quarantaine seule : ni retrait des rôles, ni repli.
    pub const ROLE_ONLY: Self = Self {
        allow_timeout_fallback: false,
        remove_dangerous_roles: false,
        timeout: DEFAULT_QUARANTINE_TIMEOUT,
    };
}

/// Rôle de quarantaine de la guilde, d'après la configuration et le cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineRoleLookup {
    NotConfigured,
    /// Configuré mais absent du serveur.
    Deleted {
        role_id: u64,
    },
    Found(RoleFacts),
    /// Configuré, serveur absent du cache : l'appel est tenté.
    Unknown {
        role_id: u64,
    },
}

/// Salon verrouillable et overwrite actuel du membre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberChannel {
    pub channel_id: u64,
    pub member_overwrite: Option<OverwriteBits>,
}

/// Tout ce que le runtime sait avant d'agir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineFacts {
    pub guild_id: u64,
    pub user_id: u64,
    pub bot_id: u64,
    /// `None` si le serveur n'est pas en cache.
    pub owner_id: Option<u64>,
    /// Membre exempté par la liste blanche (le rôle de quarantaine n'exempte
    /// jamais).
    pub whitelisted: bool,
    pub quarantine_role: QuarantineRoleLookup,
    /// `None` si le cache ne permet pas de conclure : les appels sont tentés.
    pub bot: Option<BotRoleStanding>,
    /// Rôles du membre connus du cache.
    pub member_roles: Vec<RoleFacts>,
    /// Salons verrouillables (voir `lockable_channels`).
    pub channels: Vec<MemberChannel>,
}

/// Membre jamais mis en quarantaine (V1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineSkip {
    GuildOwner,
    BotItself,
    Whitelisted,
}

/// Garde : propriétaire → bot lui-même → liste blanche.
pub fn quarantine_guard(facts: &QuarantineFacts) -> Option<QuarantineSkip> {
    if facts.owner_id == Some(facts.user_id) {
        Some(QuarantineSkip::GuildOwner)
    } else if facts.user_id == facts.bot_id {
        Some(QuarantineSkip::BotItself)
    } else if facts.whitelisted {
        Some(QuarantineSkip::Whitelisted)
    } else {
        None
    }
}

/// Pourquoi le bot ne peut pas poser le rôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleBlock {
    /// Pas de `MANAGE_ROLES`.
    MissingPermission,
    /// Rôle de quarantaine au niveau du bot ou au-dessus.
    RoleHierarchy { role: u16, bot: u16 },
    /// Rôle géré par une intégration.
    Managed,
}

/// Résultat de la pose du rôle de quarantaine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleStatus {
    Applied,
    /// Aucun rôle de quarantaine configuré.
    NotConfigured,
    /// Rôle configuré supprimé du serveur.
    RoleDeleted,
    NotManageable(RoleBlock),
    /// Le membre a quitté le serveur.
    MemberMissing,
    /// Échec de l'API.
    Failed(DiscordFailure),
}

/// Vérifie d'après le cache que le rôle peut être posé ; renvoie son
/// identifiant.
pub fn precheck_quarantine_role(
    role: &QuarantineRoleLookup,
    bot: Option<BotRoleStanding>,
) -> Result<u64, RoleStatus> {
    let role = match *role {
        QuarantineRoleLookup::NotConfigured => return Err(RoleStatus::NotConfigured),
        QuarantineRoleLookup::Deleted { .. } => return Err(RoleStatus::RoleDeleted),
        QuarantineRoleLookup::Unknown { role_id } => return Ok(role_id),
        QuarantineRoleLookup::Found(role) => role,
    };
    if role.managed {
        return Err(RoleStatus::NotManageable(RoleBlock::Managed));
    }
    let Some(bot) = bot else {
        return Ok(role.id);
    };
    if !bot.manage_roles {
        return Err(RoleStatus::NotManageable(RoleBlock::MissingPermission));
    }
    if role.position >= bot.top_role_position {
        return Err(RoleStatus::NotManageable(RoleBlock::RoleHierarchy {
            role: role.position,
            bot: bot.top_role_position,
        }));
    }
    Ok(role.id)
}

/// Classe l'échec de la pose du rôle.
///
/// `404` : rôle inconnu (supprimé entre-temps) ou membre inconnu (parti).
/// `403` : permission ou hiérarchie (Discord ne les distingue pas).
pub fn classify_role_failure(failure: DiscordFailure) -> RoleStatus {
    if failure.is_unknown(UNKNOWN_ROLE) {
        RoleStatus::RoleDeleted
    } else if failure.is_unknown(UNKNOWN_MEMBER) {
        RoleStatus::MemberMissing
    } else if failure.status == Some(403) {
        RoleStatus::NotManageable(RoleBlock::MissingPermission)
    } else {
        RoleStatus::Failed(failure)
    }
}

/// Rôles dangereux du membre : `(gérables, non gérables)`.
///
/// `@everyone` n'est jamais retiré. Un rôle géré n'est retirable par aucun
/// bot. Bot inconnu du cache : tout rôle non géré est tenté.
pub fn plan_dangerous_role_removal(
    guild_id: u64,
    member_roles: &[RoleFacts],
    bot: Option<BotRoleStanding>,
) -> (Vec<u64>, Vec<u64>) {
    let mut removable = Vec::new();
    let mut unmanageable = Vec::new();
    for role in member_roles
        .iter()
        .filter(|role| role.is_dangerous() && !is_everyone_role(guild_id, role.id))
    {
        let manageable = !role.managed && bot.is_none_or(|bot| bot.can_manage(role));
        if manageable {
            removable.push(role.id);
        } else {
            unmanageable.push(role.id);
        }
    }
    (removable, unmanageable)
}

/// Retrait des rôles dangereux.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DangerousRoleRemoval {
    /// Rôles retirés : **non rendus** à la libération.
    pub removed: Vec<u64>,
    /// Rôles ignorés : non gérables par le bot.
    pub unmanageable: Vec<u64>,
    /// Retraits refusés par Discord.
    pub failed: Vec<(u64, FailureCode)>,
}

impl DangerousRoleRemoval {
    fn action_outcome(&self) -> SecurityActionOutcome {
        let details = format!(
            "removed={} unmanageable={} failed={}",
            self.removed.len(),
            self.unmanageable.len(),
            self.failed.len()
        );
        let failure_code = self
            .failed
            .first()
            .map(|(_, code)| *code)
            .or_else(|| (!self.unmanageable.is_empty()).then_some(FailureCode::RoleHierarchy));
        let status = match (self.removed.is_empty(), failure_code.is_none()) {
            (true, true) => ActionStatus::Skipped,
            (false, true) => ActionStatus::Success,
            (false, false) => ActionStatus::Partial,
            (true, false) => ActionStatus::Failed,
        };
        SecurityActionOutcome {
            action: ActionCode::RemoveDangerousRoles,
            status,
            details: Some(details),
            failure_code,
        }
    }
}

/// Bilan du verrou au niveau du membre.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelLockSummary {
    /// Salons verrouillés par cette opération.
    pub locked: usize,
    /// Salons déjà verrouillés (ligne conservée d'une libération inachevée).
    pub already_locked: usize,
    /// Refus préexistant des deux bits : ni modifié, ni enregistré.
    pub preexisting_deny: usize,
    pub failed: usize,
    pub first_failure: Option<FailureCode>,
}

impl ChannelLockSummary {
    fn action_outcome(&self) -> SecurityActionOutcome {
        let locked = self.locked + self.already_locked;
        let status = match (self.failed, locked) {
            (0, _) => ActionStatus::Success,
            (_, 0) => ActionStatus::Failed,
            _ => ActionStatus::Partial,
        };
        SecurityActionOutcome {
            action: ActionCode::LockMemberChannels,
            status,
            details: Some(format!(
                "locked={} already_locked={} preexisting_deny={} failed={}",
                self.locked, self.already_locked, self.preexisting_deny, self.failed
            )),
            failure_code: self.first_failure,
        }
    }

    fn record(&mut self, result: ChannelLockResult) {
        match result {
            ChannelLockResult::Locked => self.locked += 1,
            ChannelLockResult::AlreadyLocked => self.already_locked += 1,
            ChannelLockResult::PreexistingDeny => self.preexisting_deny += 1,
            ChannelLockResult::Failed(code) => {
                self.failed += 1;
                self.first_failure.get_or_insert(code);
            }
        }
    }
}

/// Résultat du verrou d'un salon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLockResult {
    Locked,
    AlreadyLocked,
    PreexistingDeny,
    Failed(FailureCode),
}

/// Résultat détaillé : chaque étape échoue indépendamment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantineOutcome {
    /// Membre jamais mis en quarantaine : aucune étape n'a été tentée.
    pub skipped: Option<QuarantineSkip>,
    /// `None` : retrait non demandé.
    pub dangerous_roles: Option<DangerousRoleRemoval>,
    /// `None` seulement si le membre a été écarté.
    pub role: Option<RoleStatus>,
    /// `None` : rôle non posé, aucun verrou tenté.
    pub channel_lock: Option<ChannelLockSummary>,
    /// `None` : aucun timeout tenté (rôle posé ou repli non autorisé).
    pub timeout: Option<SanctionOutcome>,
    /// Écritures SQLite échouées (libération en attente non effacée) :
    /// journalisées par le runtime.
    pub store_errors: Vec<String>,
}

impl QuarantineOutcome {
    fn skipped(skip: QuarantineSkip) -> Self {
        Self {
            skipped: Some(skip),
            ..Self::default()
        }
    }

    pub fn role_applied(&self) -> bool {
        self.role == Some(RoleStatus::Applied)
    }

    pub fn timeout_applied(&self) -> bool {
        self.timeout
            .as_ref()
            .is_some_and(SanctionOutcome::is_applied)
    }

    /// Le membre est contenu : rôle de quarantaine ou timeout appliqué.
    pub fn contained(&self) -> bool {
        self.role_applied() || self.timeout_applied()
    }

    /// Rôles dangereux retirés (non rendus à la libération).
    pub fn removed_roles(&self) -> &[u64] {
        self.dangerous_roles
            .as_ref()
            .map_or(&[], |removal| removal.removed.as_slice())
    }

    /// Résultats d'action de l'incident, dans l'ordre des étapes : retrait
    /// des rôles dangereux, rôle de quarantaine, verrou des salons, timeout.
    pub fn action_outcomes(&self) -> Vec<SecurityActionOutcome> {
        let skipped = |details: &str| SecurityActionOutcome {
            action: ActionCode::QuarantineMember,
            status: ActionStatus::Skipped,
            details: Some(details.to_owned()),
            failure_code: None,
        };
        match self.skipped {
            Some(QuarantineSkip::GuildOwner) => return vec![skipped("guild_owner")],
            Some(QuarantineSkip::BotItself) => return vec![skipped("bot_itself")],
            Some(QuarantineSkip::Whitelisted) => return vec![exempt_member_action()],
            None => {}
        }

        let mut actions = Vec::new();
        if let Some(removal) = &self.dangerous_roles {
            actions.push(removal.action_outcome());
        }
        if let Some(role) = &self.role {
            actions.push(role_action(role));
        }
        if let Some(lock) = &self.channel_lock {
            actions.push(lock.action_outcome());
        }
        if let Some(timeout) = &self.timeout {
            actions.push(timeout.action_outcome_as(ActionCode::TimeoutMember));
        }
        actions
    }
}

fn role_action(status: &RoleStatus) -> SecurityActionOutcome {
    let (status, failure_code, details) = match status {
        RoleStatus::Applied => (ActionStatus::Success, None, None),
        RoleStatus::NotConfigured => (ActionStatus::Skipped, None, Some("not_configured".into())),
        RoleStatus::RoleDeleted => (
            ActionStatus::Failed,
            Some(FailureCode::ResourceMissing),
            Some("quarantine_role_deleted".into()),
        ),
        RoleStatus::NotManageable(RoleBlock::MissingPermission) => (
            ActionStatus::Failed,
            Some(FailureCode::MissingPermission),
            Some("MANAGE_ROLES".into()),
        ),
        RoleStatus::NotManageable(RoleBlock::RoleHierarchy { role, bot }) => (
            ActionStatus::Failed,
            Some(FailureCode::RoleHierarchy),
            Some(format!("quarantine_role={role} bot_top_role={bot}")),
        ),
        RoleStatus::NotManageable(RoleBlock::Managed) => (
            ActionStatus::Failed,
            Some(FailureCode::RoleHierarchy),
            Some("managed_role".into()),
        ),
        RoleStatus::MemberMissing => (
            ActionStatus::Skipped,
            Some(FailureCode::ResourceMissing),
            Some("member_missing".into()),
        ),
        RoleStatus::Failed(failure) => (
            ActionStatus::Failed,
            Some(failure.failure_code()),
            Some(failure.details.clone()),
        ),
    };
    SecurityActionOutcome {
        action: ActionCode::QuarantineMember,
        status,
        details,
        failure_code,
    }
}

/// Échec d'une lecture ou d'une écriture SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

/// Effets d'une quarantaine ou d'une libération, pour un membre donné.
///
/// Le runtime les exécute (Discord, SQLite) avec la raison d'audit log de
/// l'opération ; les tests les simulent.
pub trait QuarantineEffects {
    /// Retire un rôle au membre.
    fn remove_role(
        &mut self,
        role_id: u64,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;

    /// Attribue un rôle au membre.
    fn add_role(&mut self, role_id: u64)
    -> impl Future<Output = Result<(), DiscordFailure>> + Send;

    /// Écrit l'overwrite du membre dans un salon.
    fn write_member_overwrite(
        &mut self,
        channel_id: u64,
        overwrite: OverwriteBits,
    ) -> impl Future<Output = Result<(), DiscordFailure>> + Send;

    /// Timeout de repli, exécuté par le socle des sanctions.
    fn timeout(&mut self, duration: Duration) -> impl Future<Output = SanctionOutcome> + Send;

    /// Ligne enregistrée pour un salon.
    fn recorded_overwrite(
        &mut self,
        channel_id: u64,
    ) -> impl Future<Output = Result<Option<RecordedOverwrite>, StoreError>> + Send;

    /// Enregistre l'état d'origine ; `false` si une ligne existait déjà
    /// (conservée).
    fn record_overwrite(
        &mut self,
        channel_id: u64,
        state: RecordedOverwrite,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Supprime la ligne d'un salon.
    fn forget_overwrite(
        &mut self,
        channel_id: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Enregistre ou efface la libération en attente du membre.
    fn set_pending_release(
        &mut self,
        pending: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Met le membre en quarantaine. L'appelant tient le verrou du membre.
pub async fn quarantine_member<E: QuarantineEffects>(
    effects: &mut E,
    facts: &QuarantineFacts,
    request: &QuarantineRequest,
) -> QuarantineOutcome {
    if let Some(skip) = quarantine_guard(facts) {
        return QuarantineOutcome::skipped(skip);
    }
    let mut outcome = QuarantineOutcome::default();

    if request.remove_dangerous_roles {
        let (removable, unmanageable) =
            plan_dangerous_role_removal(facts.guild_id, &facts.member_roles, facts.bot);
        let mut removal = DangerousRoleRemoval {
            unmanageable,
            ..DangerousRoleRemoval::default()
        };
        for role_id in removable {
            match effects.remove_role(role_id).await {
                Ok(()) => removal.removed.push(role_id),
                Err(failure) => removal.failed.push((role_id, failure.failure_code())),
            }
        }
        outcome.dangerous_roles = Some(removal);
    }

    let role = match precheck_quarantine_role(&facts.quarantine_role, facts.bot) {
        Err(status) => status,
        Ok(role_id) => match effects.add_role(role_id).await {
            Ok(()) => RoleStatus::Applied,
            Err(failure) => classify_role_failure(failure),
        },
    };
    outcome.role = Some(role);

    if outcome.role_applied() {
        // Remis en quarantaine : une libération en attente est obsolète. Les
        // lignes d'une libération inachevée sont gardées (état d'origine).
        if let Err(StoreError(error)) = effects.set_pending_release(false).await {
            outcome.store_errors.push(error);
        }
        let mut summary = ChannelLockSummary::default();
        for channel in &facts.channels {
            summary.record(lock_member_channel(effects, channel).await);
        }
        outcome.channel_lock = Some(summary);
    } else if request.allow_timeout_fallback {
        outcome.timeout = Some(effects.timeout(request.timeout).await);
    }

    outcome
}

/// Verrouille un salon : enregistre l'état d'origine **avant** de le
/// modifier, et supprime la ligne tout juste créée si la modification
/// échoue. Sans enregistrement réussi, le salon n'est jamais modifié.
pub async fn lock_member_channel<E: QuarantineEffects>(
    effects: &mut E,
    channel: &MemberChannel,
) -> ChannelLockResult {
    let recorded = match effects.recorded_overwrite(channel.channel_id).await {
        Ok(recorded) => recorded,
        Err(_) => return ChannelLockResult::Failed(FailureCode::Unknown),
    };

    let (record, overwrite) = match plan_member_lock(channel.member_overwrite, recorded) {
        MemberLockPlan::PreexistingDeny => return ChannelLockResult::PreexistingDeny,
        MemberLockPlan::AlreadyLocked => return ChannelLockResult::AlreadyLocked,
        MemberLockPlan::Lock { record, overwrite } => (record, overwrite),
    };

    let inserted = match record {
        Some(state) => match effects.record_overwrite(channel.channel_id, state).await {
            Ok(inserted) => inserted,
            Err(_) => return ChannelLockResult::Failed(FailureCode::Unknown),
        },
        None => false,
    };

    match effects
        .write_member_overwrite(channel.channel_id, overwrite)
        .await
    {
        Ok(()) => ChannelLockResult::Locked,
        Err(failure) => {
            if inserted {
                // Rien n'a été modifié : la ligne ne décrit aucun verrou. Un
                // échec ici laisse une ligne dont la restauration est
                // idempotente (état d'origine réécrit à l'identique).
                let _ = effects.forget_overwrite(channel.channel_id).await;
            }
            ChannelLockResult::Failed(failure.failure_code())
        }
    }
}
