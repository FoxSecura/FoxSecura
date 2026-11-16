// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Intégrité du serveur : retour en arrière des permissions dangereuses,
//! réglages du serveur et URL personnalisée.
//!
//! Chaque module répond **unitairement** à une entrée du journal d'audit (ou
//! à un événement Gateway corrélé), sans compteur de rafale. Les gardes du
//! socle (`audit::screen_entry`) s'appliquent à tous : entrée trop vieille ou
//! rejouée, sans auteur, propriétaire du serveur, FoxSecura lui-même.
//!
//! `automod_rule_guard` reste un socle non branché : la V2 ne crée pas encore
//! de règles AutoMod natives à protéger.

pub mod alert;
pub mod anti_external_application;
pub mod anti_permissions;
pub mod anti_server_edit;
pub mod anti_vanity_change;
pub mod automod_rule_guard;
pub mod outcome;
pub mod server_guard;
