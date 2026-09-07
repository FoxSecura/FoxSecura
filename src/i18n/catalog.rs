// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::Language;

macro_rules! catalog {
    ($(
        $key:ident => {
            en: $en:literal,
            fr: $fr:literal,
            de: $de:literal
        }
    ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum TextKey {
            $($key),+
        }

        impl TextKey {
            pub const ALL: &'static [Self] = &[
                $(Self::$key),+
            ];
        }

        pub fn text(language: Language, key: TextKey) -> &'static str {
            match key {
                $(
                    TextKey::$key => match language {
                        Language::English => $en,
                        Language::French => $fr,
                        Language::German => $de,
                    },
                )+
            }
        }
    };
}

catalog! {
    ConfigTitle => {
        en: "FoxSecura | Configuration",
        fr: "FoxSecura | Configuration",
        de: "FoxSecura | Konfiguration"
    },
    ConfigDescription => {
        en: "Select a category to open the corresponding panel.",
        fr: "Sélectionnez une catégorie pour ouvrir le panneau correspondant.",
        de: "Wähle eine Kategorie aus, um das entsprechende Panel zu öffnen."
    },
    ConfigFieldCategory => {
        en: "Category",
        fr: "Catégorie",
        de: "Kategorie"
    },
    ConfigFieldDescription => {
        en: "Description",
        fr: "Description",
        de: "Beschreibung"
    },
    ConfigFieldState => {
        en: "Status",
        fr: "État",
        de: "Status"
    },
    ConfigStatePlaceholder => {
        en: "This panel will contain the module settings.",
        fr: "Ce panneau sera complété avec les réglages du module.",
        de: "Dieses Panel wird die Einstellungen des Moduls enthalten."
    },
    ConfigDashboard => {
        en: "Dashboard",
        fr: "Tableau de bord",
        de: "Übersicht"
    },
    ConfigDashboardPrompt => {
        en: "Choose a category from the selector below.",
        fr: "Choisissez une catégorie dans le sélecteur ci-dessous.",
        de: "Wähle unten eine Kategorie aus."
    },
    ConfigSelectPlaceholder => {
        en: "Select a category",
        fr: "Sélectionnez une catégorie",
        de: "Kategorie auswählen"
    },
    CategoryGeneralSettings => {
        en: "General settings",
        fr: "Paramètres généraux",
        de: "Allgemeine Einstellungen"
    },
    CategoryGeneralSettingsDescription => {
        en: "General FoxSecura configuration.",
        fr: "Configuration générale de FoxSecura.",
        de: "Allgemeine Konfiguration von FoxSecura."
    },
    CategoryAntiRaid => {
        en: "Anti-Raid",
        fr: "Anti-Raid",
        de: "Anti-Raid"
    },
    CategoryAntiRaidDescription => {
        en: "Protection against raids and mass joins.",
        fr: "Protection contre les raids et arrivées massives.",
        de: "Schutz vor Raids und massenhaften Beitritten."
    },
    CategoryAntiSpam => {
        en: "Anti-Spam",
        fr: "Anti-Spam",
        de: "Anti-Spam"
    },
    CategoryAntiSpamDescription => {
        en: "Protection against spam and message abuse.",
        fr: "Protection contre le spam et les abus de messages.",
        de: "Schutz vor Spam und Nachrichtenmissbrauch."
    },
    CategoryServerProtection => {
        en: "Server protection",
        fr: "Protection serveur",
        de: "Serverschutz"
    },
    CategoryServerProtectionDescription => {
        en: "Protection for channels, roles and server settings.",
        fr: "Protection des salons, rôles et paramètres du serveur.",
        de: "Schutz von Kanälen, Rollen und Servereinstellungen."
    },
    CategoryAccessControl => {
        en: "Access control",
        fr: "Contrôle d'accès",
        de: "Zugriffskontrolle"
    },
    CategoryAccessControlDescription => {
        en: "Trusted access management and restrictions.",
        fr: "Gestion des accès de confiance et restrictions.",
        de: "Verwaltung vertrauenswürdiger Zugriffe und Einschränkungen."
    },
    CategoryAntiDoubleAccount => {
        en: "Anti-alt account",
        fr: "Anti-double compte",
        de: "Schutz vor Zweitkonten"
    },
    CategoryAntiDoubleAccountDescription => {
        en: "Verification and protection against alternate accounts.",
        fr: "Vérification et protection contre les doubles comptes.",
        de: "Prüfung und Schutz vor Zweitkonten."
    },
    CategoryAutomod => {
        en: "AutoMod",
        fr: "AutoMod",
        de: "AutoMod"
    },
    CategoryAutomodDescription => {
        en: "Configuration of AutoMod protections.",
        fr: "Configuration des protections AutoMod.",
        de: "Konfiguration der AutoMod-Schutzfunktionen."
    },
    CategoryAiModeration => {
        en: "AI Moderation",
        fr: "Modération IA",
        de: "KI-Moderation"
    },
    CategoryAiModerationDescription => {
        en: "Configuration of AI-assisted moderation.",
        fr: "Configuration de la modération assistée par IA.",
        de: "Konfiguration der KI-gestützten Moderation."
    },
    CategoryUtils => {
        en: "Utilities",
        fr: "Utilitaires",
        de: "Werkzeuge"
    },
    CategoryUtilsDescription => {
        en: "Server utility features.",
        fr: "Fonctions utilitaires du serveur.",
        de: "Hilfsfunktionen für den Server."
    },
    CategoryBackupSystem => {
        en: "Backup",
        fr: "Sauvegarde",
        de: "Sicherung"
    },
    CategoryBackupSystemDescription => {
        en: "Configuration backup and restore.",
        fr: "Sauvegarde et restauration de la configuration.",
        de: "Sicherung und Wiederherstellung der Konfiguration."
    },
    CategoryLogsHealth => {
        en: "Logs and health",
        fr: "Logs et santé",
        de: "Protokolle und Status"
    },
    CategoryLogsHealthDescription => {
        en: "Logging, diagnostics and bot health.",
        fr: "Journalisation, diagnostics et état du bot.",
        de: "Protokollierung, Diagnose und Bot-Status."
    },
    HelpTitle => {
        en: "FoxSecura | Help",
        fr: "FoxSecura | Aide",
        de: "FoxSecura | Hilfe"
    },
    HelpDescription => {
        en: "Commands available in FoxSecura v2.",
        fr: "Commandes disponibles dans FoxSecura v2.",
        de: "Verfügbare Befehle in FoxSecura v2."
    },
    HelpConfigDescription => {
        en: "Opens the configuration dashboard with its category selector.",
        fr: "Ouvre le tableau de bord de configuration avec sélecteur de catégories.",
        de: "Öffnet die Konfigurationsübersicht mit Kategorieauswahl."
    },
    HelpHelpDescription => {
        en: "Shows this help and the bot's main commands.",
        fr: "Affiche cette aide et les principales commandes du bot.",
        de: "Zeigt diese Hilfe und die wichtigsten Befehle des Bots."
    },
    HelpStatusDescription => {
        en: "Shows the current FoxSecura runtime status.",
        fr: "Affiche l'état d'exécution actuel de FoxSecura.",
        de: "Zeigt den aktuellen Betriebsstatus von FoxSecura."
    },
    StatusTitle => {
        en: "FoxSecura | Status",
        fr: "FoxSecura | Statut",
        de: "FoxSecura | Status"
    },
    StatusDescription => {
        en: "Current FoxSecura v2 runtime status.",
        fr: "État d'exécution actuel de FoxSecura v2.",
        de: "Aktueller Betriebsstatus von FoxSecura v2."
    },
    StatusApplication => {
        en: "Application",
        fr: "Application",
        de: "Anwendung"
    },
    StatusOperational => {
        en: "Operational",
        fr: "Opérationnelle",
        de: "Betriebsbereit"
    },
    StatusGateway => {
        en: "Discord Gateway",
        fr: "Gateway Discord",
        de: "Discord-Gateway"
    },
    StatusConnected => {
        en: "Connected",
        fr: "Connecté",
        de: "Verbunden"
    },
    StatusFramework => {
        en: "Framework",
        fr: "Framework",
        de: "Framework"
    },
    StatusCommands => {
        en: "Commands",
        fr: "Commandes",
        de: "Befehle"
    },
    StatusSecurityModules => {
        en: "Security modules",
        fr: "Modules de sécurité",
        de: "Schutzmodule"
    },
    StatusSecurityModulesReady => {
        en: "Protection engines loaded.",
        fr: "Moteurs de protection chargés.",
        de: "Schutzmodule geladen."
    },
    StatusVersion => {
        en: "Version",
        fr: "Version",
        de: "Version"
    },
    LogsChannelMessageLabel => {
        en: "Message logs",
        fr: "Logs messages",
        de: "Nachrichtenprotokolle"
    },
    LogsChannelMessagePurpose => {
        en: "Message edits, deletions and related events.",
        fr: "Modifications, suppressions et événements liés aux messages.",
        de: "Änderungen, Löschungen und zugehörige Nachrichtenereignisse."
    },
    LogsChannelServerLabel => {
        en: "Server logs",
        fr: "Logs serveur",
        de: "Serverprotokolle"
    },
    LogsChannelServerPurpose => {
        en: "Server changes and important guild-level events.",
        fr: "Modifications du serveur et événements importants au niveau de la guilde.",
        de: "Serveränderungen und wichtige Ereignisse auf Serverebene."
    },
    LogsChannelMemberLabel => {
        en: "Member logs",
        fr: "Logs membres",
        de: "Mitgliederprotokolle"
    },
    LogsChannelMemberPurpose => {
        en: "Joins, leaves, bots, nicknames and member-related events.",
        fr: "Arrivées, départs, bots, pseudonymes et événements liés aux membres.",
        de: "Beitritte, Austritte, Bots, Spitznamen und mitgliederbezogene Ereignisse."
    },
    LogsChannelChannelLabel => {
        en: "Channel logs",
        fr: "Logs salons",
        de: "Kanalprotokolle"
    },
    LogsChannelChannelPurpose => {
        en: "Channel creations, deletions, updates and related events.",
        fr: "Créations, suppressions, modifications et événements liés aux salons.",
        de: "Erstellungen, Löschungen, Änderungen und kanalbezogene Ereignisse."
    },
    LogsChannelRoleLabel => {
        en: "Role logs",
        fr: "Logs rôles",
        de: "Rollenprotokolle"
    },
    LogsChannelRolePurpose => {
        en: "Role creations, deletions, updates and related events.",
        fr: "Créations, suppressions, modifications et événements liés aux rôles.",
        de: "Erstellungen, Löschungen, Änderungen und rollenbezogene Ereignisse."
    },
    LogsChannelModerationLabel => {
        en: "Moderation logs",
        fr: "Logs modération",
        de: "Moderationsprotokolle"
    },
    LogsChannelModerationPurpose => {
        en: "Moderation actions, triggered protections and FoxSecura interventions.",
        fr: "Actions de modération, protections déclenchées et interventions de FoxSecura.",
        de: "Moderationsaktionen, ausgelöste Schutzfunktionen und FoxSecura-Eingriffe."
    },
    LogsIncidentTitle => {
        en: "FoxSecura Security Incident",
        fr: "Incident de sécurité FoxSecura",
        de: "FoxSecura-Sicherheitsvorfall"
    },
    LogsFieldModule => {
        en: "Module",
        fr: "Module",
        de: "Modul"
    },
    LogsFieldType => {
        en: "Type",
        fr: "Type",
        de: "Typ"
    },
    LogsFieldSeverity => {
        en: "Severity",
        fr: "Sévérité",
        de: "Schweregrad"
    },
    LogsFieldSummary => {
        en: "Summary",
        fr: "Résumé",
        de: "Zusammenfassung"
    },
    LogsFieldActions => {
        en: "Actions",
        fr: "Actions",
        de: "Aktionen"
    },
    LogsTypeMessage => {
        en: "Messages",
        fr: "Messages",
        de: "Nachrichten"
    },
    LogsTypeServer => {
        en: "Server",
        fr: "Serveur",
        de: "Server"
    },
    LogsTypeMember => {
        en: "Members",
        fr: "Membres",
        de: "Mitglieder"
    },
    LogsTypeChannel => {
        en: "Channels",
        fr: "Salons",
        de: "Kanäle"
    },
    LogsTypeRole => {
        en: "Roles",
        fr: "Rôles",
        de: "Rollen"
    },
    LogsTypeModeration => {
        en: "Moderation",
        fr: "Modération",
        de: "Moderation"
    },
    LogsSeverityInfo => {
        en: "Information",
        fr: "Information",
        de: "Information"
    },
    LogsSeverityWarning => {
        en: "Warning",
        fr: "Avertissement",
        de: "Warnung"
    },
    LogsSeverityCritical => {
        en: "Critical",
        fr: "Critique",
        de: "Kritisch"
    },
    LogsStatusSuccess => {
        en: "Success",
        fr: "Réussie",
        de: "Erfolgreich"
    },
    LogsStatusPartial => {
        en: "Partial",
        fr: "Partielle",
        de: "Teilweise"
    },
    LogsStatusFailed => {
        en: "Failed",
        fr: "Échec",
        de: "Fehlgeschlagen"
    },
    LogsStatusSkipped => {
        en: "Skipped",
        fr: "Ignorée",
        de: "Übersprungen"
    },
    LogsActionDeleteMessage => {
        en: "Delete message",
        fr: "Supprimer le message",
        de: "Nachricht löschen"
    },
    LogsActionBanMember => {
        en: "Ban member",
        fr: "Bannir le membre",
        de: "Mitglied bannen"
    },
    LogsActionKickMember => {
        en: "Kick member",
        fr: "Expulser le membre",
        de: "Mitglied kicken"
    },
    LogsActionQuarantineMember => {
        en: "Quarantine member",
        fr: "Mettre le membre en quarantaine",
        de: "Mitglied unter Quarantäne stellen"
    },
    LogsActionTimeoutMember => {
        en: "Timeout member",
        fr: "Exclure temporairement le membre",
        de: "Mitglied mit Timeout belegen"
    },
    LogsActionApplyLockdown => {
        en: "Apply lockdown",
        fr: "Activer le verrouillage",
        de: "Sperrmodus aktivieren"
    },
    LogsActionRestoreLockdown => {
        en: "Restore lockdown",
        fr: "Restaurer le verrouillage",
        de: "Sperrmodus wiederherstellen"
    },
    LogsActionRestoreChannel => {
        en: "Restore channel",
        fr: "Restaurer le salon",
        de: "Kanal wiederherstellen"
    },
    LogsActionRestoreRole => {
        en: "Restore role",
        fr: "Restaurer le rôle",
        de: "Rolle wiederherstellen"
    },
    LogsActionRemoveWebhook => {
        en: "Remove webhook",
        fr: "Supprimer le webhook",
        de: "Webhook entfernen"
    },
    LogsActionApplySlowmode => {
        en: "Apply slowmode",
        fr: "Activer le mode lent",
        de: "Slowmode aktivieren"
    },
    LogsActionRemoveLimitedRole => {
        en: "Remove limited role",
        fr: "Retirer le rôle limité",
        de: "Begrenzte Rolle entfernen"
    },
    LogsActionRestoreAutomodRule => {
        en: "Restore AutoMod rule",
        fr: "Restaurer la règle AutoMod",
        de: "AutoMod-Regel wiederherstellen"
    },
    LogsActionImportBackup => {
        en: "Import backup",
        fr: "Importer la sauvegarde",
        de: "Sicherung importieren"
    },
    LogsActionRestoreBackup => {
        en: "Restore backup",
        fr: "Restaurer la sauvegarde",
        de: "Sicherung wiederherstellen"
    },
    LogsActionUpdateConfig => {
        en: "Update configuration",
        fr: "Mettre à jour la configuration",
        de: "Konfiguration aktualisieren"
    },
    LogsActionExecuteSensitiveAction => {
        en: "Execute sensitive action",
        fr: "Exécuter l'action sensible",
        de: "Sensible Aktion ausführen"
    },
    LogsActionNormalizeNickname => {
        en: "Normalize nickname",
        fr: "Normaliser le pseudonyme",
        de: "Spitznamen normalisieren"
    },
    LogsActionRollbackPermissions => {
        en: "Rollback permissions",
        fr: "Restaurer les permissions",
        de: "Berechtigungen zurücksetzen"
    },
    LogsActionIgnoreExemptMember => {
        en: "Ignore exempt member",
        fr: "Ignorer le membre exempté",
        de: "Ausgenommenes Mitglied ignorieren"
    },
    LogsActionRequestStaffReview => {
        en: "Request staff review",
        fr: "Demander une vérification du staff",
        de: "Teamprüfung anfordern"
    },
    LogsActionRecordAlert => {
        en: "Record alert",
        fr: "Enregistrer l'alerte",
        de: "Warnung protokollieren"
    },
    LogsActionNotifyMember => {
        en: "Notify member",
        fr: "Notifier le membre",
        de: "Mitglied benachrichtigen"
    }
}
