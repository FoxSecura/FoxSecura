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
        en: "Commands available in FoxSecura.",
        fr: "Commandes disponibles dans FoxSecura.",
        de: "Verfügbare Befehle in FoxSecura."
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
        en: "Current FoxSecura runtime status.",
        fr: "État d'exécution actuel de FoxSecura.",
        de: "Aktueller Betriebsstatus von FoxSecura."
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
    },
    LogsFieldActor => {
        en: "Member",
        fr: "Membre",
        de: "Mitglied"
    },
    LogsFieldLocation => {
        en: "Channel",
        fr: "Salon",
        de: "Kanal"
    },
    LogsFieldEvidence => {
        en: "Evidence",
        fr: "Preuve",
        de: "Beweis"
    },
    LogsFieldRecommendation => {
        en: "Recommendation",
        fr: "Recommandation",
        de: "Empfehlung"
    },
    LogsUnitMessages => {
        en: "messages",
        fr: "messages",
        de: "Nachrichten"
    },
    LogsUnitMentions => {
        en: "mentions",
        fr: "mentions",
        de: "Erwähnungen"
    },
    LogsUnitJoins => {
        en: "joins",
        fr: "arrivées",
        de: "Beitritte"
    },
    LogsUnitActions => {
        en: "actions",
        fr: "actions",
        de: "Aktionen"
    },
    LogsUnitSignals => {
        en: "signals",
        fr: "signaux",
        de: "Signale"
    },
    LogsEvidenceWindow => {
        en: "in",
        fr: "en",
        de: "in"
    },
    AntiSpamIncidentSummary => {
        en: "Message flood detected.",
        fr: "Rafale de messages détectée.",
        de: "Nachrichtenflut erkannt."
    },
    AntiSpamRecommendationReviewMember => {
        en: "Review the suspicious member.",
        fr: "Examiner le membre suspect.",
        de: "Das verdächtige Mitglied überprüfen."
    },
    AntiSpamRecommendationCheckPermissions => {
        en: "Check that FoxSecura can delete messages (Manage Messages).",
        fr: "Vérifier les permissions de suppression de FoxSecura (Gérer les messages).",
        de: "Prüfen, ob FoxSecura Nachrichten löschen darf (Nachrichten verwalten)."
    },
    ConfigAccessDenied => {
        en: "You need to be the server owner or have the Administrator or Manage Server permission.",
        fr: "Vous devez être propriétaire du serveur ou disposer de la permission Administrateur ou Gérer le serveur.",
        de: "Du musst Serverinhaber sein oder die Berechtigung Administrator oder Server verwalten haben."
    },
    ConfigSaveFailed => {
        en: "The configuration could not be loaded or saved. Please try again.",
        fr: "La configuration n'a pas pu être lue ou enregistrée. Réessayez.",
        de: "Die Konfiguration konnte nicht geladen oder gespeichert werden. Bitte erneut versuchen."
    },
    ConfigAntiSpamEnabled => {
        en: "Enabled: messages that reach the threshold are deleted.",
        fr: "Actif : les messages qui atteignent le seuil sont supprimés.",
        de: "Aktiv: Nachrichten, die den Schwellenwert erreichen, werden gelöscht."
    },
    ConfigAntiSpamDisabled => {
        en: "Disabled.",
        fr: "Désactivé.",
        de: "Deaktiviert."
    },
    ConfigAntiSpamThreshold => {
        en: "Message threshold",
        fr: "Seuil de messages",
        de: "Nachrichtenschwelle"
    },
    ConfigAntiSpamWindow => {
        en: "Window (seconds)",
        fr: "Fenêtre (secondes)",
        de: "Zeitfenster (Sekunden)"
    },
    ConfigAntiSpamEnableButton => {
        en: "Enable",
        fr: "Activer",
        de: "Aktivieren"
    },
    ConfigAntiSpamDisableButton => {
        en: "Disable",
        fr: "Désactiver",
        de: "Deaktivieren"
    },
    ConfigAntiSpamEditLimitsButton => {
        en: "Edit thresholds",
        fr: "Modifier les seuils",
        de: "Schwellenwerte ändern"
    },
    ConfigAntiSpamLimitsModalTitle => {
        en: "Anti-Spam thresholds",
        fr: "Seuils Anti-Spam",
        de: "Anti-Spam-Schwellenwerte"
    },
    ConfigAntiSpamThresholdInput => {
        en: "Messages (2 to 50)",
        fr: "Messages (2 à 50)",
        de: "Nachrichten (2 bis 50)"
    },
    ConfigAntiSpamWindowInput => {
        en: "Window in seconds (1 to 60)",
        fr: "Fenêtre en secondes (1 à 60)",
        de: "Zeitfenster in Sekunden (1 bis 60)"
    },
    ConfigAntiSpamInvalidLimits => {
        en: "Invalid values: the threshold must be between 2 and 50 messages and the window between 1 and 60 seconds.",
        fr: "Valeurs invalides : le seuil doit être compris entre 2 et 50 messages et la fenêtre entre 1 et 60 secondes.",
        de: "Ungültige Werte: Die Schwelle muss zwischen 2 und 50 Nachrichten und das Zeitfenster zwischen 1 und 60 Sekunden liegen."
    },
    ConfigAccessControlNotice => {
        en: "Whitelisted members are exempt from sanctions; the whitelist never grants access to /config. No protection runs in ignored channels. Pick an entry to add it, or pick it again to remove it.",
        fr: "Les membres sur liste blanche sont exemptés de sanction ; la liste blanche ne donne jamais accès à /config. Aucune protection ne s'applique dans les salons ignorés. Choisissez une entrée pour l'ajouter, choisissez-la à nouveau pour la retirer.",
        de: "Mitglieder auf der Whitelist sind von Sanktionen ausgenommen; die Whitelist gewährt nie Zugriff auf /config. In ignorierten Kanälen greift kein Schutz. Wähle einen Eintrag, um ihn hinzuzufügen, und erneut, um ihn zu entfernen."
    },
    ConfigWhitelistUsers => {
        en: "Exempt users",
        fr: "Utilisateurs exemptés",
        de: "Ausgenommene Benutzer"
    },
    ConfigWhitelistRoles => {
        en: "Exempt roles",
        fr: "Rôles exemptés",
        de: "Ausgenommene Rollen"
    },
    ConfigIgnoredChannels => {
        en: "Ignored channels",
        fr: "Salons ignorés",
        de: "Ignorierte Kanäle"
    },
    ConfigListEmpty => {
        en: "None",
        fr: "Aucun",
        de: "Keine"
    },
    ConfigWhitelistUserSelect => {
        en: "Add or remove exempt users",
        fr: "Ajouter ou retirer des utilisateurs exemptés",
        de: "Ausgenommene Benutzer hinzufügen oder entfernen"
    },
    ConfigWhitelistRoleSelect => {
        en: "Add or remove exempt roles",
        fr: "Ajouter ou retirer des rôles exemptés",
        de: "Ausgenommene Rollen hinzufügen oder entfernen"
    },
    ConfigIgnoredChannelSelect => {
        en: "Add or remove ignored channels",
        fr: "Ajouter ou retirer des salons ignorés",
        de: "Ignorierte Kanäle hinzufügen oder entfernen"
    },
    ConfigWhitelistReadOnly => {
        en: "Only the server owner and administrators can edit the whitelist.",
        fr: "Seuls le propriétaire du serveur et les administrateurs peuvent modifier la liste blanche.",
        de: "Nur der Serverinhaber und Administratoren können die Whitelist bearbeiten."
    },
    ConfigWhitelistAccessDenied => {
        en: "The whitelist is reserved for the server owner and administrators (Manage Server is not enough).",
        fr: "La liste blanche est réservée au propriétaire du serveur et aux administrateurs (Gérer le serveur ne suffit pas).",
        de: "Die Whitelist ist dem Serverinhaber und Administratoren vorbehalten (Server verwalten reicht nicht)."
    },
    ConfigWhitelistEveryoneRefused => {
        en: "The @everyone role cannot be exempted: it would exempt the whole server. Nothing was changed.",
        fr: "Le rôle @everyone ne peut pas être exempté : il exempterait tout le serveur. Rien n'a été modifié.",
        de: "Die Rolle @everyone kann nicht ausgenommen werden: Sie würde den ganzen Server ausnehmen. Es wurde nichts geändert."
    }
}
