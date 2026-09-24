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
    ContentFilterSummaryInvisibleChar => {
        en: "Invisible or obfuscating characters detected.",
        fr: "Caractères invisibles ou d'obfuscation détectés.",
        de: "Unsichtbare oder verschleiernde Zeichen erkannt."
    },
    ContentFilterSummaryMaliciousLink => {
        en: "Malicious link detected.",
        fr: "Lien malveillant détecté.",
        de: "Schädlicher Link erkannt."
    },
    ContentFilterSummaryAdultLink => {
        en: "Adult content link detected.",
        fr: "Lien vers un contenu adulte détecté.",
        de: "Link zu Inhalten für Erwachsene erkannt."
    },
    ContentFilterSummaryInvite => {
        en: "Discord invite link detected.",
        fr: "Lien d'invitation Discord détecté.",
        de: "Discord-Einladungslink erkannt."
    },
    ContentFilterSummaryEveryone => {
        en: "@everyone or @here mention detected.",
        fr: "Mention @everyone ou @here détectée.",
        de: "Erwähnung von @everyone oder @here erkannt."
    },
    ContentFilterSummaryMassMention => {
        en: "Mass mention detected.",
        fr: "Mentions de masse détectées.",
        de: "Massenerwähnung erkannt."
    },
    ContentFilterSummaryAttachment => {
        en: "Dangerous attachment detected.",
        fr: "Pièce jointe dangereuse détectée.",
        de: "Gefährlicher Anhang erkannt."
    },
    ContentFilterSummaryScam => {
        en: "Probable scam detected.",
        fr: "Arnaque probable détectée.",
        de: "Wahrscheinlicher Betrug erkannt."
    },
    ContentFilterSummaryBadWord => {
        en: "Forbidden word detected.",
        fr: "Mot interdit détecté.",
        de: "Verbotenes Wort erkannt."
    },
    ContentFilterEvidenceFile => {
        en: "File",
        fr: "Fichier",
        de: "Datei"
    },
    ContentFilterEvidenceExtension => {
        en: "Extension",
        fr: "Extension",
        de: "Endung"
    },
    ContentFilterEvidenceWord => {
        en: "Word",
        fr: "Mot",
        de: "Wort"
    },
    AntiScamEvidenceSignals => {
        en: "Signals",
        fr: "Signaux",
        de: "Signale"
    },
    AntiScamEvidenceScore => {
        en: "Score",
        fr: "Score",
        de: "Punktzahl"
    },
    AntiScamEvidenceConfidence => {
        en: "Confidence",
        fr: "Confiance",
        de: "Konfidenz"
    },
    AntiScamRecommendationReview => {
        en: "Review the member: medium-confidence scam, no sanction was applied.",
        fr: "Examiner le membre : arnaque de confiance moyenne, aucune sanction appliquée.",
        de: "Das Mitglied überprüfen: Betrug mittlerer Konfidenz, keine Sanktion verhängt."
    },
    AntiScamRecommendationCheckHierarchy => {
        en: "Check the ban hierarchy: FoxSecura's role must be above the member, with Moderate Members and Ban Members.",
        fr: "Vérifier la hiérarchie du ban : le rôle de FoxSecura doit être au-dessus du membre, avec Modérer les membres et Bannir des membres.",
        de: "Die Bann-Hierarchie prüfen: Die Rolle von FoxSecura muss über dem Mitglied liegen, mit Mitglieder moderieren und Mitglieder bannen."
    },
    AntiScamRecommendationBanFalsePositive => {
        en: "Member banned: check the evidence and revoke the ban if it is a false positive (compromised account).",
        fr: "Membre banni : vérifier les preuves et révoquer le ban s'il s'agit d'un faux positif (compte compromis).",
        de: "Mitglied gebannt: Beweise prüfen und den Bann bei einem Fehlalarm aufheben (kompromittiertes Konto)."
    },
    AntiScamRecommendationTimeoutFalsePositive => {
        en: "Member timed out for one hour: check the evidence and lift the timeout if it is a false positive.",
        fr: "Membre exclu une heure : vérifier les preuves et lever l'exclusion s'il s'agit d'un faux positif.",
        de: "Mitglied für eine Stunde stummgeschaltet: Beweise prüfen und bei einem Fehlalarm aufheben."
    },
    RecommendationReviewWhitelist => {
        en: "Review the whitelist: an exempt member posted content that would have been sanctioned (possibly a compromised account).",
        fr: "Revoir la liste blanche : un membre exempté a publié un contenu qui aurait été sanctionné (compte peut-être compromis).",
        de: "Die Whitelist überprüfen: Ein ausgenommenes Mitglied hat Inhalte gepostet, die sanktioniert worden wären (möglicherweise kompromittiertes Konto)."
    },
    ModuleAttachmentFilter => {
        en: "Dangerous attachments",
        fr: "Pièces jointes dangereuses",
        de: "Gefährliche Anhänge"
    },
    ModuleAntiScam => {
        en: "Anti-scam",
        fr: "Anti-arnaque",
        de: "Anti-Betrug"
    },
    ModuleBadWords => {
        en: "Forbidden words",
        fr: "Mots interdits",
        de: "Verbotene Wörter"
    },
    ContentFilterEvidenceObfuscation => {
        en: "Obfuscation",
        fr: "Obfuscation",
        de: "Verschleierung"
    },
    ContentFilterEvidenceMention => {
        en: "Mention",
        fr: "Mention",
        de: "Erwähnung"
    },
    ContentFilterEvidenceEvent => {
        en: "Event",
        fr: "Événement",
        de: "Ereignis"
    },
    ContentFilterEventEdited => {
        en: "message edited",
        fr: "message modifié",
        de: "Nachricht bearbeitet"
    },
    LogsEvidenceExcerpt => {
        en: "Excerpt",
        fr: "Extrait",
        de: "Auszug"
    },
    LogsEvidenceDomain => {
        en: "Domain",
        fr: "Domaine",
        de: "Domain"
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
    ConfigContentFilters => {
        en: "Content filters",
        fr: "Filtres de contenu",
        de: "Inhaltsfilter"
    },
    ConfigContentFiltersNotice => {
        en: "Enabled filters delete matching messages (new or edited) and log an incident. Only the anti-scam sanctions: medium confidence asks for a staff review, high confidence times out for 1 hour, critical confidence bans and purges 7 days of messages (Moderate Members, Ban Members and a role above members required). A false positive bans a legitimate member: review every incident. Filters also apply to whitelisted members (deletion only, never a sanction), never in ignored channels. The Message Content intent is required.",
        fr: "Les filtres actifs suppriment les messages concernés (nouveaux ou modifiés) et journalisent un incident. Seul l'anti-arnaque sanctionne : confiance moyenne → revue par l'équipe, haute → exclusion d'une heure, critique → ban avec purge de 7 jours de messages (Modérer les membres, Bannir des membres et un rôle au-dessus des membres requis). Un faux positif bannit un membre légitime : examinez chaque incident. Les filtres s'appliquent aussi aux membres sur liste blanche (suppression seule, jamais de sanction), jamais dans les salons ignorés. L'intent Message Content est requis.",
        de: "Aktive Filter löschen betroffene Nachrichten (neu oder bearbeitet) und protokollieren einen Vorfall. Nur der Anti-Betrug sanktioniert: mittlere Konfidenz → Prüfung durch das Team, hohe → 1 Stunde Timeout, kritische → Bann mit Löschung von 7 Tagen Nachrichten (Mitglieder moderieren, Mitglieder bannen und eine Rolle über den Mitgliedern erforderlich). Ein Fehlalarm bannt ein legitimes Mitglied: Jeden Vorfall prüfen. Filter gelten auch für Mitglieder auf der Whitelist (nur Löschung, nie eine Sanktion), aber nie in ignorierten Kanälen. Der Message-Content-Intent ist erforderlich."
    },
    ConfigModuleEnabled => {
        en: "enabled",
        fr: "actif",
        de: "aktiv"
    },
    ConfigModuleDisabled => {
        en: "disabled",
        fr: "désactivé",
        de: "deaktiviert"
    },
    ModuleInvisibleCharFilter => {
        en: "Invisible characters",
        fr: "Caractères invisibles",
        de: "Unsichtbare Zeichen"
    },
    ModuleMaliciousLink => {
        en: "Malicious links",
        fr: "Liens malveillants",
        de: "Schädliche Links"
    },
    ModuleAdultLink => {
        en: "Adult links",
        fr: "Liens adultes",
        de: "Links für Erwachsene"
    },
    ModuleAntiInvite => {
        en: "Discord invites",
        fr: "Invitations Discord",
        de: "Discord-Einladungen"
    },
    ModuleAntiEveryone => {
        en: "@everyone / @here",
        fr: "@everyone / @here",
        de: "@everyone / @here"
    },
    ModuleAntiMassMention => {
        en: "Mass mentions",
        fr: "Mentions de masse",
        de: "Massenerwähnungen"
    },
    ConfigBadWords => {
        en: "Forbidden words",
        fr: "Mots interdits",
        de: "Verbotene Wörter"
    },
    ConfigBadWordsLanguage => {
        en: "Built-in list",
        fr: "Liste intégrée",
        de: "Integrierte Liste"
    },
    ConfigBadWordsCustomCount => {
        en: "Custom words",
        fr: "Mots personnalisés",
        de: "Eigene Wörter"
    },
    ConfigBadWordsNotice => {
        en: "Case-insensitive, whole words only (a letter, digit or _ next to it prevents a match). Deletion only, never a sanction, including for whitelisted members.",
        fr: "Insensible à la casse, mots entiers seulement (une lettre, un chiffre ou _ accolé empêche la correspondance). Suppression seule, jamais de sanction, y compris pour les membres sur liste blanche.",
        de: "Groß-/Kleinschreibung egal, nur ganze Wörter (ein angrenzender Buchstabe, eine Ziffer oder _ verhindert einen Treffer). Nur Löschung, nie eine Sanktion, auch für Mitglieder auf der Whitelist."
    },
    ConfigBadWordsFrench => {
        en: "French",
        fr: "Français",
        de: "Französisch"
    },
    ConfigBadWordsEnglish => {
        en: "English",
        fr: "Anglais",
        de: "Englisch"
    },
    ConfigBadWordsAll => {
        en: "All",
        fr: "Toutes",
        de: "Alle"
    },
    ConfigBadWordsEditButton => {
        en: "Edit custom words",
        fr: "Modifier les mots personnalisés",
        de: "Eigene Wörter bearbeiten"
    },
    ConfigBadWordsModalTitle => {
        en: "Custom forbidden words",
        fr: "Mots interdits personnalisés",
        de: "Eigene verbotene Wörter"
    },
    ConfigBadWordsInput => {
        en: "One word or phrase per line",
        fr: "Un mot ou une expression par ligne",
        de: "Ein Wort oder Ausdruck pro Zeile"
    },
    ConfigBadWordsInvalid => {
        en: "Invalid list: at most 200 words, 100 characters per word and 2,000 characters in total, without control characters. Nothing was changed.",
        fr: "Liste invalide : 200 mots au maximum, 100 caractères par mot et 2 000 caractères au total, sans caractère de contrôle. Rien n'a été modifié.",
        de: "Ungültige Liste: höchstens 200 Wörter, 100 Zeichen pro Wort und 2.000 Zeichen insgesamt, ohne Steuerzeichen. Es wurde nichts geändert."
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
    },
    BlacklistSummary => {
        en: "A blacklisted user joined the server.",
        fr: "Un utilisateur de la liste noire a rejoint le serveur.",
        de: "Ein Benutzer der Blacklist ist dem Server beigetreten."
    },
    BlacklistEvidenceEntry => {
        en: "Blacklist entry",
        fr: "Entrée de la liste noire",
        de: "Blacklist-Eintrag"
    },
    BlacklistRecommendationBanned => {
        en: "Blacklisted user banned. If this is a mistake, remove them from the blacklist, then revoke the ban.",
        fr: "Utilisateur de la liste noire banni. En cas d'erreur, retirez-le de la liste noire, puis révoquez le ban.",
        de: "Benutzer der Blacklist gebannt. Bei einem Fehler aus der Blacklist entfernen und dann den Bann aufheben."
    },
    MemberRecommendationCheckBanHierarchy => {
        en: "Check the ban hierarchy: FoxSecura needs Ban Members and a role above the member. Ban them manually if they are still on the server.",
        fr: "Vérifier la hiérarchie du ban : FoxSecura doit avoir Bannir des membres et un rôle au-dessus du membre. Bannissez-le manuellement s'il est encore sur le serveur.",
        de: "Die Bann-Hierarchie prüfen: FoxSecura braucht Mitglieder bannen und eine Rolle über dem Mitglied. Manuell bannen, falls es noch auf dem Server ist."
    },
    ModuleAntiBot => {
        en: "Anti-bot",
        fr: "Anti-bot",
        de: "Anti-Bot"
    },
    AntiBotSummaryUnauthorized => {
        en: "An unauthorized bot joined the server.",
        fr: "Un bot non autorisé a rejoint le serveur.",
        de: "Ein nicht autorisierter Bot ist dem Server beigetreten."
    },
    AntiBotSummaryAuthorized => {
        en: "Authorized bot ignored (whitelist).",
        fr: "Bot autorisé ignoré (liste blanche).",
        de: "Autorisierter Bot ignoriert (Whitelist)."
    },
    AntiBotEvidenceAccount => {
        en: "Account type",
        fr: "Type de compte",
        de: "Kontotyp"
    },
    AntiBotRecommendationKicked => {
        en: "Unauthorized bot kicked. If it is legitimate, add its ID to the whitelist, then invite it again.",
        fr: "Bot non autorisé expulsé. S'il est légitime, ajoutez son identifiant à la liste blanche, puis réinvitez-le.",
        de: "Nicht autorisierter Bot gekickt. Ist er legitim, seine ID zur Whitelist hinzufügen und ihn erneut einladen."
    },
    AntiBotRecommendationCheckKick => {
        en: "Check the kick: FoxSecura needs Kick Members and a role above the bot's role. Kick it manually if it is still on the server.",
        fr: "Vérifier l'expulsion : FoxSecura doit avoir Expulser des membres et un rôle au-dessus de celui du bot. Expulsez-le manuellement s'il est encore sur le serveur.",
        de: "Den Kick prüfen: FoxSecura braucht Mitglieder kicken und eine Rolle über der des Bots. Manuell kicken, falls er noch auf dem Server ist."
    }
}
