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
        en: "Alt accounts & honeypot",
        fr: "Doubles comptes et salon piège",
        de: "Zweitkonten & Honeypot"
    },
    CategoryAntiDoubleAccountDescription => {
        en: "Alternate accounts and a trap channel against automated accounts.",
        fr: "Doubles comptes et salon piège contre les comptes automatisés.",
        de: "Zweitkonten und ein Fallenkanal gegen automatisierte Konten."
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
    LogsActionRemoveDangerousRoles => {
        en: "Remove dangerous roles",
        fr: "Retirer les rôles dangereux",
        de: "Gefährliche Rollen entfernen"
    },
    LogsActionLockMemberChannels => {
        en: "Lock channels for the member",
        fr: "Verrouiller les salons pour le membre",
        de: "Kanäle für das Mitglied sperren"
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
    },
    ModuleAntiNewAccount => {
        en: "New accounts",
        fr: "Nouveaux comptes",
        de: "Neue Konten"
    },
    NewAccountSummary => {
        en: "An account younger than the minimum age joined the server.",
        fr: "Un compte plus récent que l'âge minimal a rejoint le serveur.",
        de: "Ein Konto unter dem Mindestalter ist dem Server beigetreten."
    },
    NewAccountRecommendationExempt => {
        en: "Recent account exempted (whitelist or server owner): no action. Make sure it is a trusted member.",
        fr: "Compte récent exempté (liste blanche ou propriétaire) : aucune action. Vérifiez qu'il s'agit bien d'un membre de confiance.",
        de: "Neues Konto ausgenommen (Whitelist oder Serverinhaber): keine Aktion. Sicherstellen, dass es ein vertrauenswürdiges Mitglied ist."
    },
    NewAccountRecommendationBanned => {
        en: "Recent account banned: check the member and revoke the ban if it is a legitimate newcomer (false positive).",
        fr: "Compte récent banni : vérifiez le membre et révoquez le ban s'il s'agit d'un nouveau venu légitime (faux positif).",
        de: "Neues Konto gebannt: Das Mitglied prüfen und den Bann aufheben, falls es ein legitimer Neuling ist (Fehlalarm)."
    },
    NewAccountRecommendationBanFailed => {
        en: "Neither the ban nor the fallback quarantine was applied: the recent account is still on the server without restriction. Check the ban hierarchy (Ban Members, FoxSecura's role above the member), the quarantine role (/config, Anti-Raid) and review the member.",
        fr: "Ni le ban ni la quarantaine de repli n'ont été appliqués : le compte récent est resté sur le serveur sans restriction. Vérifiez la hiérarchie du ban (Bannir des membres, rôle de FoxSecura au-dessus du membre), le rôle de quarantaine (/config, Anti-Raid) et examinez le membre.",
        de: "Weder der Bann noch die Ersatz-Quarantäne wurden angewendet: Das neue Konto ist ohne Einschränkung auf dem Server. Die Bann-Hierarchie prüfen (Mitglieder bannen, Rolle von FoxSecura über dem Mitglied), die Quarantäne-Rolle (/config, Anti-Raid) und das Mitglied überprüfen."
    },
    NewAccountRecommendationQuarantined => {
        en: "The ban was not applied: the recent account was quarantined instead (or timed out if the quarantine role could not be assigned). Check the ban hierarchy, then ban the member or release them from /config (Anti-Raid).",
        fr: "Le ban n'a pas été appliqué : le compte récent a été mis en quarantaine à la place (ou exclu temporairement si le rôle de quarantaine n'a pas pu être posé). Vérifiez la hiérarchie du ban, puis bannissez le membre ou libérez-le depuis /config (Anti-Raid).",
        de: "Der Bann wurde nicht angewendet: Das neue Konto wurde stattdessen unter Quarantäne gestellt (oder getimeoutet, falls die Quarantäne-Rolle nicht vergeben werden konnte). Die Bann-Hierarchie prüfen, dann das Mitglied bannen oder über /config (Anti-Raid) freigeben."
    },
    LogsEvidenceAccountAge => {
        en: "Account age",
        fr: "Âge du compte",
        de: "Kontoalter"
    },
    LogsEvidenceMinimum => {
        en: "minimum",
        fr: "minimum",
        de: "Minimum"
    },
    LogsUnitDays => {
        en: "days",
        fr: "jours",
        de: "Tage"
    },
    ModuleAntiNicknameHoisting => {
        en: "Hoisted nicknames",
        fr: "Pseudos hoistés",
        de: "Gehoistete Spitznamen"
    },
    HoistingSummary => {
        en: "Hoisted display name detected.",
        fr: "Nom affiché hoisté détecté.",
        de: "Gehoisteter Anzeigename erkannt."
    },
    HoistingEvidenceOldName => {
        en: "Previous name",
        fr: "Ancien nom",
        de: "Vorheriger Name"
    },
    HoistingEvidenceNewName => {
        en: "New nickname",
        fr: "Nouveau pseudo",
        de: "Neuer Spitzname"
    },
    HoistingRecommendationCheckPermissions => {
        en: "Check that FoxSecura has Manage Nicknames and a role above the member. The server owner can never be renamed by a bot.",
        fr: "Vérifiez que FoxSecura a Gérer les pseudos et un rôle au-dessus du membre. Le propriétaire du serveur ne peut jamais être renommé par un bot.",
        de: "Prüfen, ob FoxSecura Spitznamen verwalten und eine Rolle über dem Mitglied hat. Der Serverinhaber kann nie von einem Bot umbenannt werden."
    },
    ModuleAntiImpersonation => {
        en: "Impersonation",
        fr: "Usurpation d'identité",
        de: "Identitätsdiebstahl"
    },
    ImpersonationSummary => {
        en: "A joining member uses the name of the owner or of a privileged member.",
        fr: "Un membre arrivé utilise le nom du propriétaire ou d'un membre privilégié.",
        de: "Ein beigetretenes Mitglied verwendet den Namen des Inhabers oder eines privilegierten Mitglieds."
    },
    ImpersonationEvidenceName => {
        en: "Member name",
        fr: "Nom du membre",
        de: "Name des Mitglieds"
    },
    ImpersonationEvidenceProtected => {
        en: "Protected name",
        fr: "Nom protégé",
        de: "Geschützter Name"
    },
    ImpersonationRecommendationQuarantined => {
        en: "Member quarantined. Check whether it is a real impersonation: ban them, or release them from /config (Anti-Raid) if it is a false positive.",
        fr: "Membre mis en quarantaine. Vérifiez s'il s'agit d'une vraie usurpation : bannissez-le, ou libérez-le depuis /config (Anti-Raid) s'il s'agit d'un faux positif.",
        de: "Mitglied unter Quarantäne gestellt. Prüfen, ob es ein echter Identitätsdiebstahl ist: bannen, oder bei einem Fehlalarm über /config (Anti-Raid) freigeben."
    },
    QuarantineRecommendationFailed => {
        en: "The quarantine was not applied: the member is still on the server without restriction. Configure the quarantine role in /config (Anti-Raid), check Manage Roles and that FoxSecura's role is above it, then review the member.",
        fr: "La quarantaine n'a pas été appliquée : le membre est resté sur le serveur sans restriction. Configurez le rôle de quarantaine dans /config (Anti-Raid), vérifiez Gérer les rôles et que le rôle de FoxSecura est au-dessus, puis examinez le membre.",
        de: "Die Quarantäne wurde nicht angewendet: Das Mitglied ist ohne Einschränkung auf dem Server. Die Quarantäne-Rolle in /config (Anti-Raid) konfigurieren, Rollen verwalten prüfen und dass die Rolle von FoxSecura darüber liegt, dann das Mitglied überprüfen."
    },
    QuarantineEvidenceRemovedRoles => {
        en: "Dangerous roles removed (not restored on release)",
        fr: "Rôles dangereux retirés (non rendus à la libération)",
        de: "Entfernte gefährliche Rollen (bei Freigabe nicht zurückgegeben)"
    },
    ConfigMemberProtection => {
        en: "Member arrivals",
        fr: "Arrivées de membres",
        de: "Beitritte von Mitgliedern"
    },
    ConfigMemberProtectionNotice => {
        en: "On join, in this order: blacklist (always active), anti-raid (see Lockdown), anti-bot (kicks bots missing from the whitelist), new accounts (ban and 7-day purge; otherwise quarantine, or a 10-minute timeout), alt accounts, impersonation (name of the owner or of a member with Administrator or Manage Server: quarantine), hoisted nicknames (rename, also on name changes). A ban, kick or quarantine stops the chain. FoxSecura's role must be above members; permissions: Kick Members, Ban Members, Timeout Members, Manage Nicknames, Manage Roles. Whitelisted members and the owner are never banned or quarantined. A false positive hits a legitimate member: review every incident. The Server Members intent is required.",
        fr: "À l'arrivée, dans cet ordre : liste noire (toujours active), anti-raid (voir Verrouillage), anti-bot (expulse les bots absents de la liste blanche), nouveaux comptes (ban et purge de 7 jours ; sinon quarantaine, ou timeout de 10 minutes), doubles comptes, usurpation (nom du propriétaire ou d'un membre avec Administrateur ou Gérer le serveur : quarantaine), pseudos hoistés (renommage, aussi lors d'un changement de nom). Un ban, une expulsion ou une quarantaine arrête la chaîne. Le rôle de FoxSecura doit être au-dessus des membres ; permissions : Expulser, Bannir, Exclure temporairement, Gérer les pseudos, Gérer les rôles. La liste blanche et le propriétaire ne sont jamais bannis ni mis en quarantaine. Un faux positif touche un membre légitime : examinez chaque incident. L'intent Server Members est requis.",
        de: "Beim Beitritt in dieser Reihenfolge: Blacklist (immer aktiv), Anti-Raid (siehe Sperre), Anti-Bot (kickt Bots, die nicht auf der Whitelist stehen), neue Konten (Bann und 7 Tage Nachrichten löschen; sonst Quarantäne oder 10 Minuten Timeout), Zweitkonten, Identitätsdiebstahl (Name des Inhabers oder eines Mitglieds mit Administrator oder Server verwalten: Quarantäne), gehoistete Spitznamen (Umbenennung, auch bei Namensänderungen). Bann, Kick oder Quarantäne beenden die Kette. Die Rolle von FoxSecura muss über den Mitgliedern liegen; Rechte: Kicken, Bannen, Timeout, Spitznamen verwalten, Rollen verwalten. Whitelist und Inhaber werden nie gebannt oder unter Quarantäne gestellt. Ein Fehlalarm trifft ein legitimes Mitglied: Jeden Vorfall prüfen. Der Server-Members-Intent ist erforderlich."
    },
    ConfigQuarantineRole => {
        en: "Quarantine role",
        fr: "Rôle de quarantaine",
        de: "Quarantäne-Rolle"
    },
    ConfigQuarantineNotConfigured => {
        en: "Not configured: no member can be quarantined (new accounts fall back to a timeout).",
        fr: "Non configuré : aucun membre ne peut être mis en quarantaine (les nouveaux comptes retombent sur un timeout).",
        de: "Nicht konfiguriert: Kein Mitglied kann unter Quarantäne gestellt werden (neue Konten erhalten ersatzweise einen Timeout)."
    },
    ConfigQuarantine => {
        en: "Quarantine",
        fr: "Quarantaine",
        de: "Quarantäne"
    },
    ConfigQuarantineNotice => {
        en: "Create: a “FoxSecura Quarantine” role without any permission, placed just below FoxSecura's role. Select: refused for @everyone, a managed role, a role FoxSecura cannot manage or a role with a dangerous permission. The role is denied View, Send, Threads, Reactions, Connect and Speak on categories and unsynced channels (one API call per channel, slower during a rate limit), and again on every new channel. Each quarantined member also gets a View/Connect deny of their own, restored exactly on release. Dangerous roles removed are not given back; a member who leaves and returns keeps their denies. Removing the role by hand restores their channels. Requires Manage Roles and Manage Channels; owner and administrators only.",
        fr: "Créer : un rôle « FoxSecura Quarantine » sans aucune permission, placé juste sous le rôle de FoxSecura. Choisir : refusé pour @everyone, un rôle géré, un rôle que FoxSecura ne peut pas gérer ou un rôle portant une permission dangereuse. Le rôle se voit refuser Voir, Écrire, Fils, Réactions, Se connecter et Parler sur les catégories et les salons non synchronisés (un appel API par salon, plus lent pendant une limitation de débit), puis sur chaque nouveau salon. Chaque membre en quarantaine reçoit aussi un refus Voir/Se connecter à son nom, restauré exactement à la libération. Les rôles dangereux retirés ne sont pas rendus ; un membre qui part et revient garde ses refus. Retirer le rôle à la main restaure ses salons. Requiert Gérer les rôles et Gérer les salons ; réservé au propriétaire et aux administrateurs.",
        de: "Erstellen: eine Rolle „FoxSecura Quarantine“ ohne Berechtigung, direkt unter der Rolle von FoxSecura. Auswählen: abgelehnt für @everyone, verwaltete Rollen, Rollen, die FoxSecura nicht verwalten kann, oder Rollen mit gefährlicher Berechtigung. Der Rolle werden Ansehen, Schreiben, Threads, Reaktionen, Verbinden und Sprechen in Kategorien und nicht synchronisierten Kanälen verweigert (ein API-Aufruf pro Kanal, langsamer bei Rate-Limits), danach in jedem neuen Kanal. Jedes Mitglied in Quarantäne erhält zusätzlich ein eigenes Verbot für Ansehen/Verbinden, das bei der Freigabe exakt wiederhergestellt wird. Entfernte gefährliche Rollen werden nicht zurückgegeben; wer geht und zurückkommt, behält die Verbote. Die Rolle von Hand zu entfernen stellt die Kanäle wieder her. Benötigt Rollen verwalten und Kanäle verwalten; nur Inhaber und Administratoren."
    },
    ConfigQuarantineCreateButton => {
        en: "Create quarantine role",
        fr: "Créer le rôle de quarantaine",
        de: "Quarantäne-Rolle erstellen"
    },
    ConfigQuarantineRoleSelect => {
        en: "Use an existing role as quarantine role",
        fr: "Utiliser un rôle existant comme rôle de quarantaine",
        de: "Bestehende Rolle als Quarantäne-Rolle verwenden"
    },
    ConfigQuarantineReleaseButton => {
        en: "Release a member",
        fr: "Libérer un membre",
        de: "Mitglied freigeben"
    },
    ConfigQuarantineAccessDenied => {
        en: "The quarantine role and member release are reserved for the server owner and administrators (Manage Server is not enough).",
        fr: "Le rôle de quarantaine et la libération d'un membre sont réservés au propriétaire du serveur et aux administrateurs (Gérer le serveur ne suffit pas).",
        de: "Quarantäne-Rolle und Freigabe von Mitgliedern sind dem Serverinhaber und Administratoren vorbehalten (Server verwalten reicht nicht)."
    },
    ConfigQuarantineSaved => {
        en: "Quarantine role saved. The channel lock is being applied in the background (one API call per category, channel without category or unsynced channel).",
        fr: "Rôle de quarantaine enregistré. Le verrou des salons est posé en arrière-plan (un appel API par catégorie, salon sans catégorie ou salon désynchronisé).",
        de: "Quarantäne-Rolle gespeichert. Die Kanalsperre wird im Hintergrund gesetzt (ein API-Aufruf pro Kategorie, Kanal ohne Kategorie oder nicht synchronisiertem Kanal)."
    },
    ConfigQuarantineRoleEveryone => {
        en: "@everyone cannot be the quarantine role: it would lock the whole server. Nothing was changed.",
        fr: "@everyone ne peut pas être le rôle de quarantaine : il verrouillerait tout le serveur. Rien n'a été modifié.",
        de: "@everyone kann nicht die Quarantäne-Rolle sein: Sie würde den ganzen Server sperren. Es wurde nichts geändert."
    },
    ConfigQuarantineRoleManaged => {
        en: "This role is managed by an integration (bot, subscription, boost) and cannot be assigned. Nothing was changed.",
        fr: "Ce rôle est géré par une intégration (bot, abonnement, boost) et ne peut pas être attribué. Rien n'a été modifié.",
        de: "Diese Rolle wird von einer Integration verwaltet (Bot, Abonnement, Boost) und kann nicht vergeben werden. Es wurde nichts geändert."
    },
    ConfigQuarantineRoleNotManageable => {
        en: "FoxSecura cannot manage this role: it needs Manage Roles and a role above it. Nothing was changed.",
        fr: "FoxSecura ne peut pas gérer ce rôle : il lui faut Gérer les rôles et un rôle au-dessus. Rien n'a été modifié.",
        de: "FoxSecura kann diese Rolle nicht verwalten: Es braucht Rollen verwalten und eine höhere Rolle. Es wurde nichts geändert."
    },
    ConfigQuarantineRoleDangerous => {
        en: "This role has dangerous permissions and would give them to quarantined members. Nothing was changed. Permissions:",
        fr: "Ce rôle porte des permissions dangereuses et les donnerait aux membres en quarantaine. Rien n'a été modifié. Permissions :",
        de: "Diese Rolle hat gefährliche Berechtigungen und würde sie Mitgliedern in Quarantäne geben. Es wurde nichts geändert. Berechtigungen:"
    },
    ConfigQuarantineRoleUnknown => {
        en: "This role or the server is not known to FoxSecura yet. Try again in a moment. Nothing was changed.",
        fr: "Ce rôle ou le serveur n'est pas encore connu de FoxSecura. Réessayez dans un instant. Rien n'a été modifié.",
        de: "Diese Rolle oder der Server ist FoxSecura noch nicht bekannt. Gleich erneut versuchen. Es wurde nichts geändert."
    },
    ConfigQuarantineMissingManageRoles => {
        en: "FoxSecura does not have Manage Roles: it cannot create the quarantine role. Nothing was changed.",
        fr: "FoxSecura n'a pas la permission Gérer les rôles : il ne peut pas créer le rôle de quarantaine. Rien n'a été modifié.",
        de: "FoxSecura hat keine Berechtigung Rollen verwalten: Die Quarantäne-Rolle kann nicht erstellt werden. Es wurde nichts geändert."
    },
    ConfigQuarantineCreateFailed => {
        en: "Discord refused to create the quarantine role. Check FoxSecura's permissions and try again.",
        fr: "Discord a refusé la création du rôle de quarantaine. Vérifiez les permissions de FoxSecura et réessayez.",
        de: "Discord hat das Erstellen der Quarantäne-Rolle abgelehnt. Die Berechtigungen von FoxSecura prüfen und erneut versuchen."
    },
    ConfigQuarantineReleaseDone => {
        en: "Member released: quarantine role removed and channels restored to their original state. Dangerous roles removed during the quarantine are not given back.",
        fr: "Membre libéré : rôle de quarantaine retiré et salons restaurés dans leur état d'origine. Les rôles dangereux retirés pendant la quarantaine ne sont pas rendus.",
        de: "Mitglied freigegeben: Quarantäne-Rolle entfernt und Kanäle in den ursprünglichen Zustand versetzt. Während der Quarantäne entfernte gefährliche Rollen werden nicht zurückgegeben."
    },
    ConfigQuarantineReleasePending => {
        en: "Release unfinished: something could not be restored. FoxSecura retries automatically every 5 minutes.",
        fr: "Libération inachevée : une partie n'a pas pu être restaurée. FoxSecura réessaie automatiquement toutes les 5 minutes.",
        de: "Freigabe unvollständig: Etwas konnte nicht wiederhergestellt werden. FoxSecura versucht es alle 5 Minuten automatisch erneut."
    },
    ConfigQuarantineReleaseNothing => {
        en: "Nothing to release: this member has neither the quarantine role nor a channel locked by FoxSecura.",
        fr: "Rien à libérer : ce membre n'a ni le rôle de quarantaine ni de salon verrouillé par FoxSecura.",
        de: "Nichts freizugeben: Dieses Mitglied hat weder die Quarantäne-Rolle noch einen von FoxSecura gesperrten Kanal."
    },
    ConfigQuarantineReleaseCounts => {
        en: "Channels restored: {restored}, already restored: {unchanged}, deleted: {missing}, failed: {failed}.",
        fr: "Salons restaurés : {restored}, déjà restaurés : {unchanged}, supprimés : {missing}, en échec : {failed}.",
        de: "Wiederhergestellte Kanäle: {restored}, bereits wiederhergestellt: {unchanged}, gelöscht: {missing}, fehlgeschlagen: {failed}."
    },
    ConfigNewAccountMinAge => {
        en: "Minimum account age (days)",
        fr: "Âge minimal des comptes (jours)",
        de: "Mindestalter der Konten (Tage)"
    },
    ConfigNewAccountMinAgeButton => {
        en: "Edit minimum age",
        fr: "Modifier l'âge minimal",
        de: "Mindestalter ändern"
    },
    ConfigNewAccountMinAgeModalTitle => {
        en: "Minimum account age",
        fr: "Âge minimal des comptes",
        de: "Mindestalter der Konten"
    },
    ConfigNewAccountMinAgeInput => {
        en: "Days (1 to 365)",
        fr: "Jours (1 à 365)",
        de: "Tage (1 bis 365)"
    },
    ConfigNewAccountMinAgeInvalid => {
        en: "Invalid value: the minimum age must be between 1 and 365 days. Nothing was changed.",
        fr: "Valeur invalide : l'âge minimal doit être compris entre 1 et 365 jours. Rien n'a été modifié.",
        de: "Ungültiger Wert: Das Mindestalter muss zwischen 1 und 365 Tagen liegen. Es wurde nichts geändert."
    },
    ConfigBlacklistUsers => {
        en: "Blacklist",
        fr: "Liste noire",
        de: "Blacklist"
    },
    ConfigBlacklistNotice => {
        en: "Blacklisted users are banned when they join (Ban Members and a role above them required). Adding a member who is already on the server does not ban them. The whitelist and the blacklist exclude each other; the owner and FoxSecura itself are refused.",
        fr: "Les utilisateurs de la liste noire sont bannis à leur arrivée (Bannir des membres et un rôle au-dessus d'eux requis). Inscrire un membre déjà présent ne le bannit pas. Les listes blanche et noire s'excluent ; le propriétaire et FoxSecura lui-même sont refusés.",
        de: "Benutzer auf der Blacklist werden beim Beitritt gebannt (Mitglieder bannen und eine Rolle über ihnen erforderlich). Ein bereits anwesendes Mitglied einzutragen bannt es nicht. Whitelist und Blacklist schließen sich aus; der Inhaber und FoxSecura selbst werden abgelehnt."
    },
    ConfigBlacklistAddButton => {
        en: "Add to blacklist",
        fr: "Ajouter à la liste noire",
        de: "Zur Blacklist hinzufügen"
    },
    ConfigBlacklistRemoveButton => {
        en: "Remove from blacklist",
        fr: "Retirer de la liste noire",
        de: "Aus der Blacklist entfernen"
    },
    ConfigBlacklistInput => {
        en: "User ID (or mention)",
        fr: "Identifiant de l'utilisateur (ou mention)",
        de: "Benutzer-ID (oder Erwähnung)"
    },
    ConfigBlacklistInvalidId => {
        en: "Invalid user ID: enter the 17 to 20 digit ID (Developer Mode → Copy User ID). Nothing was changed.",
        fr: "Identifiant invalide : saisissez l'identifiant de 17 à 20 chiffres (mode développeur → Copier l'identifiant). Rien n'a été modifié.",
        de: "Ungültige Benutzer-ID: die 17- bis 20-stellige ID eingeben (Entwicklermodus → ID kopieren). Es wurde nichts geändert."
    },
    ConfigBlacklistOwnerRefused => {
        en: "The server owner cannot be blacklisted. Nothing was changed.",
        fr: "Le propriétaire du serveur ne peut pas être mis sur la liste noire. Rien n'a été modifié.",
        de: "Der Serverinhaber kann nicht auf die Blacklist gesetzt werden. Es wurde nichts geändert."
    },
    ConfigBlacklistBotRefused => {
        en: "FoxSecura cannot blacklist itself. Nothing was changed.",
        fr: "FoxSecura ne peut pas se mettre lui-même sur la liste noire. Rien n'a été modifié.",
        de: "FoxSecura kann sich nicht selbst auf die Blacklist setzen. Es wurde nichts geändert."
    },
    ConfigBlacklistWhitelistedRefused => {
        en: "This user is on the whitelist: the whitelist and the blacklist exclude each other. Remove them from the whitelist first. Nothing was changed.",
        fr: "Cet utilisateur est sur la liste blanche : les listes blanche et noire s'excluent. Retirez-le d'abord de la liste blanche. Rien n'a été modifié.",
        de: "Dieser Benutzer steht auf der Whitelist: Whitelist und Blacklist schließen sich aus. Zuerst aus der Whitelist entfernen. Es wurde nichts geändert."
    },
    ConfigWhitelistBlacklistedRefused => {
        en: "A selected user is on the blacklist: the whitelist and the blacklist exclude each other. Remove them from the blacklist first. Nothing was changed.",
        fr: "Un utilisateur choisi est sur la liste noire : les listes blanche et noire s'excluent. Retirez-le d'abord de la liste noire. Rien n'a été modifié.",
        de: "Ein ausgewählter Benutzer steht auf der Blacklist: Whitelist und Blacklist schließen sich aus. Zuerst aus der Blacklist entfernen. Es wurde nichts geändert."
    },
    ConfigBlacklistAccessDenied => {
        en: "The blacklist is reserved for the server owner and administrators (Manage Server is not enough).",
        fr: "La liste noire est réservée au propriétaire du serveur et aux administrateurs (Gérer le serveur ne suffit pas).",
        de: "Die Blacklist ist dem Serverinhaber und Administratoren vorbehalten (Server verwalten reicht nicht)."
    },
    ConfigBlacklistScope => {
        en: "Blacklist scope",
        fr: "Portée de la liste noire",
        de: "Geltungsbereich der Blacklist"
    },
    LockdownLiftSummary => {
        en: "Temporary lockdown lifted",
        fr: "Verrouillage temporaire levé",
        de: "Temporäre Sperre aufgehoben"
    },
    LockdownLiftStaffSummary => {
        en: "Temporary lockdown lifted by staff",
        fr: "Verrouillage temporaire levé par l'équipe",
        de: "Temporäre Sperre vom Team aufgehoben"
    },
    LockdownLiftRecommendationDone => {
        en: "Every channel got its original Send Messages permission for @everyone and its original slowmode back.",
        fr: "Chaque salon a retrouvé la permission Envoyer des messages d'origine de @everyone et son ancien mode lent.",
        de: "Jeder Kanal hat die ursprüngliche Berechtigung Nachrichten senden für @everyone und seinen alten Slowmode zurückerhalten."
    },
    LockdownLiftRecommendationPending => {
        en: "Some channels are still locked: FoxSecura retries every minute. Check that it still has Manage Channels on them.",
        fr: "Des salons restent verrouillés : FoxSecura réessaie toutes les minutes. Vérifiez qu'il a toujours Gérer les salons sur ces salons.",
        de: "Einige Kanäle sind noch gesperrt: FoxSecura versucht es jede Minute erneut. Prüfen, ob es dort noch Kanäle verwalten hat."
    },
    ModuleAntiRaid => {
        en: "Anti-raid (join bursts)",
        fr: "Anti-raid (rafales d'arrivées)",
        de: "Anti-Raid (Beitrittswellen)"
    },
    AntiRaidSummary => {
        en: "Join burst: server locked down and member quarantined",
        fr: "Rafale d'arrivées : serveur verrouillé et membre mis en quarantaine",
        de: "Beitrittswelle: Server gesperrt und Mitglied unter Quarantäne"
    },
    AntiRaidEvidenceLockdown => {
        en: "Lockdown",
        fr: "Verrouillage",
        de: "Sperre"
    },
    AntiRaidLockdownApplied => {
        en: "applied: {locked} channels locked, {failed} failed, {total} in total",
        fr: "posé : {locked} salons modifiés, {failed} en échec, {total} au total",
        de: "aktiv: {locked} Kanäle gesperrt, {failed} fehlgeschlagen, {total} insgesamt"
    },
    AntiRaidLockdownAlreadyActive => {
        en: "already active",
        fr: "déjà actif",
        de: "bereits aktiv"
    },
    AntiRaidLockdownFailed => {
        en: "failed: {locked} channels locked, {failed} failed, {total} in total",
        fr: "en échec : {locked} salons modifiés, {failed} en échec, {total} au total",
        de: "fehlgeschlagen: {locked} Kanäle gesperrt, {failed} fehlgeschlagen, {total} insgesamt"
    },
    AntiRaidRecommendationQuarantined => {
        en: "Check the members who joined just before: they are not quarantined. The server stays locked for 10 minutes; lift it early in /config if this was a legitimate wave.",
        fr: "Vérifiez les membres arrivés juste avant : ils ne sont pas mis en quarantaine. Le serveur reste verrouillé 10 minutes ; levez-le plus tôt dans /config s'il s'agissait d'une vague légitime.",
        de: "Die kurz zuvor beigetretenen Mitglieder prüfen: Sie sind nicht unter Quarantäne. Der Server bleibt 10 Minuten gesperrt; bei einer legitimen Welle in /config früher aufheben."
    },
    AntiRaidRecommendationFailed => {
        en: "The member could not be quarantined or timed out: check the quarantine role, Manage Roles and Moderate Members, then review the recent joins by hand.",
        fr: "Le membre n'a pu être ni mis en quarantaine ni exclu temporairement : vérifiez le rôle de quarantaine, Gérer les rôles et Exclure temporairement des membres, puis examinez les arrivées récentes à la main.",
        de: "Das Mitglied konnte weder unter Quarantäne gestellt noch mit Timeout belegt werden: Quarantänerolle, Rollen verwalten und Mitglieder moderieren prüfen, dann die letzten Beitritte von Hand prüfen."
    },
    ModuleHoneypot => {
        en: "Honeypot channel",
        fr: "Salon piège (honeypot)",
        de: "Honeypot-Kanal"
    },
    HoneypotSummary => {
        en: "Message posted in the honeypot channel",
        fr: "Message posté dans le salon piège",
        de: "Nachricht im Honeypot-Kanal gepostet"
    },
    HoneypotRecommendationQuarantined => {
        en: "The author is quarantined and their dangerous roles were removed (not given back). Check the account: only automated accounts write in a channel hidden from members.",
        fr: "L'auteur est en quarantaine et ses rôles dangereux ont été retirés (non rendus). Examinez le compte : seuls des comptes automatisés écrivent dans un salon caché aux membres.",
        de: "Der Autor ist unter Quarantäne, seine gefährlichen Rollen wurden entfernt (nicht zurückgegeben). Konto prüfen: Nur automatisierte Konten schreiben in einen für Mitglieder verborgenen Kanal."
    },
    HoneypotRecommendationUnknownPermissions => {
        en: "The author's permissions could not be established from the cache: the message was deleted but nobody was quarantined, to avoid a false positive on the staff. Check the author by hand.",
        fr: "Les permissions de l'auteur n'ont pas pu être établies d'après le cache : le message a été supprimé mais personne n'a été mis en quarantaine, pour éviter un faux positif sur l'équipe. Vérifiez l'auteur à la main.",
        de: "Die Berechtigungen des Autors ließen sich aus dem Cache nicht ermitteln: Die Nachricht wurde gelöscht, aber niemand unter Quarantäne gestellt, um einen Fehlalarm beim Team zu vermeiden. Autor von Hand prüfen."
    },
    ModuleAntiDoubleAccount => {
        en: "Alt accounts",
        fr: "Doubles comptes",
        de: "Zweitkonten"
    },
    DoubleAccountSummary => {
        en: "Likely alternate account of a member",
        fr: "Double compte probable d'un membre",
        de: "Wahrscheinliches Zweitkonto eines Mitglieds"
    },
    DoubleAccountEvidenceMatch => {
        en: "Same name and avatar as member",
        fr: "Même nom et même avatar que le membre",
        de: "Gleicher Name und Avatar wie Mitglied"
    },
    DoubleAccountRecommendationReview => {
        en: "Review the duplicate: compare both accounts, then release the member from /config if this is a coincidence.",
        fr: "Examinez le doublon : comparez les deux comptes, puis libérez le membre depuis /config s'il s'agit d'une coïncidence.",
        de: "Das Duplikat prüfen: beide Konten vergleichen und das Mitglied bei einem Zufall über /config freigeben."
    },
    ConfigAntiRaidLimits => {
        en: "Anti-raid threshold",
        fr: "Seuil de l'anti-raid",
        de: "Anti-Raid-Schwelle"
    },
    ConfigAntiRaidLimitsValue => {
        en: "{threshold} joins in {window} s",
        fr: "{threshold} arrivées en {window} s",
        de: "{threshold} Beitritte in {window} s"
    },
    ConfigAntiRaidLimitsButton => {
        en: "Edit anti-raid threshold",
        fr: "Modifier le seuil anti-raid",
        de: "Anti-Raid-Schwelle ändern"
    },
    ConfigAntiRaidLimitsModalTitle => {
        en: "Anti-raid threshold",
        fr: "Seuil de l'anti-raid",
        de: "Anti-Raid-Schwelle"
    },
    ConfigAntiRaidThresholdInput => {
        en: "Joins (2 to 50)",
        fr: "Arrivées (2 à 50)",
        de: "Beitritte (2 bis 50)"
    },
    ConfigAntiRaidWindowInput => {
        en: "Window in seconds (5 to 120)",
        fr: "Fenêtre en secondes (5 à 120)",
        de: "Zeitfenster in Sekunden (5 bis 120)"
    },
    ConfigAntiRaidInvalidLimits => {
        en: "Invalid values: the threshold must be between 2 and 50 joins and the window between 5 and 120 seconds. Nothing was changed.",
        fr: "Valeurs invalides : le seuil doit être compris entre 2 et 50 arrivées et la fenêtre entre 5 et 120 secondes. Rien n'a été modifié.",
        de: "Ungültige Werte: Die Schwelle muss zwischen 2 und 50 Beitritten und das Zeitfenster zwischen 5 und 120 Sekunden liegen. Es wurde nichts geändert."
    },
    ConfigLockdown => {
        en: "Server lockdown",
        fr: "Verrouillage du serveur",
        de: "Serversperre"
    },
    ConfigLockdownTitle => {
        en: "Lockdown",
        fr: "Verrouillage",
        de: "Sperre"
    },
    ConfigLockdownInactive => {
        en: "Inactive",
        fr: "Inactif",
        de: "Inaktiv"
    },
    ConfigLockdownActive => {
        en: "Active, lifted {time}",
        fr: "Actif, levée prévue {time}",
        de: "Aktiv, Aufhebung {time}"
    },
    ConfigLockdownLifting => {
        en: "Being lifted",
        fr: "Levée en cours",
        de: "Wird aufgehoben"
    },
    ConfigLockdownRetry => {
        en: "Lift unfinished, next attempt {time}",
        fr: "Levée inachevée, nouvelle tentative {time}",
        de: "Aufhebung unvollständig, nächster Versuch {time}"
    },
    ConfigLockdownNotice => {
        en: "A join burst denies Send Messages to @everyone on every channel except threads, then sets a 10 s slowmode (never lowering a stricter one), for 10 minutes. The original state is saved first and restored exactly, even after a restart; failed channels stay locked and are retried every minute. Cost: up to two API calls per channel each way, slower during a rate limit. A false positive locks the server for 10 minutes: lift it with the button (owner and administrators). Requires Manage Channels.",
        fr: "Une rafale d'arrivées refuse Envoyer des messages à @everyone sur tous les salons sauf les fils, puis pose un mode lent de 10 s (sans jamais réduire un mode lent plus strict), pour 10 minutes. L'état d'origine est enregistré d'abord et restauré exactement, même après un redémarrage ; les salons en échec restent verrouillés et sont retentés toutes les minutes. Coût : jusqu'à deux appels API par salon dans chaque sens, plus lent pendant une limitation de débit. Un faux positif verrouille le serveur 10 minutes : levez-le avec le bouton (propriétaire et administrateurs). Requiert Gérer les salons.",
        de: "Eine Beitrittswelle verweigert @everyone Nachrichten senden in allen Kanälen außer Threads und setzt 10 Minuten lang einen Slowmode von 10 s (ein strengerer wird nie gesenkt). Der Ursprungszustand wird zuerst gespeichert und exakt wiederhergestellt, auch nach einem Neustart; fehlgeschlagene Kanäle bleiben gesperrt und werden jede Minute erneut versucht. Kosten: bis zu zwei API-Aufrufe pro Kanal in jede Richtung, langsamer bei Rate-Limits. Ein Fehlalarm sperrt den Server 10 Minuten: mit der Schaltfläche aufheben (Inhaber und Administratoren). Benötigt Kanäle verwalten."
    },
    ConfigLockdownLiftButton => {
        en: "Lift lockdown",
        fr: "Lever le verrouillage",
        de: "Sperre aufheben"
    },
    ConfigLockdownAccessDenied => {
        en: "Lifting the lockdown is reserved for the server owner and administrators (Manage Server is not enough).",
        fr: "La levée du verrouillage est réservée au propriétaire du serveur et aux administrateurs (Gérer le serveur ne suffit pas).",
        de: "Das Aufheben der Sperre ist dem Serverinhaber und Administratoren vorbehalten (Server verwalten reicht nicht)."
    },
    ConfigLockdownLiftNothing => {
        en: "No lockdown to lift.",
        fr: "Aucun verrouillage à lever.",
        de: "Keine Sperre aufzuheben."
    },
    ConfigLockdownLiftDone => {
        en: "Lockdown lifted: every channel got its original permissions and slowmode back.",
        fr: "Verrouillage levé : chaque salon a retrouvé ses permissions et son mode lent d'origine.",
        de: "Sperre aufgehoben: Jeder Kanal hat seine ursprünglichen Berechtigungen und seinen Slowmode zurück."
    },
    ConfigLockdownLiftPending => {
        en: "Lift unfinished: some channels are still locked, FoxSecura retries every minute.",
        fr: "Levée inachevée : des salons restent verrouillés, FoxSecura réessaie toutes les minutes.",
        de: "Aufhebung unvollständig: Einige Kanäle sind noch gesperrt, FoxSecura versucht es jede Minute erneut."
    },
    ConfigLockdownLiftUnresolved => {
        en: "The server is not available to FoxSecura yet: the lift will be retried in a minute.",
        fr: "Le serveur n'est pas encore disponible pour FoxSecura : la levée sera retentée dans une minute.",
        de: "Der Server ist für FoxSecura noch nicht verfügbar: Die Aufhebung wird in einer Minute erneut versucht."
    },
    ConfigHoneypotChannel => {
        en: "Trap channel",
        fr: "Salon piège",
        de: "Fallenkanal"
    },
    ConfigHoneypotNotConfigured => {
        en: "Not configured",
        fr: "Non configuré",
        de: "Nicht konfiguriert"
    },
    ConfigHoneypotSelect => {
        en: "Choose the trap channel (choose it again to remove it)",
        fr: "Choisir le salon piège (le rechoisir le retire)",
        de: "Fallenkanal wählen (erneut wählen entfernt ihn)"
    },
    ConfigHoneypotNotice => {
        en: "Keep the trap channel out of real members' way (collapsed category, explicit name) but readable and writable by @everyone, or bots cannot post either: only automated accounts write there. A message there is deleted and its author quarantined with their dangerous roles removed, without timeout fallback. Exempt: owner, Administrator, Manage Server, whitelist. If the author's permissions cannot be read from the cache, the message is only deleted and reported. An ignored channel is never watched. Requires Manage Messages and Manage Roles.",
        fr: "Cachez le salon piège aux vrais membres (catégorie repliée, nom explicite) sans le leur interdire : s'il n'est pas lisible et ouvert à l'écriture pour @everyone, les robots non plus ne peuvent pas y écrire. Seuls des comptes automatisés y écrivent. Un message y est supprimé et son auteur mis en quarantaine avec retrait de ses rôles dangereux, sans repli timeout. Exemptés : propriétaire, Administrateur, Gérer le serveur, liste blanche. Si les permissions de l'auteur ne peuvent pas être lues dans le cache, le message est seulement supprimé et signalé. Un salon ignoré n'est jamais surveillé. Requiert Gérer les messages et Gérer les rôles.",
        de: "Den Fallenkanal vor echten Mitgliedern verstecken (eingeklappte Kategorie, eindeutiger Name), aber für @everyone lesbar und beschreibbar lassen, sonst können auch Bots nicht schreiben: Nur automatisierte Konten schreiben dort. Eine Nachricht dort wird gelöscht und ihr Autor unter Quarantäne gestellt, gefährliche Rollen werden entfernt, ohne Timeout als Ersatz. Ausgenommen: Inhaber, Administrator, Server verwalten, Whitelist. Lassen sich die Berechtigungen des Autors nicht aus dem Cache lesen, wird die Nachricht nur gelöscht und gemeldet. Ein ignorierter Kanal wird nie überwacht. Benötigt Nachrichten verwalten und Rollen verwalten."
    },
    ConfigDoubleAccountNotice => {
        en: "A joining member with the same display name and custom avatar as a member in FoxSecura's cache is quarantined, or timed out for 10 minutes without a usable quarantine role. Only the cache is compared, never a full member fetch; it is warmed up at startup for servers where the module is on (best effort). Owner, whitelist and bots are never checked. Requires Manage Roles, Moderate Members and the Server Members intent.",
        fr: "Un membre qui arrive avec le même nom affiché et le même avatar personnalisé qu'un membre du cache de FoxSecura est mis en quarantaine, ou exclu 10 minutes sans rôle de quarantaine utilisable. Seul le cache est comparé, jamais une lecture complète des membres ; il est préchauffé au démarrage pour les serveurs où le module est actif (au mieux). Le propriétaire, la liste blanche et les bots ne sont jamais vérifiés. Requiert Gérer les rôles, Exclure temporairement et l'intent Server Members.",
        de: "Ein beitretendes Mitglied mit gleichem Anzeigenamen und eigenem Avatar wie ein Mitglied im Cache von FoxSecura wird unter Quarantäne gestellt oder ohne nutzbare Quarantäne-Rolle 10 Minuten mit Timeout belegt. Verglichen wird nur der Cache, nie ein vollständiger Abruf der Mitglieder; er wird beim Start für Server mit aktivem Modul vorgewärmt (nach Möglichkeit). Inhaber, Whitelist und Bots werden nie geprüft. Benötigt Rollen verwalten, Mitglieder moderieren und den Server-Members-Intent."
        },
    ModuleAntiMassBan => {
        en: "Mass bans",
        fr: "Bannissements de masse",
        de: "Massenbanns"
    },
    ModuleAntiMassKick => {
        en: "Mass kicks",
        fr: "Expulsions de masse",
        de: "Massenkicks"
    },
    ModuleAntiMassTimeout => {
        en: "Mass timeouts",
        fr: "Exclusions temporaires de masse",
        de: "Massen-Timeouts"
    },
    ModuleAntiMassUnban => {
        en: "Mass unbans",
        fr: "Débannissements de masse",
        de: "Massen-Entbannungen"
    },
    ModuleAntiMassChannelCreate => {
        en: "Mass channel creation",
        fr: "Création de salons en masse",
        de: "Massenerstellung von Kanälen"
    },
    ModuleAntiMassRoleCreate => {
        en: "Mass role creation",
        fr: "Création de rôles en masse",
        de: "Massenerstellung von Rollen"
    },
    ModuleAntiEmojiStickerNuke => {
        en: "Emoji and sticker nuke",
        fr: "Nuke d'emojis et de stickers",
        de: "Emoji- und Sticker-Nuke"
    },
    ModuleAntiMassRoleGrant => {
        en: "Mass role grants",
        fr: "Attribution de rôles en masse",
        de: "Massenvergabe von Rollen"
    },
    ModulePanicMode => {
        en: "Panic mode",
        fr: "Mode panique",
        de: "Panikmodus"
        },
    AntiNukeSummary => {
        en: "Burst of sensitive actions by the same author",
        fr: "Rafale d'actions sensibles par un même auteur",
        de: "Serie sensibler Aktionen durch denselben Urheber"
    },
    PanicModeSummary => {
        en: "Panic mode: several anti-nuke protections fired at once, server locked down",
        fr: "Mode panique : plusieurs protections anti-nuke ont réagi en même temps, serveur verrouillé",
        de: "Panikmodus: Mehrere Anti-Nuke-Schutzfunktionen haben gleichzeitig ausgelöst, Server gesperrt"
        },
    AntiNukeExemptSummary => {
        en: "Burst of sensitive actions by a whitelisted author: no containment",
        fr: "Rafale d'actions sensibles par un auteur de la liste blanche : aucun confinement",
        de: "Serie sensibler Aktionen durch einen Urheber auf der Whitelist: keine Eindämmung"
    },
    AntiNukeEvidenceTarget => {
        en: "Last target",
        fr: "Dernière cible",
        de: "Letztes Ziel"
    },
    AntiNukeRecommendation => {
        en: "Review the author's permissions and roles. Actions already taken (bans, kicks, timeouts, creations) are never undone automatically: review them one by one. Release the author from /config if this was legitimate.",
        fr: "Revoyez les permissions et les rôles de l'auteur. Les actions déjà faites (bans, expulsions, exclusions, créations) ne sont jamais annulées automatiquement : revoyez-les une par une. Libérez l'auteur depuis /config si c'était légitime.",
        de: "Überprüfe die Berechtigungen und Rollen des Urhebers. Bereits ausgeführte Aktionen (Banns, Kicks, Timeouts, Erstellungen) werden nie automatisch rückgängig gemacht: Prüfe sie einzeln. Gib den Urheber über /config frei, falls es legitim war."
    },
    AntiNukeRecommendationExempt => {
        en: "Whitelisted author: confirm with them that these actions were intended, and review their permissions.",
        fr: "Auteur de la liste blanche : confirmez avec lui que ces actions étaient voulues, et revoyez ses permissions.",
        de: "Urheber auf der Whitelist: Kläre mit ihm, ob diese Aktionen beabsichtigt waren, und überprüfe seine Berechtigungen."
        },
    PanicModeEvidenceModules => {
        en: "Correlated modules",
        fr: "Modules corrélés",
        de: "Korrelierte Module"
    },
    PanicModeRecommendation => {
        en: "The server is locked down for 15 minutes (30 s slowmode). Check the anti-nuke incidents above, review the permissions of every author, then lift the lockdown from /config once the server is safe.",
        fr: "Le serveur est verrouillé 15 minutes (mode lent de 30 s). Consultez les incidents anti-nuke précédents, revoyez les permissions de chaque auteur, puis levez le verrouillage depuis /config une fois le serveur sûr.",
        de: "Der Server ist 15 Minuten gesperrt (30 s Slowmode). Prüfe die vorherigen Anti-Nuke-Vorfälle, überprüfe die Berechtigungen jedes Urhebers und hebe die Sperre über /config auf, sobald der Server sicher ist."
    },
    PanicModeRecommendationFailed => {
        en: "The lockdown could not be applied (see the action status, usually Manage Channels is missing): lock the server down by hand and review the permissions of every author.",
        fr: "Le verrouillage n'a pas pu être posé (voir l'état de l'action, souvent Gérer les salons manquant) : verrouillez le serveur à la main et revoyez les permissions de chaque auteur.",
        de: "Die Sperre konnte nicht gesetzt werden (siehe Aktionsstatus, meist fehlt Kanäle verwalten): Sperre den Server manuell und überprüfe die Berechtigungen jedes Urhebers."
        },
    ConfigAntiNuke => {
        en: "Anti-nuke",
        fr: "Anti-nuke",
        de: "Anti-Nuke"
    },
    ConfigAntiNukeThresholds => {
        en: "Burst thresholds (actions by one author)",
        fr: "Seuils des rafales (actions d'un même auteur)",
        de: "Schwellenwerte (Aktionen eines Urhebers)"
    },
    ConfigAntiNukeThresholdsValue => {
        en: "Bans: {ban} in 20 s · Unbans: {unban} in 20 s · Channel and role creation: {create} in 20 s · Emojis and stickers: {emoji} in 20 s · Role grants: {grant} in 20 s · Kicks and timeouts: {fixed} in 30 s (fixed)",
        fr: "Bans : {ban} en 20 s · Débannissements : {unban} en 20 s · Créations de salons et de rôles : {create} en 20 s · Emojis et stickers : {emoji} en 20 s · Attributions de rôles : {grant} en 20 s · Expulsions et exclusions : {fixed} en 30 s (fixe)",
        de: "Banns: {ban} in 20 s · Entbannungen: {unban} in 20 s · Kanal- und Rollenerstellung: {create} in 20 s · Emojis und Sticker: {emoji} in 20 s · Rollenvergaben: {grant} in 20 s · Kicks und Timeouts: {fixed} in 30 s (fest)"
    },
    ConfigPanicThresholdValue => {
        en: "{threshold} different modules within 30 s: 15-minute lockdown, 30 s slowmode",
        fr: "{threshold} modules différents en 30 s : verrouillage de 15 minutes, mode lent de 30 s",
        de: "{threshold} verschiedene Module in 30 s: 15 Minuten Sperre, 30 s Slowmode"
    },
    ConfigAntiNukeNoticeTitle => {
        en: "Before enabling",
        fr: "Avant d'activer",
        de: "Vor dem Aktivieren"
    },
    ConfigAntiNukeNotice => {
        en: "Requires View Audit Log (without it Discord sends nothing and the anti-nuke stays blind), Manage Roles and Manage Channels, with FoxSecura's role above the roles to remove. The author of a burst is quarantined and loses their dangerous roles, without timeout fallback; whitelisted authors, the owner and FoxSecura itself are never contained. Actions already taken (bans, kicks, creations) are never undone. A false positive quarantines a legitimate moderator (release them from Anti-Raid) and panic mode can lock the server for 15 minutes. Counters live in memory: lost on restart, never shared between instances.",
        fr: "Requiert Voir les logs du serveur (sans elle, Discord n'envoie rien et l'anti-nuke est aveugle), Gérer les rôles et Gérer les salons, avec le rôle de FoxSecura au-dessus des rôles à retirer. L'auteur d'une rafale est mis en quarantaine et perd ses rôles dangereux, sans repli timeout ; la liste blanche, le propriétaire et FoxSecura ne sont jamais confinés. Les actions déjà faites (bans, expulsions, créations) ne sont jamais annulées. Un faux positif met en quarantaine un modérateur légitime (libération dans Anti-Raid) et le mode panique peut verrouiller le serveur 15 minutes. Les compteurs sont en mémoire : perdus au redémarrage, jamais partagés entre instances.",
        de: "Benötigt Audit-Log anzeigen (ohne sie sendet Discord nichts und der Anti-Nuke ist blind), Rollen verwalten und Kanäle verwalten, mit der Rolle von FoxSecura über den zu entfernenden Rollen. Der Urheber einer Serie wird unter Quarantäne gestellt und verliert seine gefährlichen Rollen, ohne Timeout als Ersatz; Whitelist, Inhaber und FoxSecura werden nie eingedämmt. Bereits ausgeführte Aktionen (Banns, Kicks, Erstellungen) werden nie rückgängig gemacht. Ein Fehlalarm stellt einen legitimen Moderator unter Quarantäne (Freigabe unter Anti-Raid) und der Panikmodus kann den Server 15 Minuten sperren. Zähler liegen im Speicher: beim Neustart verloren, nie zwischen Instanzen geteilt."
    },
    ConfigAntiNukeThresholdsButton => {
        en: "Burst thresholds",
        fr: "Seuils des rafales",
        de: "Schwellenwerte"
    },
    ConfigPanicThresholdButton => {
        en: "Panic mode threshold",
        fr: "Seuil du mode panique",
        de: "Schwelle des Panikmodus"
    },
    ConfigAntiNukeThresholdsModalTitle => {
        en: "Anti-nuke thresholds (2 to 20)",
        fr: "Seuils de l'anti-nuke (2 à 20)",
        de: "Anti-Nuke-Schwellen (2 bis 20)"
    },
    ConfigAntiNukeBanInput => {
        en: "Bans in 20 s",
        fr: "Bans en 20 s",
        de: "Banns in 20 s"
    },
    ConfigAntiNukeUnbanInput => {
        en: "Unbans in 20 s",
        fr: "Débannissements en 20 s",
        de: "Entbannungen in 20 s"
    },
    ConfigAntiNukeCreateInput => {
        en: "Channel or role creations in 20 s",
        fr: "Créations de salons ou de rôles en 20 s",
        de: "Kanal- oder Rollenerstellungen in 20 s"
    },
    ConfigAntiNukeEmojiStickerInput => {
        en: "Emoji or sticker changes in 20 s",
        fr: "Emojis ou stickers modifiés en 20 s",
        de: "Emoji- oder Sticker-Änderungen in 20 s"
    },
    ConfigAntiNukeRoleGrantInput => {
        en: "Role grants in 20 s",
        fr: "Attributions de rôles en 20 s",
        de: "Rollenvergaben in 20 s"
    },
    ConfigPanicThresholdInput => {
        en: "Different modules in 30 s (2 to 10)",
        fr: "Modules différents en 30 s (2 à 10)",
        de: "Verschiedene Module in 30 s (2 bis 10)"
    },
    ConfigAntiNukeInvalidThresholds => {
        en: "Invalid thresholds: enter whole numbers from 2 to 20. Nothing was changed.",
        fr: "Seuils invalides : saisissez des nombres entiers de 2 à 20. Rien n'a été modifié.",
        de: "Ungültige Schwellen: Gib ganze Zahlen von 2 bis 20 ein. Nichts wurde geändert."
    },
    ConfigPanicInvalidThreshold => {
        en: "Invalid threshold: enter a whole number from 2 to 10. Nothing was changed.",
        fr: "Seuil invalide : saisissez un nombre entier de 2 à 10. Rien n'a été modifié.",
        de: "Ungültige Schwelle: Gib eine ganze Zahl von 2 bis 10 ein. Nichts wurde geändert."
    }
}
