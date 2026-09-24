# Changelog

Toutes les modifications importantes de FoxSecura sont documentées dans ce fichier.

Le projet suit le versionnage sémantique. La version `0.1.0` correspond à la première base Rust complète du projet, construite le 7 septembre 2026.

## [Non publié]

### Runtime Discord

- `AppData` porte désormais la base SQLite (`Arc<Database>`) et l'état en mémoire des protections.
- Ouverture de la base au démarrage via `DATABASE_PATH` (défaut : `data/foxsecura.sqlite3`), migrations appliquées automatiquement.
- Ajout de l'intent `GUILD_MESSAGES`.
- Ajout de l'intent privilégié `MESSAGE_CONTENT`, nécessaire aux filtres de contenu ; un refus de Discord (code 4014) affiche au démarrage quoi activer et où dans le portail développeur.
- Dispatch de `MessageUpdate` : les modifications de messages passent par les filtres de contenu (jamais par l'anti-spam).
- Dispatch de `Message` vers un pipeline de protection des messages ; les erreurs des modules sont journalisées et ne sont jamais propagées au client.
- Gardes du pipeline : messages hors guilde, de webhook ou d'auteur bot ignorés.
- Ordre des gardes aligné sur la V1 : hors guilde, salon ignoré, webhook, bot, puis auteur sur liste blanche (aucune sanction).
- Configuration de la guilde, salon ignoré, liste blanche de l'auteur et modules activés lus en un seul passage `spawn_blocking` par message.

### Anti-Spam

- Branchement de bout en bout de l'anti-spam par rafales de messages : clé `(guilde, membre)`, déclenchement quand le nombre de messages dans la fenêtre atteint le seuil, état borné à 10 000 clés.
- Suppression du message déclencheur avec résultats `deleted`, `not_deletable` (`Skipped`, `MissingPermission`) ou `failed` (`Failed`).
- Incident structuré (type `Message`, preuve chiffrée, recommandation) journalisé localement et envoyé dans le salon de logs `message` s'il est configuré.
- Alignement de `message_flood::evaluate` sur la sémantique `count >= seuil` (auparavant `count > limite`).
- Cœur pur testable sans Discord : `MessageSnapshot`, `screen_message`, `MessageFloodTracker`, `plan_response`, `build_incident`.

### Filtres de contenu

- Six filtres branchés de bout en bout : caractères invisibles, liens malveillants, liens adultes, invitations Discord, `@everyone`/`@here`, mentions de masse (seuil 5).
- Ordre de la V1 avec court-circuit : le premier filtre qui déclenche arrête la chaîne (une seule suppression, un seul incident par message) ; filtres évalués avant l'anti-spam.
- Un message retenu par un filtre n'est pas compté par l'anti-spam.
- Les auteurs sur liste blanche subissent la suppression (correction de contenu) mais aucune sanction ; rien ne s'applique dans un salon ignoré.
- Messages modifiés analysés avec les mêmes filtres ; la version courante est relue avant suppression pour ne jamais effacer une version déjà corrigée.
- Incident par module (preuve : hôte, invitation, motif, nombre de mentions, type d'obfuscation ; extrait du message), sévérité `Warning` si supprimé, `Critical` sinon.
- Plan, résultat de suppression et squelette d'incident mutualisés avec l'anti-spam (`protection::shared`).

### Liste blanche et salons ignorés

- La liste blanche est une exemption de sanction de l'auteur, jamais un droit d'administration : elle ne donne pas accès à `/config`.
- Exemption si l'identifiant de l'auteur ou l'un de ses rôles est listé ; rôles absents de l'événement → pas d'exemption par rôle.
- Paramètre des rôles attribués par FoxSecura (qui n'exemptent jamais), vide tant que vérification, quarantaine et rôle limité ne sont pas portés.
- Un auteur exempté saute l'anti-spam (les filtres de contenu s'appliquent encore) ; un salon ignoré court-circuite toutes les protections.
- `@everyone` refusé comme rôle exempté.

### Configuration

- Migration SQLite `2` : colonnes `anti_spam_enabled`, `anti_spam_message_threshold` (2 à 50) et `anti_spam_window_seconds` (1 à 60) dans `guild_configs`.
- Repository : lecture sans écriture (`find_guild_config`), `set_anti_spam_enabled` et `set_anti_spam_limits` validés.
- `/config` réservé au propriétaire du serveur et aux membres `ADMINISTRATOR` ou `MANAGE_GUILD`, vérifié à chaque interaction.
- Catégorie Anti-Spam de `/config` : interrupteur et modal des seuils, persistés et relus par le moteur.
- Migration SQLite `3` : tables `guild_whitelist_users`, `guild_whitelist_roles` et `guild_ignored_channels` (clé composite, suppression en cascade avec la guilde, `CHECK` contre `@everyone`).
- Repository : ajout et retrait idempotents, test d'appartenance et listes pour la liste blanche et les salons ignorés.
- Catégorie Contrôle d'accès de `/config` : sélecteurs natifs en bascule pour les utilisateurs, rôles et salons.
- Liste blanche réservée au propriétaire du serveur et à `ADMINISTRATOR` (`MANAGE_GUILD` ne suffit pas) ; salons ignorés avec l'accès normal à `/config`.
- Migration SQLite `4` : table générique `guild_protection_modules` (clé composite, suppression en cascade, modules désactivés par défaut) ; clés validées par l'énumération `ProtectionModule`. L'anti-spam garde ses colonnes.
- `/config` : un interrupteur persistant par filtre de contenu dans les catégories Anti-Spam et AutoMod.

### Logs

- Ajout de `format_security_log_message` : membre, salon, preuve chiffrée et recommandation, sans ping.
- Rendu des extraits, domaines et textes issus de messages via `inline_literal` : code en ligne neutralisé (ni formatage, ni lien cliquable, ni fausse ligne, ni caractère invisible ou bidirectionnel).

## [0.1.0] - 2026-09-07

### Fondation du projet

- Initialisation du projet Cargo avec Rust 2024.
- Toolchain Rust épinglée sur `1.98.1` avec `rustfmt` et `clippy`.
- Ajout de Tokio `1.53.1` pour le runtime asynchrone.
- Ajout de Serenity `0.12.5` avec les fonctionnalités Discord explicitement sélectionnées et `rustls_backend`.
- Ajout de Poise `0.7.0` pour les commandes Discord.
- Adaptation du framework et du gestionnaire d'événements à l'API Poise 0.7.
- Utilisation de `DISCORD_TOKEN` comme variable d'environnement pour le token Discord.
- Configuration des intents `GUILDS`, `GUILD_MODERATION` et `GUILD_MEMBERS`.
- Découpage de l'application en modules dédiés pour les données, intents, événements et démarrage du bot.
- Ajout du registre des commandes et de leur enregistrement global auprès de Discord.
- Ajout du `.gitignore` Rust.
- Ajout de la configuration GitHub Funding.
- Passage du dépôt sous licence `AGPL-3.0-only`.

### Commandes Discord

- Ajout de `/config` comme tableau de bord privé et éphémère basé sur un sélecteur de catégories.
- Ajout du routage des interactions de composants pour le dashboard `/config`.
- Ajout des catégories de configuration principales : paramètres généraux, Anti-Raid, Anti-Spam, protection serveur, contrôle d'accès, doubles comptes, AutoMod, AI Moderation, utilitaires, sauvegardes et logs/santé.
- Ajout de `/help` avec contenu localisé.
- Ajout de `/status` pour afficher l'état de l'application, du Gateway, du framework, des commandes et des moteurs de protection.
- Limitation volontaire des slash commands publiques à `/config`, `/help` et `/status`.

### Architecture des protections

- Création de `src/protection/` comme racine commune des moteurs de sécurité.
- Ajout de `ProtectionDecision` comme décision typée partagée.
- Ajout de `ActionBurstDetector` pour mutualiser les fenêtres temporelles et éviter les compteurs concurrents.
- Ajout des signaux URL partagés, de l'extraction des hôtes et de la détection de credentials dans les URL.
- Organisation des familles `anti_spam`, `anti_raid`, `anti_nuke`, `automod`, `ai_moderation` et `shared`.
- Mise en place de tests organisés en miroir sous `tests/protection/`.

### Anti-Spam

- Implémentation de la famille Anti-Spam.
- Ajout de `anti_everyone`.
- Ajout de `anti_ghost_ping` avec suivi des récidives.
- Ajout de `anti_mass_mention`.
- Ajout de `anti_ping_owner`.
- Ajout de `anti_scam` en composition avec les détecteurs déjà existants.
- Ajout de `anti_spam_ping`.
- Ajout de `attachment_filter`.
- Ajout de `auto_slowmode`.
- Ajout de `invisible_char_filter`.
- Ajout de `malicious_link`.
- Finalisation de `message_flood` et du coeur de détection Anti-Spam.
- Réutilisation de `ActionBurstDetector` pour les protections temporelles au lieu de créer plusieurs trackers indépendants.
- Ajout des tests d'intégration et des tests unitaires de la famille Anti-Spam.

### Anti-Raid

- Implémentation de la famille Anti-Raid.
- Ajout de `join_burst` pour les rafales d'arrivées.
- Ajout de `anti_bot`.
- Ajout de `anti_double_account` avec corrélation de signaux indépendants.
- Ajout de `anti_impersonation` avec normalisation des noms, accents, séparateurs et substitutions courantes.
- Ajout de `anti_new_account` pour contrôler l'âge des comptes.
- Ajout de `anti_nickname_hoisting` et du nettoyage associé.
- Ajout de `honeypot` avec exemptions prévues pour les utilisateurs autorisés.
- Ajout de `webhook_message` en réutilisant les détecteurs Anti-Spam et AutoMod existants.
- Ajout de `webhook_watch` pour la corrélation des modifications de webhooks et de leur exécuteur.
- Réutilisation des primitives partagées pour les compteurs temporels.
- Ajout des tests de la famille Anti-Raid.

### Anti-Nuke

- Implémentation de la famille Anti-Nuke.
- Ajout de la protection contre les bans massifs.
- Ajout de la protection contre les kicks massifs.
- Ajout de la protection contre les timeouts massifs.
- Ajout de la protection contre les unbans massifs.
- Ajout des protections contre les créations massives de salons et de rôles.
- Ajout de la protection contre les attributions massives de rôles.
- Ajout des protections contre les suppressions de salons et de rôles.
- Ajout de la protection contre les attaques sur emojis et stickers.
- Ajout de `anti_permissions`.
- Ajout de `anti_external_application`.
- Ajout de `anti_server_edit`.
- Ajout de `anti_vanity_change`.
- Ajout de `automod_rule_guard`.
- Ajout de `server_guard`.
- Ajout de `limit_role`.
- Ajout de `panic_mode`, basé sur plusieurs types distincts d'incidents observés dans une fenêtre temporelle.
- Mutualisation des rafales d'actions sensibles autour du moteur partagé.
- Ajout des politiques communes `Ignore`, `Alert` et `Enforce` pour les changements sensibles.
- Ajout des tests de la famille Anti-Nuke.

### AutoMod

- Implémentation de la famille AutoMod.
- Ajout de la détection des liens adultes.
- Finalisation de la détection des invitations Discord.
- Ajout du filtre de mots interdits avec listes françaises et anglaises.
- Ajout du filtrage de profil membre prévu pour Discord AutoMod.
- Ajout d'un registre typé des règles AutoMod natives.
- Gestion des règles Invite Link Blocking, Adult Links Filtering, Bad Words Filter, Mention Spam Blocking, Spam Blocking et Member Profile Filter.
- Ajout d'un planificateur de réconciliation des règles Discord AutoMod.
- Gestion des règles absentes, désactivées, dupliquées ou renommées.
- Gestion des migrations de trigger et des conflits de triggers singleton.
- Réutilisation des moteurs Anti-Spam pour les règles de spam et de mentions au lieu de dupliquer la logique.
- Ajout des tests de la famille AutoMod.

### AI Moderation

- Organisation complète de `src/protection/ai_moderation/` par responsabilités.
- Ajout des modules `action`, `analysis`, `availability`, `context`, `diagnostics`, `model_input`, `notice`, `policy`, `prefilter`, `providers`, `rules`, `runtime`, `safety_mapping`, `schema`, `settings`, `telemetry` et `types`.
- Conservation du principe : le modèle classe, FoxSecura décide, la couche action applique.
- Ajout d'un prefilter limitant l'analyse aux contenus réellement pertinents et à une longueur maximale de 4000 caractères.
- Ajout des catégories et niveaux de sévérité FoxSecura.
- Ajout du moteur de règles et des seuils de décision.
- Ajout de la policy et de la validation stricte des résultats.
- Ajout du contexte pseudonymisé et borné.
- Ajout du formatage des entrées selon le type de modèle.
- Ajout du cache runtime avec TTL.
- Ajout de la détection des analyses identiques déjà en cours.
- Ajout d'une limite de concurrence.
- Ajout d'un circuit breaker avec cooldown.
- Ajout de diagnostics, disponibilité et télémétrie.
- Ajout de tests couvrant policy, schéma, contexte, mapping, runtime, prefilter, règles et adapters.

### OpenAI

- Choix d'OpenAI comme fournisseur unique de AI Moderation.
- Verrouillage du modèle sur `omni-moderation-latest`.
- Utilisation de l'endpoint officiel `POST /v1/moderations`.
- Utilisation de `OPENAI_API_KEY` comme variable d'environnement.
- Ajout de `reqwest 0.13.4` avec TLS Rustls.
- Ajout de `serde_json 1.0.145` pour la validation des réponses JSON.
- Suppression des chemins spécifiques Nemotron et OpenRouter.
- Mapping des catégories natives OpenAI vers les catégories FoxSecura.
- Non-utilisation des `category_scores` pour décider directement des sanctions.
- Garantie que le provider ne peut jamais appliquer directement une sanction Discord.
- Protection contre l'exposition de la clé API dans les sorties de debug.

### Internationalisation

- Création de `src/i18n/` avec seulement trois fichiers source : `mod.rs`, `language.rs` et `catalog.rs`.
- Prise en charge officielle de l'anglais, du français et de l'allemand.
- Prise en charge des variantes de locales Discord comme `en-US`, `en-GB`, `fr-FR` et `de-DE`.
- Fallback en français pour les locales non supportées.
- Catalogue de traductions typé et centralisé.
- Génération centralisée de `TextKey`, de la liste des clés et des traductions.
- Intégration de l'i18n dans `/config`, `/help`, `/status` et les interactions du dashboard.
- Ajout de tests vérifiant que chaque clé possède une traduction non vide dans les trois langues.

### Logs

- Création de `src/logs/`.
- Ajout des types de logs `message`, `server`, `member`, `channel`, `role` et `moderation`.
- Ajout des incidents de sécurité typés avec identifiants `FS-*`.
- Ajout des niveaux `Info`, `Warning` et `Critical`.
- Ajout de la gestion des preuves et des résultats d'actions.
- Ajout du formatage centralisé des incidents.
- Définition de la structure de logs FoxSecura avec les salons techniques `fs-message-logs`, `fs-server-logs`, `fs-member-logs`, `fs-channel-logs`, `fs-role-logs` et `fs-mod-logs`.
- Suppression des anciens alias `VulpesGuard` hérités de l'ancien projet.
- Intégration complète des textes lisibles des logs dans le système i18n EN / FR / DE.
- Traduction des types, sévérités, actions, statuts, titres et champs des incidents.
- Ajout des tests de localisation et de structure des logs.

### Base de données

- Création de `src/database/` avec `mod.rs`, `client.rs`, `migrations.rs`, `models.rs` et `repository.rs`.
- Ajout de SQLite via `rusqlite 0.40.2` avec SQLite embarqué.
- Activation des clés étrangères.
- Activation du mode WAL.
- Configuration de `synchronous = NORMAL`.
- Ajout d'un `busy_timeout` de 5 secondes.
- Ajout de la table `schema_migrations`.
- Ajout de la migration initiale pour `guild_configs`.
- Ajout de la migration initiale pour `guild_log_channels`.
- Persistance de la langue des serveurs en `en`, `fr` ou `de`.
- Persistance des six types de salons de logs.
- Ajout des repositories pour lire et modifier la langue et les salons de logs.
- Stockage des identifiants Discord en texte dans SQLite et conversion vers `u64` côté Rust.
- Ajout de tests pour les migrations, la persistance, le CRUD des salons, l'isolation entre serveurs et la réouverture d'une base fichier.

### Site et documentation

- Création d'un site moderne dans `docs/` pour GitHub Pages.
- Ajout d'une landing page produit et documentation complète.
- Ajout des sections protections, architecture, commandes, installation, OpenAI, logs, SQLite, i18n, sécurité, état du projet et FAQ.
- Ajout d'un design responsive pour desktop et mobile.
- Ajout des thèmes sombre et clair.
- Ajout de la navigation multilingue FR / EN / DE.
- Ajout du logo officiel FoxSecura comme identité principale du site.
- Adoption d'une palette orange, noir et blanc cohérente avec le logo.
- Ajout du logo comme favicon et image Open Graph.
- Correction de la page blanche provoquée par l'initialisation JavaScript du premier site.
- Simplification de la publication pour garder le contenu visible même si JavaScript échoue.
- Correction du fichier WebP du logo officiel après détection d'un asset corrompu.
- Correction du hero afin d'afficher les cinq familles de protection dans le même tableau.
- Suppression des badges flottants Anti-Spam et Logs du hero.
- Déplacement de SQLite, i18n et Logs dans une zone technique séparée.
- Restauration et finalisation du site complet après les corrections de mise en page.
- Activation et validation du déploiement GitHub Pages.

### Documentation du dépôt

- Création et mise à jour du README pour refléter la stack Rust actuelle.
- Ajout des badges Rust `1.98.1`, Tokio `1.53.1` et licence `AGPL-3.0-only`.
- Documentation de Serenity et Poise.
- Mise à jour du README après le passage à Poise `0.7.0`.
- Renommage du dépôt de `FoxSecura-v2` vers `FoxSecura`.
- Mise à jour des URLs, commandes de clone et métadonnées vers `FoxSecura/FoxSecura`.
- Suppression du branding `v2` dans le README et dans l'i18n.

### CI et qualité

- Ajout du workflow GitHub Actions pour Rust.
- Validation systématique avec `cargo check`.
- Ajout de `cargo test` comme étape obligatoire du workflow.
- Validation des familles de protection par des suites de tests dédiées.
- Validation de l'i18n, des logs et de la base SQLite par des tests dédiés.
- Correction d'un pattern Unicode inaccessible dans le prefilter AI Moderation afin d'obtenir une compilation Rust sans warning associé.
- Maintien de versions principales épinglées pour rendre les builds reproductibles.

### État de cette version

`0.1.0` fournit le socle Rust, les moteurs de protection, l'internationalisation, les logs, la persistance SQLite, AI Moderation avec OpenAI, les commandes principales et le site de documentation.

L'intégration runtime complète de chaque moteur avec tous les événements Discord, la configuration persistante détaillée par protection et l'application finale de toutes les actions de modération restent les prochaines étapes du projet.
