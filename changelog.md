# Changelog

Toutes les modifications importantes de FoxSecura sont documentées dans ce fichier.

Le projet suit le versionnage sémantique. La version `0.1.0` correspond à la première base Rust complète du projet, construite le 7 septembre 2026.

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
