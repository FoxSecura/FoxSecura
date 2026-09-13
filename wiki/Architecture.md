# Architecture

FoxSecura privilégie une architecture où les détecteurs et règles de sécurité restent testables sans nécessiter une connexion Discord réelle.

## Vue d'ensemble

Le Gateway transmet les événements à `src/app`. Les composants vont vers `src/commands` ; les événements de sécurité vont vers `src/runtime`, qui construit les snapshots pour `src/protection`, planifie les actions, les applique via Serenity et produit les logs. SQLite conserve la configuration générale et les états nécessaires à la restauration.

## `src/app`

`App` possède le token Discord et les `GatewayIntents`. `App::from_env()` récupère `DISCORD_TOKEN`; `App::run()` construit Poise puis Serenity. Les commandes sont fournies par `crate::commands::all()` et l'event handler central route les interactions de composants et les événements messages, membres, audit et AutoMod.

`AppData` partage un `Arc<ProtectionRuntime>` : configuration par serveur, détecteurs en mémoire, client SQLite, admission IA et sérialisation des actions. Les verrous des détecteurs sont libérés avant les appels réseau. Une maintenance restaure les ralentissements expirés toutes les 30 secondes, y compris après redémarrage.

## `src/commands`

Le registre retourne actuellement trois commandes : `config`, `help` et `status`. Le module `config` fournit un tableau de bord éphémère basé sur un menu de sélection et des catégories de configuration.

La commande ne doit pas être confondue avec un moteur de persistance complet : certaines catégories affichent encore un état de substitution, ce qui permet de construire l'interface avant de brancher chaque réglage.

## `src/database`

La couche de données est divisée en client, migrations, modèles et repository. Les identifiants Discord sont stockés sous forme textuelle dans SQLite puis validés lors de la lecture. Cette approche évite les problèmes de plage d'entiers tout en conservant les snowflakes comme `u64` dans le domaine Rust.

La version de schéma actuelle est suivie dans `schema_migrations`. La migration initiale crée la configuration de guild et les destinations de logs. La migration 2 conserve les ralentissements temporaires et l’identité des règles AutoMod gérées, y compris leur nom canonique.

## `src/i18n`

La couche i18n définit un vocabulaire de clés de texte et trois langues : français, anglais et allemand. Le français est la langue par défaut. La résolution utilise le préfixe primaire des locales Discord, ce qui permet par exemple de résoudre `fr-FR` vers `fr`.

## `src/logs`

La journalisation de sécurité est modélisée en données structurées : type de log, sévérité, code d'action, statut de l'action, code d'échec, preuves, acteur et ressources affectées. Ce modèle est destiné à rendre les incidents exploitables autant par Discord que par des tests ou une future télémétrie.

## `src/protection/shared`

Les primitives communes comprennent notamment la détection de rafales d'actions, une décision partagée et l'analyse de signaux d'URL. Les protections spécifiques doivent réutiliser cette couche lorsque le concept est transversal plutôt que dupliquer une logique.

## Moteurs de protection

`anti_nuke` traite les actions sensibles et l'intégrité du serveur. `anti_raid` se concentre sur les arrivées, comptes et webhooks. `anti_spam` analyse les messages, mentions, pièces jointes et liens. `automod` regroupe des règles locales et le rapprochement avec l'AutoMod natif Discord. `ai_moderation` isole la classification assistée par modèle, ses politiques, son schéma et ses fournisseurs.

Voir [Modules de protection](https://github.com/FoxSecura/FoxSecura/wiki/Protection-Modules) et [Modération IA](https://github.com/FoxSecura/FoxSecura/wiki/AI-Moderation) pour le détail.

## Règle d'intégration

Une fonctionnalité est plus sûre lorsqu'elle suit ce chemin :

```text
événement brut → snapshot minimal → détecteur → décision → action → résultat structuré → log
```

Cette séparation permet de tester une décision sans appeler Discord et de tester un exécuteur d'action indépendamment d'un détecteur.

## État d'intégration

Les 43 clés de modules disponibles sont raccordées aux événements pertinents. La configuration des protections est chargée depuis un fichier JSON au démarrage ; `/config` reste un tableau de bord sans modification de ces réglages. Voir [Runtime et activation](Runtime-Protection.md) pour les actions, exemptions et limites. Les tests valident les décisions et la persistance sans connecter un bot à Discord.
