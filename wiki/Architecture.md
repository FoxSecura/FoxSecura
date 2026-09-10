# Architecture

FoxSecura privilégie une architecture où les détecteurs et règles de sécurité restent testables sans nécessiter une connexion Discord réelle.

## Vue d'ensemble

```text
Discord Gateway
      │
      ▼
src/app ─────────► src/commands
      │
      └──────────► événements / composants

src/lib.rs
  ├── database
  ├── i18n
  ├── logs
  └── protection
       ├── shared
       ├── anti_nuke
       ├── anti_raid
       ├── anti_spam
       ├── automod
       └── ai_moderation
```

## `src/app`

`App` possède le token Discord et les `GatewayIntents`. `App::from_env()` récupère `DISCORD_TOKEN`; `App::run()` construit Poise puis Serenity. Les commandes sont fournies par `crate::commands::all()` et l'event handler central passe aujourd'hui principalement les interactions de composants au module de commandes.

`AppData` est volontairement léger à ce stade. Cette surface pourra accueillir progressivement les services réellement nécessaires au runtime sans faire dépendre les moteurs purs de l'état global Discord.

## `src/commands`

Le registre retourne actuellement trois commandes : `config`, `help` et `status`. Le module `config` fournit un tableau de bord éphémère basé sur un menu de sélection et des catégories de configuration.

La commande ne doit pas être confondue avec un moteur de persistance complet : certaines catégories affichent encore un état de substitution, ce qui permet de construire l'interface avant de brancher chaque réglage.

## `src/database`

La couche de données est divisée en client, migrations, modèles et repository. Les identifiants Discord sont stockés sous forme textuelle dans SQLite puis validés lors de la lecture. Cette approche évite les problèmes de plage d'entiers tout en conservant les snowflakes comme `u64` dans le domaine Rust.

La version de schéma actuelle est suivie dans `schema_migrations`. La migration initiale crée la configuration de guild et les destinations de logs.

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

Le code contient déjà de nombreux détecteurs et tests. En revanche, le handler Discord exécutable ne relaie pas encore tous les événements vers toutes les protections. Toute documentation ou PR doit donc distinguer clairement :

- module implémenté ;
- module testé ;
- module branché au runtime ;
- module configurable par guild ;
- module considéré stable pour production.
