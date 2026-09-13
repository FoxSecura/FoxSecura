# Configuration et commandes

FoxSecura utilise Poise pour les commandes slash et Serenity pour les composants Discord.

## Commandes actuelles

Le registre de commandes contient actuellement :

| Commande | Rôle |
| --- | --- |
| `/config` | ouvre le tableau de bord de configuration dans une réponse éphémère |
| `/help` | présente l'aide disponible |
| `/status` | affiche le mode de protection, le nombre de modules configurés et la version |

Les commandes sont enregistrées globalement au démarrage du framework.

## Tableau de bord `/config`

La commande `/config` affiche un menu de catégories. Les catégories déclarées aujourd'hui sont :

- paramètres généraux ;
- anti-raid ;
- anti-spam ;
- protection du serveur ;
- contrôle d'accès ;
- anti-double-compte ;
- AutoMod ;
- modération IA ;
- utilitaires ;
- système de sauvegarde ;
- logs et santé.

Le composant utilise l'identifiant interne `foxsecura:config:category`. Lorsqu'une catégorie est choisie, FoxSecura met à jour le même message éphémère avec son nom, sa description et son état.

## Important : interface et configuration persistée

Les protections se règlent dans le fichier JSON désigné par `FOXSECURA_PROTECTION_CONFIG`, chargé au démarrage. `/config` reste un tableau de bord ; il ne modifie pas ces réglages. `/status` affiche la configuration demandée, sans garantir que Discord autorise toutes les actions. Voir le [guide complet](Runtime-Protection.md).

SQLite, en version de schéma 2, conserve la langue, les salons de logs, les ralentissements temporaires et les identifiants des règles AutoMod gérées.

## Langue

Les locales prises en charge par la couche i18n sont `fr`, `en` et `de`. Le français est le fallback. Les réponses de `/config` résolvent la locale Discord de l'interaction.

## Variables d'environnement

### `DISCORD_TOKEN`

Obligatoire pour le runtime actuel. Il contient le token du bot Discord.

Les secrets liés à de futurs fournisseurs externes doivent suivre la même philosophie : injection par environnement ou gestionnaire de secrets, jamais stockage en base en clair par défaut et jamais commit Git.

## Intents Discord

La configuration par défaut active :

- `GUILDS` ;
- `GUILD_MODERATION` ;
- `GUILD_MEMBERS` ;
- `GUILD_MESSAGES` et `MESSAGE_CONTENT` ;
- `GUILD_WEBHOOKS` ;
- `AUTO_MODERATION_CONFIGURATION` et `AUTO_MODERATION_EXECUTION`.

Activez Server Members Intent et Message Content Intent dans le portail développeur.

Chaque nouvel intent privilégié doit être justifié. FoxSecura ne doit pas demander plus de données Discord que ce qui est nécessaire aux fonctionnalités réellement activées.

## Permissions du bot

Les permissions Discord ne sont pas équivalentes aux intents. Une protection peut recevoir un événement mais échouer à appliquer une action si le bot manque de permission, si la hiérarchie de rôles l'empêche ou si la ressource a disparu.

La couche de logs prévoit explicitement des codes d'échec pour ces cas, notamment permissions manquantes, hiérarchie de rôles, ressource absente ou indisponibilité Discord.
