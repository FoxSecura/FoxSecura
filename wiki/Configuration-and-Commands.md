# Configuration et commandes

FoxSecura utilise Poise pour les commandes slash et Serenity pour les composants Discord.

## Commandes actuelles

Le registre de commandes contient actuellement :

| Commande | Rôle |
| --- | --- |
| `/config` | ouvre le tableau de bord de configuration dans une réponse éphémère |
| `/help` | présente l'aide disponible |
| `/status` | expose l'état général prévu par le module de statut |

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

Le tableau de bord est plus large que le modèle SQLite actuellement persisté. La base de données version 1 stocke pour l'instant la langue d'une guild et les salons associés aux types de logs.

Cela signifie qu'une catégorie visible dans `/config` peut représenter une **surface d'interface prévue** avant que son stockage et son exécution soient entièrement branchés. Les futures PR doivent éviter de présenter un réglage comme actif tant que les trois couches suivantes ne sont pas reliées :

```text
UI de configuration
      ↓
validation + persistance
      ↓
runtime / moteur de protection
```

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
- `GUILD_MEMBERS`.

Chaque nouvel intent privilégié doit être justifié. FoxSecura ne doit pas demander plus de données Discord que ce qui est nécessaire aux fonctionnalités réellement activées.

## Permissions du bot

Les permissions Discord ne sont pas équivalentes aux intents. Une protection peut recevoir un événement mais échouer à appliquer une action si le bot manque de permission, si la hiérarchie de rôles l'empêche ou si la ressource a disparu.

La couche de logs prévoit explicitement des codes d'échec pour ces cas, notamment permissions manquantes, hiérarchie de rôles, ressource absente ou indisponibilité Discord.
