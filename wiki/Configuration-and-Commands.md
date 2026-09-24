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

### Autorisation

La commande `/config` et tous ses composants (menu, boutons, sélecteurs, modal) sont réservés au **propriétaire du serveur** et aux membres disposant de `ADMINISTRATOR` ou `MANAGE_GUILD`. Les permissions sont vérifiées côté bot à chaque interaction, pas seulement à l'ouverture du tableau de bord ; les autres membres reçoivent un refus éphémère.

La **liste blanche** exige un droit plus fort : propriétaire du serveur ou `ADMINISTRATOR` uniquement ; `MANAGE_GUILD` ne suffit pas. Figurer sur la liste blanche ne donne jamais accès à `/config`.

| Action | Propriétaire | `ADMINISTRATOR` | `MANAGE_GUILD` seul | Autre membre |
| --- | --- | --- | --- | --- |
| Ouvrir `/config`, Anti-Spam, salons ignorés | oui | oui | oui | non |
| Modifier la liste blanche | oui | oui | non | non |

### Catégorie Anti-Spam

La catégorie Anti-Spam est la première catégorie réellement persistée et lue par un moteur :

| Réglage | Colonne SQLite | Défaut | Bornes |
| --- | --- | --- | --- |
| Activation | `anti_spam_enabled` | désactivé | on/off |
| Seuil de messages | `anti_spam_message_threshold` | 5 | 2 à 50 |
| Fenêtre (secondes) | `anti_spam_window_seconds` | 5 | 1 à 60 |

- Le bouton **Activer / Désactiver** enregistre directement la valeur cible.
- Le bouton **Modifier les seuils** ouvre un modal prérempli ; les valeurs hors bornes ou non numériques sont refusées sans écriture.
- Les bornes sont validées dans le domaine (`MessageFloodConfig::validated`), dans le repository et par des contraintes `CHECK` SQLite.
- L'état affiché est relu depuis la base après chaque écriture : il correspond exactement à ce que le moteur utilise au message suivant.

Identifiants internes : `foxsecura:config:anti_spam:enable`, `foxsecura:config:anti_spam:disable`, `foxsecura:config:anti_spam:limits` et le modal `foxsecura:config:anti_spam:limits_modal`.

### Catégorie Contrôle d'accès

Liste blanche (utilisateurs, rôles) et salons ignorés, persistés par la migration 3 et lus par le pipeline de messages (voir [Modules de protection](Protection-Modules#liste-blanche-et-salons-ignorés)).

| Liste | Table SQLite | Droit requis |
| --- | --- | --- |
| Utilisateurs exemptés | `guild_whitelist_users` | propriétaire ou `ADMINISTRATOR` |
| Rôles exemptés | `guild_whitelist_roles` | propriétaire ou `ADMINISTRATOR` |
| Salons ignorés | `guild_ignored_channels` | accès normal à `/config` |

- Chaque liste se modifie avec un sélecteur natif Discord (utilisateurs, rôles, salons), jusqu'à 25 entrées par soumission. Le sélecteur fonctionne **en bascule** : une entrée absente est ajoutée, une entrée présente est retirée.
- Les sélecteurs de la liste blanche ne sont affichés qu'aux membres autorisés ; le droit est de toute façon revérifié à chaque soumission.
- `@everyone` est refusé comme rôle exempté ; la sélection entière est alors rejetée sans écriture.
- L'état affiché (mentions, tronquées si la liste dépasse la taille d'un champ d'embed) est relu depuis la base après chaque écriture.

Identifiants internes : `foxsecura:config:access_control:whitelist_users`, `foxsecura:config:access_control:whitelist_roles` et `foxsecura:config:access_control:ignored_channels`.

## Important : interface et configuration persistée

Le tableau de bord est plus large que le modèle SQLite actuellement persisté. La base de données version 3 stocke la langue d'une guild, les salons associés aux types de logs, les réglages Anti-Spam, la liste blanche et les salons ignorés. Les autres catégories affichent encore un état de substitution.

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

### `DATABASE_PATH`

Optionnelle. Chemin du fichier SQLite ouvert au démarrage (migrations appliquées automatiquement). Par défaut : `data/foxsecura.sqlite3`. Une base impossible à ouvrir ou à migrer empêche le démarrage du bot.

Les secrets liés à de futurs fournisseurs externes doivent suivre la même philosophie : injection par environnement ou gestionnaire de secrets, jamais stockage en base en clair par défaut et jamais commit Git.

## Intents Discord

La configuration par défaut active :

- `GUILDS` ;
- `GUILD_MODERATION` ;
- `GUILD_MEMBERS` (privilégié : **Server Members Intent**) ;
- `GUILD_MESSAGES` : réception des nouveaux messages pour l'anti-spam.

`MESSAGE_CONTENT` (intent privilégié) n'est **pas** demandé : l'anti-spam compte les messages à partir de l'auteur, du salon et de l'horodatage, sans lire leur contenu. Il ne sera ajouté qu'avec les modules qui analysent réellement le contenu.

Chaque nouvel intent privilégié doit être justifié. FoxSecura ne doit pas demander plus de données Discord que ce qui est nécessaire aux fonctionnalités réellement activées.

## Permissions du bot

Les permissions Discord ne sont pas équivalentes aux intents. Une protection peut recevoir un événement mais échouer à appliquer une action si le bot manque de permission, si la hiérarchie de rôles l'empêche ou si la ressource a disparu.

La couche de logs prévoit explicitement des codes d'échec pour ces cas, notamment permissions manquantes, hiérarchie de rôles, ressource absente ou indisponibilité Discord.

Permissions nécessaires aux fonctionnalités branchées :

| Fonctionnalité | Permission du bot | Où |
| --- | --- | --- |
| Anti-Spam (suppression du message déclencheur) | `MANAGE_MESSAGES` | salons protégés |
| Envoi des incidents | `VIEW_CHANNEL`, `SEND_MESSAGES` | salon de logs `message` |

Sans `MANAGE_MESSAGES`, l'anti-spam produit un incident `Critical` avec l'action `Skipped` et le code `MissingPermission`.
