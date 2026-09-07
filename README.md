# FoxSecura v2

[![Rust](https://img.shields.io/badge/Rust-1.98.1-DEA584?style=plastic&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tokio](https://img.shields.io/badge/Tokio-1.53.1-000000?style=plastic&logo=tokio&logoColor=white)](https://tokio.rs/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL--3.0--only-663399?style=plastic&logo=gnu&logoColor=white)](https://www.gnu.org/licenses/agpl-3.0.html)

FoxSecura v2 est la réécriture en **Rust** de FoxSecura, un bot Discord orienté **sécurité**, **protection** et **modération** des serveurs.

> Le projet est actuellement en phase de reconstruction.

## Stack technique

FoxSecura v2 repose sur une stack Rust moderne et asynchrone :

- **Rust 1.98.1** : langage principal du projet ;
- **Tokio 1.53.1** : runtime asynchrone ;
- **Serenity 0.12.5** : client Discord, Gateway, événements et API Discord ;
- **Poise 0.7.0** : framework de commandes construit au-dessus de Serenity.

Les versions principales sont actuellement épinglées dans `Cargo.toml` afin de conserver une base reproductible et maîtrisée.

## Objectifs

- disposer d'une base Rust moderne, robuste et maintenable ;
- construire une architecture modulaire pour les fonctionnalités de sécurité ;
- privilégier la fiabilité, les performances et la sûreté ;
- séparer clairement les commandes, les événements Discord et les modules de sécurité ;
- permettre une évolution progressive du bot sans dépendre de l'ancienne base propriétaire.

## Prérequis

- Rust **1.98.1** ;
- Cargo ;
- un token de bot Discord ;
- l'intent privilégié **Server Members Intent** activé dans le Discord Developer Portal.

Le projet utilise également les intents Discord suivants :

- `GUILDS` ;
- `GUILD_MODERATION` ;
- `GUILD_MEMBERS`.

## Configuration

Le token Discord doit être fourni avec la variable d'environnement `DISCORD_TOKEN`.

Sous Linux ou macOS :

```bash
export DISCORD_TOKEN="votre_token"
```

Sous PowerShell :

```powershell
$env:DISCORD_TOKEN="votre_token"
```

> Ne stockez jamais le token du bot directement dans le code source ou dans un fichier suivi par Git.

## Développement

Clonez le dépôt puis vérifiez la compilation :

```bash
git clone https://github.com/FoxSecura/FoxSecura-v2.git
cd FoxSecura-v2
cargo check
```

Pour démarrer FoxSecura :

```bash
cargo run
```

## État du projet

La base actuelle fournit :

- le runtime asynchrone Tokio ;
- le client Discord Serenity ;
- la connexion au Gateway Discord ;
- les intents nécessaires à la future couche de sécurité ;
- Poise comme framework prévu pour les commandes du bot ;
- une base sous licence AGPLv3.

L'architecture modulaire, les commandes et les fonctionnalités de sécurité seront ajoutées progressivement.

## Licence

FoxSecura v2 est distribué sous la **GNU Affero General Public License v3.0 uniquement** (`AGPL-3.0-only`).

Consultez le fichier [`LICENSE`](LICENSE) pour le texte complet de la licence.

Copyright © 2026 FoxSecura contributors.
