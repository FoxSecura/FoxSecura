# FoxSecura

[![Rust](https://img.shields.io/badge/Rust-1.98.1-DEA584?style=plastic&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tokio](https://img.shields.io/badge/Tokio-1.53.1-000000?style=plastic&logo=tokio&logoColor=white)](https://tokio.rs/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL--3.0--only-663399?style=plastic&logo=gnu&logoColor=white)](https://www.gnu.org/licenses/agpl-3.0.html)

FoxSecura est la réécriture en **Rust** de FoxSecura, un bot Discord orienté **sécurité**, **protection** et **modération** des serveurs.

> Le projet est actuellement en phase de reconstruction.

## Stack technique

FoxSecura repose sur une stack Rust moderne et asynchrone :

- **Rust 1.98.1** : langage principal du projet ;
- **Tokio 1.53.1** : runtime asynchrone ;
- **Serenity 0.12.5** : client Discord, Gateway, événements et API Discord ;
- **Poise 0.7.0** : framework de commandes construit au-dessus de Serenity ;
- **SQLite / rusqlite 0.40.2** : persistance locale des configurations et des salons de logs.

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
- les intents privilégiés **Server Members Intent** et **Message Content Intent** activés dans le Discord Developer Portal.

Le projet utilise les intents Discord suivants :

- `GUILDS` ;
- `GUILD_MODERATION` ;
- `GUILD_MEMBERS` ;
- `GUILD_MESSAGES` ;
- `MESSAGE_CONTENT`.

## Configuration

Le token Discord doit être fourni avec la variable d'environnement `DISCORD_TOKEN`.

La base SQLite utilise `data/foxsecura.sqlite3` par défaut. Son emplacement peut être remplacé avec la variable d'environnement `DATABASE_PATH`.

Sous Linux ou macOS :

```bash
export DISCORD_TOKEN="votre_token"
export DATABASE_PATH="data/foxsecura.sqlite3"
```

Sous PowerShell :

```powershell
$env:DISCORD_TOKEN="votre_token"
$env:DATABASE_PATH="data/foxsecura.sqlite3"
```

> Ne stockez jamais le token du bot directement dans le code source ou dans un fichier suivi par Git.

## Développement

Clonez le dépôt puis vérifiez le formatage, le lint, la compilation et les tests :

```bash
git clone https://github.com/FoxSecura/FoxSecura.git
cd FoxSecura
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --all-targets
cargo test --all-targets
```

Pour démarrer FoxSecura :

```bash
cargo run
```

## État du projet

La base actuelle fournit :

- le runtime asynchrone Tokio ;
- le client Discord Serenity et la connexion au Gateway ;
- Poise pour les commandes `/config`, `/help` et `/status` ;
- les familles de protection Anti-Spam, Anti-Raid, Anti-Nuke, AutoMod et AI Moderation ;
- l'internationalisation anglais, français et allemand ;
- les incidents et salons de logs structurés ;
- la persistance SQLite des configurations de guilde et des salons de logs.

L'intégration runtime complète des protections, leur configuration persistante détaillée et l'application finale de toutes les actions de modération restent en cours de reconstruction.

## Licence

FoxSecura est distribué sous la **GNU Affero General Public License v3.0 uniquement** (`AGPL-3.0-only`).

Consultez le fichier [`LICENSE`](LICENSE) pour le texte complet de la licence.

Copyright © 2026 FoxSecura contributors.
