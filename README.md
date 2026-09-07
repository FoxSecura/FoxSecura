# FoxSecura v2

[![Rust](https://img.shields.io/badge/Rust-1.98.1-DEA584?style=plastic&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tokio](https://img.shields.io/badge/Tokio-1.53.1-000000?style=plastic&logo=tokio&logoColor=white)](https://tokio.rs/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL--3.0--only-663399?style=plastic&logo=gnu&logoColor=white)](https://www.gnu.org/licenses/agpl-3.0.html)

FoxSecura v2 est la réécriture en **Rust** de FoxSecura, un bot Discord orienté sécurité et protection des serveurs.

> Le projet est actuellement en phase de reconstruction.

## Stack technique

- Rust **1.98.1** ;
- Tokio **1.53.1** ;
- Serenity **0.12.5**.

## Objectifs

- disposer d'une base Rust moderne, robuste et maintenable ;
- construire une architecture modulaire pour les fonctionnalités de sécurité ;
- privilégier la fiabilité, les performances et la sûreté ;
- permettre une évolution progressive du bot sans dépendre de l'ancienne base propriétaire.

## Prérequis

- Rust **1.98.1** ;
- Cargo ;
- un token de bot Discord exposé via la variable d'environnement `DISCORD_TOKEN` ;
- l'intent privilégié **Server Members Intent** activé dans le portail développeur Discord.

## Développement

```bash
git clone https://github.com/FoxSecura/FoxSecura-v2.git
cd FoxSecura-v2

export DISCORD_TOKEN="votre_token"
cargo check
cargo run
```

Sous PowerShell :

```powershell
$env:DISCORD_TOKEN="votre_token"
cargo check
cargo run
```

## État du projet

FoxSecura v2 dispose maintenant d'une base Tokio + Serenity minimale. Les modules Discord, la configuration et les fonctionnalités de sécurité seront ajoutés progressivement.

## Licence

FoxSecura v2 est distribué sous la **GNU Affero General Public License v3.0 uniquement** (`AGPL-3.0-only`).

Consultez le fichier [`LICENSE`](LICENSE) pour le texte complet de la licence.

Copyright © 2026 FoxSecura contributors.
