# FoxSecura

[![Rust](https://img.shields.io/badge/Rust-1.98.1-DEA584?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Cargo Check](https://github.com/FoxSecura/FoxSecura/actions/workflows/cargo-check.yml/badge.svg)](https://github.com/FoxSecura/FoxSecura/actions/workflows/cargo-check.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL--3.0--only-663399?style=flat&logo=gnu&logoColor=white)](LICENSE)

**FoxSecura** est un bot Discord de sécurité écrit en Rust. Il vise à protéger les serveurs contre les raids, le spam, les abus de permissions, les destructions de ressources et différents contenus à risque.

> FoxSecura V2 est en développement actif. Plusieurs moteurs de protection sont déjà présents dans le code et testés isolément, tandis que leur intégration complète au runtime Discord progresse par étapes.

## Fonctionnalités

- anti-raid et détection de comportements suspects à l'arrivée ;
- anti-spam, anti-mentions, liens suspects et filtres de contenu ;
- anti-nuke et garde des actions sensibles du serveur ;
- AutoMod Discord et règles de modération locales ;
- modération assistée par IA avec politique, préfiltrage et fournisseurs séparés ;
- journalisation structurée des incidents de sécurité ;
- persistance SQLite et migrations versionnées ;
- interface multilingue français, anglais et allemand.

## Démarrage rapide

Prérequis : **Rust 1.98.1**, Cargo, un bot Discord et le **Server Members Intent** activé.

```bash
git clone https://github.com/FoxSecura/FoxSecura.git
cd FoxSecura
export DISCORD_TOKEN="votre_token"
cargo run
```

Sous PowerShell :

```powershell
$env:DISCORD_TOKEN="votre_token"
cargo run
```

Ne stockez jamais un token Discord ou une clé d'API dans le dépôt.

## Documentation

La documentation détaillée est maintenue dans [`wiki/`](wiki/Home.md) puis publiée automatiquement vers le [GitHub Wiki](https://github.com/FoxSecura/FoxSecura/wiki).

Pour contribuer :

```bash
cargo check --all-targets
cargo test --all-targets
```

Consultez également le [`changelog.md`](changelog.md).

## Licence

FoxSecura est distribué sous **GNU Affero General Public License v3.0 uniquement** (`AGPL-3.0-only`). Voir [`LICENSE`](LICENSE).

Copyright © 2026 FoxSecura contributors.
