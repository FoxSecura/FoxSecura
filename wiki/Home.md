# FoxSecura Wiki

FoxSecura V2 est une réécriture en **Rust** d'un bot Discord centré sur la sécurité des communautés. Le projet cherche à fournir des protections prévisibles, testables et modulaires contre les raids, le spam, les abus de permissions, les destructions de ressources et certains contenus dangereux ou abusifs.

## État du projet

FoxSecura est en développement actif. Le dépôt contient déjà une base importante de modules de protection, de tests, de persistance, d'internationalisation et de journalisation. La couche Discord exécutable reste volontairement plus petite : le runtime Poise/Serenity enregistre aujourd'hui les commandes et relaie les interactions de composants, tandis que le branchement complet de tous les moteurs de sécurité aux événements Discord continue progressivement.

Cette distinction est importante : **présent dans le code** ne signifie pas nécessairement **activé en production par le runtime actuel**.

## Principes de conception

FoxSecura suit quelques règles simples : les décisions de sécurité doivent être explicites, les seuils doivent être testables, les composants doivent rester découplés de Discord autant que possible, les données persistées doivent être versionnées, et les actions sensibles doivent fournir des résultats structurés plutôt que dépendre uniquement de logs textuels.

Le projet sépare ainsi :

- le runtime Discord (`src/app`) ;
- les commandes (`src/commands`) ;
- les services réutilisables (`database`, `i18n`, `logs`) ;
- les moteurs de protection (`src/protection`) ;
- les tests d'intégration et de comportement (`tests`).

## Stack principale

FoxSecura utilise Rust 1.98.1 et l'édition 2024. Tokio fournit le runtime asynchrone, Serenity l'accès à Discord, Poise le framework de commandes, rusqlite la persistance SQLite, reqwest le transport HTTP et serde_json le traitement JSON nécessaire aux intégrations externes.

Les versions majeures sont actuellement épinglées dans `Cargo.toml` afin de conserver une base reproductible.

## Navigation

- [Installation et démarrage](https://github.com/FoxSecura/FoxSecura/wiki/Getting-Started)
- [Architecture](https://github.com/FoxSecura/FoxSecura/wiki/Architecture)
- [Configuration et commandes](https://github.com/FoxSecura/FoxSecura/wiki/Configuration-and-Commands)
- [Modules de protection](https://github.com/FoxSecura/FoxSecura/wiki/Protection-Modules)
- [Modération IA](https://github.com/FoxSecura/FoxSecura/wiki/AI-Moderation)
- [Données, langues et logs](https://github.com/FoxSecura/FoxSecura/wiki/Data-I18n-and-Logs)
- [Développement et tests](https://github.com/FoxSecura/FoxSecura/wiki/Development-and-Testing)
- [Automatisation du Wiki](https://github.com/FoxSecura/FoxSecura/wiki/Wiki-Automation)
- [Sécurité opérationnelle](https://github.com/FoxSecura/FoxSecura/wiki/Security)
- [Roadmap](https://github.com/FoxSecura/FoxSecura/wiki/Roadmap)

## Sources de la documentation

Les pages du wiki sont versionnées dans le dossier `wiki/` du dépôt principal. Une GitHub Action valide ces fichiers sur les pull requests et synchronise le dossier vers le wiki natif après un changement fusionné sur `main`.

Le wiki GitHub doit être considéré comme une **projection publiée**. Les modifications durables doivent être faites dans `wiki/`, relues par pull request puis fusionnées.
