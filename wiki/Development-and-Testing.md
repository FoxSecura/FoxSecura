# Développement et tests

FoxSecura est un projet de sécurité : une modification petite et vérifiable est préférable à une abstraction large difficile à relire.

Pour le parcours complet d'un nouveau contributeur, consultez également [Contribuer](Contributing) et [`CONTRIBUTING.md`](https://github.com/FoxSecura/FoxSecura/blob/main/CONTRIBUTING.md).

## Environnement

Le projet cible Rust 1.98.1, édition 2024. `rust-toolchain.toml` fournit également `rustfmt` et `clippy`.

Avant toute PR, exécutez au minimum :

```bash
cargo clippy --all-targets -- -D warnings
cargo check --all-targets
cargo test --all-targets
```

La GitHub Action `Cargo Check` exécute ces trois validations avec la toolchain 1.98.1.

Les fichiers Rust modifiés doivent respecter `rustfmt`. Le dépôt contient toutefois une dette de formatage historique : une PR fonctionnelle ne doit pas embarquer un reformatage global sans rapport avec son objectif. Le nettoyage global doit rester une contribution dédiée afin de conserver des diffs relisibles.

## Organisation des tests

Les tests de haut niveau se trouvent dans `tests/` :

- `database.rs` ;
- `i18n.rs` ;
- `logs.rs` ;
- `protection.rs` et `tests/protection/**`.

La structure de `tests/protection` suit celle de `src/protection`, notamment pour la modération IA, anti-nuke, anti-raid, anti-spam, AutoMod et les primitives partagées.

## Ce qu'un détecteur doit tester

Pour chaque nouvelle règle, couvrir au minimum : un cas réellement détecté, un cas clairement légitime, la limite exacte du seuil, les entrées vides/minimales et les cas d'exemption pertinents.

Les protections temporelles doivent contrôler les fenêtres et les bornes ; les protections textuelles doivent inclure des variantes Unicode ou de casse si cela fait partie de leur modèle de menace.

Un correctif doit, lorsque possible, ajouter un test de non-régression qui reproduit le problème corrigé.

## Dépendances

Les versions sont épinglées. Une mise à jour de dépendance doit rester séparée d'un changement fonctionnel important lorsqu'il est possible de le faire, afin de simplifier la revue et le rollback.

Une nouvelle dépendance doit avoir une utilité nette. Pour une fonction triviale ou sensible, du code Rust local et testable peut être préférable à l'ajout d'une crate transitive importante.

## Workflow Git recommandé

1. partir de `main` à jour ;
2. créer une branche ciblée ;
3. implémenter un diff minimal ;
4. ajouter ou adapter les tests ;
5. exécuter `clippy`, `check` et `test` ;
6. vérifier le formatage des fichiers Rust réellement modifiés ;
7. relire les effets de bord, permissions et cas d'échec ;
8. mettre à jour la documentation si nécessaire ;
9. ouvrir une pull request descriptive en utilisant le template du dépôt.

## Documentation

Le dossier `wiki/` est la source de vérité du GitHub Wiki. Toute modification documentaire durable doit être faite dans ce dossier.

La CI `Wiki` :

- valide `wiki/Home.md`, `_Sidebar.md`, l'absence de fichiers non Markdown et les pages vides sur PR ;
- publie automatiquement `wiki/` sur le wiki natif après un push sur `main` ;
- supprime du wiki publié les pages qui n'existent plus dans `wiki/`, afin d'éviter la dérive entre les deux sources.

Évitez donc les modifications manuelles directement dans l'interface Wiki : elles pourront être remplacées lors de la prochaine synchronisation.

## Ajouter une page de wiki

Créez `wiki/Nom-de-Page.md`, ajoutez son lien dans `_Sidebar.md`, puis référencez-la depuis la page la plus pertinente. Les noms de fichiers doivent rester simples, sans caractères interdits par les wikis GitHub.

## SPDX

Le code Rust existant utilise des en-têtes SPDX `AGPL-3.0-only`. Les nouveaux fichiers source doivent conserver la convention du projet lorsque celle-ci s'applique.
