# Contribuer à FoxSecura

Cette page sert de point d'entrée pour les contributeurs. Les règles normatives se trouvent dans [`CONTRIBUTING.md`](https://github.com/FoxSecura/FoxSecura/blob/main/CONTRIBUTING.md), la politique de sécurité dans [`SECURITY.md`](https://github.com/FoxSecura/FoxSecura/blob/main/SECURITY.md) et le comportement communautaire dans [`CODE_OF_CONDUCT.md`](https://github.com/FoxSecura/FoxSecura/blob/main/CODE_OF_CONDUCT.md).

## Parcours recommandé

1. lire l'[architecture](Architecture) et les [modules de protection](Protection-Modules) ;
2. lire [Développement et tests](Development-and-Testing) ;
3. choisir une issue existante ou ouvrir le formulaire approprié ;
4. partir d'un `main` à jour et créer une branche ciblée ;
5. implémenter le changement avec un diff minimal ;
6. ajouter ou adapter les tests ;
7. exécuter les validations locales ;
8. documenter les impacts de sécurité ;
9. ouvrir une pull request avec le template du dépôt.

## Validation locale

Avant de pousser une contribution Rust, exécutez au minimum :

```bash
cargo check --all-targets
cargo test --all-targets
```

`cargo clippy --all-targets` est recommandé pour détecter des améliorations supplémentaires. Le dépôt fixe Rust à la version 1.98.1 et fournit `rustfmt` et `clippy` via `rust-toolchain.toml`.

Les fichiers Rust modifiés doivent respecter `rustfmt`. Le dépôt contient encore une dette de formatage et de lint historique : si une vérification globale signale des fichiers sans rapport avec votre contribution, ne mélangez pas leur nettoyage à une PR fonctionnelle.

## Quel type d'issue ouvrir ?

### Bug

Utilisez le formulaire **Bug** pour une régression ou un comportement incorrect reproductible. Fournissez un scénario minimal, le comportement attendu, la version ou le commit et les logs utiles après suppression de toute donnée sensible.

### Amélioration

Utilisez **Amélioration** pour proposer une fonctionnalité ou un changement de comportement. Expliquez d'abord le problème à résoudre puis les impacts sécurité possibles.

### Documentation

Utilisez **Documentation** lorsqu'une page, un comportement documenté ou un exemple est incorrect, ambigu ou manquant.

### Vulnérabilité

N'utilisez pas une issue publique. Suivez la [politique de sécurité](https://github.com/FoxSecura/FoxSecura/security/policy).

## Ce qu'une bonne PR FoxSecura doit montrer

Une bonne PR est suffisamment petite pour être relue sérieusement. Elle indique clairement le problème, la solution, les risques, les tests et ce qui reste hors périmètre.

Pour les protections Discord, la revue s'intéresse particulièrement :

- aux faux positifs ;
- aux permissions requises ;
- aux exemptions ;
- aux fenêtres temporelles et seuils ;
- au comportement si Discord ou une dépendance échoue ;
- à l'idempotence des actions correctives ;
- à la qualité des preuves d'incident et des logs.

Pour la modération IA, un résultat fournisseur n'est jamais considéré comme intrinsèquement fiable : la validation, les timeouts, les erreurs de schéma et la politique locale doivent rester explicitement gérés.

## Documentation

Le dossier `wiki/` du dépôt est la source de vérité du Wiki GitHub. Toute page ajoutée ici doit être liée dans `_Sidebar.md` lorsqu'elle fait partie de la navigation principale.

Les modifications directes dans l'interface du Wiki ne sont pas durables : l'automatisation les remplace avec le contenu versionné du dépôt.

## Licence des contributions

Les contributions acceptées sont distribuées sous `AGPL-3.0-only`, comme le reste du projet.
