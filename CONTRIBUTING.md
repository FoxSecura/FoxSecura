# Contribuer à FoxSecura

Merci de vouloir contribuer à FoxSecura. Le projet est un bot Discord de sécurité écrit en Rust : les changements doivent privilégier la sûreté, la lisibilité et la vérifiabilité plutôt que la quantité de code.

## Avant de commencer

- Consultez le [Wiki](https://github.com/FoxSecura/FoxSecura/wiki) et en particulier la documentation de développement.
- Pour un bug, une amélioration ou une modification documentaire, utilisez le template d'issue adapté lorsqu'une discussion préalable est utile.
- Pour une vulnérabilité exploitable, **n'ouvrez pas d'issue publique** : suivez [`SECURITY.md`](SECURITY.md).
- Gardez une contribution ciblée. Une PR doit idéalement résoudre un problème cohérent et identifiable.

## Environnement de développement

Prérequis :

- Git ;
- Rust **1.98.1** ;
- Cargo.

Le dépôt contient `rust-toolchain.toml`, avec `rustfmt` et `clippy`.

```bash
git clone https://github.com/FoxSecura/FoxSecura.git
cd FoxSecura
cargo check --all-targets
cargo test --all-targets
```

Pour exécuter le bot localement, fournissez le token uniquement via l'environnement :

```bash
export DISCORD_TOKEN="votre_token"
cargo run
```

Sous PowerShell :

```powershell
$env:DISCORD_TOKEN="votre_token"
cargo run
```

Ne commitez jamais de token, clé API, cookie, `.env` réel ou données sensibles.

## Workflow Git

Créez une branche courte depuis un `main` à jour. Noms recommandés :

- `feat/nom-court` ;
- `fix/nom-court` ;
- `security/nom-court` ;
- `refactor/nom-court` ;
- `test/nom-court` ;
- `docs/nom-court` ;
- `ci/nom-court`.

Évitez de mélanger une grosse refactorisation, une mise à jour de dépendances et un changement fonctionnel dans la même PR.

## Principes de code

FoxSecura suit quelques règles simples :

1. **Sécurité d'abord.** Une protection ne doit pas créer un risque supérieur à celui qu'elle traite.
2. **Diff minimal.** Modifiez uniquement ce qui est nécessaire au problème traité.
3. **Types explicites.** Préférez des types de domaine et des états explicites aux chaînes ou booléens ambigus.
4. **Pas d'abstraction prématurée.** Une abstraction doit réduire une complexité réelle et démontrée.
5. **Dépendances limitées.** N'ajoutez une crate que si le bénéfice justifie le coût de maintenance, d'audit et de surface d'attaque.
6. **Comportement observable.** Les échecs, décisions de sécurité et actions partielles doivent pouvoir être diagnostiqués proprement.
7. **Pas de code mort.** N'introduisez pas de fonctionnalité fictive ou de chemin inutilisé pour anticiper un besoin hypothétique.

Le fait qu'un module de protection soit implémenté et testé ne signifie pas nécessairement qu'il est déjà connecté au runtime Discord. La documentation et les PR doivent distinguer clairement ces états.

## Style Rust

Avant une PR :

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo check --all-targets
cargo test --all-targets
```

Le code doit être formaté avec `rustfmt`. Les avertissements Clippy introduits par une contribution doivent être corrigés, sauf justification technique documentée.

Les nouveaux fichiers Rust doivent conserver la convention SPDX du projet lorsqu'elle s'applique :

```text
SPDX-License-Identifier: AGPL-3.0-only
```

## Tests

Toute modification de comportement doit être accompagnée de tests adaptés.

Pour une règle de sécurité ou un détecteur, couvrez au minimum :

- un cas réellement malveillant ou interdit ;
- un cas légitime qui ne doit pas être bloqué ;
- les bornes du seuil ;
- les entrées vides ou minimales ;
- les exemptions pertinentes ;
- les erreurs ou dépendances indisponibles lorsque cela modifie la décision.

Les protections de texte doivent considérer les variantes de casse et Unicode lorsqu'elles font partie du modèle de menace. Les protections temporelles doivent tester explicitement leurs fenêtres et limites.

Un correctif de bug doit, lorsque possible, ajouter un test qui échoue avant le correctif et réussit après celui-ci.

## Changements sensibles

### Anti-Nuke, Anti-Raid et actions Discord

Documentez les permissions nécessaires, les exemptions, les seuils, les conséquences d'un faux positif et le comportement en cas d'échec partiel. Les actions destructives doivent être idempotentes lorsque c'est raisonnablement possible.

### Base de données

Toute évolution du schéma doit passer par le mécanisme de migration du projet. Évitez les changements destructifs sans stratégie de compatibilité, sauvegarde ou migration explicite.

### Modération IA

Considérez le fournisseur IA comme une dépendance externe non déterministe. Validez les sorties, conservez le vocabulaire de domaine FoxSecura et testez les timeouts, erreurs de transport, réponses invalides et politiques locales.

### Dépendances

Expliquez dans la PR pourquoi une nouvelle dépendance est nécessaire. Une mise à jour de crate sensible doit mentionner les changements de comportement ou de sécurité pertinents.

## Commits

Des messages courts et explicites facilitent l'historique. Le format Conventional Commits est recommandé :

```text
feat: add join burst detector
fix: avoid duplicate moderation action
test: cover unicode mention bypass
docs: document anti-nuke permissions
ci: validate contributor workflow
```

Les catégories courantes sont `feat`, `fix`, `security`, `refactor`, `test`, `docs`, `ci`, `chore`.

## Pull requests

Une PR doit expliquer :

- le problème traité ;
- la solution retenue ;
- les risques de sécurité et effets de bord ;
- les tests exécutés ;
- les modifications de configuration, permissions, base de données ou documentation ;
- les éventuels éléments volontairement laissés hors périmètre.

Utilisez le template de pull request. Ne marquez pas une case de validation si la commande correspondante n'a pas réellement été exécutée.

Les mainteneurs peuvent demander de séparer une PR trop large ou de simplifier une solution avant fusion.

## Documentation

Le dossier `wiki/` est la source de vérité du Wiki GitHub. Pour toute modification durable de la documentation détaillée :

1. modifiez ou ajoutez la page dans `wiki/` ;
2. mettez à jour `wiki/_Sidebar.md` si nécessaire ;
3. vérifiez les liens ;
4. laissez la CI publier le Wiki après fusion sur `main`.

N'éditez pas directement le Wiki GitHub pour une modification permanente : la synchronisation automatique peut l'écraser.

## Langue

Le français est la langue privilégiée pour l'interface utilisateur et la documentation du projet. Le code Rust conserve naturellement les conventions techniques usuelles en anglais lorsque cela améliore la clarté et l'interopérabilité.

## Licence

En soumettant une contribution, vous acceptez qu'elle soit distribuée sous la licence du projet, **GNU Affero General Public License v3.0 uniquement** (`AGPL-3.0-only`).

## Comportement communautaire

Toute participation au projet est soumise au [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
