# Installation et démarrage

Cette page décrit l'environnement minimal pour développer ou lancer FoxSecura V2.

## Prérequis

Vous devez disposer de Git, de Cargo et de **Rust 1.98.1**. Le dépôt contient également `rust-toolchain.toml` et `Cargo.toml` fixe `rust-version = "1.98.1"`.

Côté Discord, créez une application et un bot depuis le Discord Developer Portal. Le runtime actuel demande les intents `GUILDS`, `GUILD_MODERATION` et `GUILD_MEMBERS`; le **Server Members Intent** doit donc être activé pour le bot.

## Cloner et vérifier le projet

```bash
git clone https://github.com/FoxSecura/FoxSecura.git
cd FoxSecura
cargo check --all-targets
cargo test --all-targets
```

La CI officielle utilise les mêmes familles de vérification avec Rust 1.98.1.

## Token Discord

Le runtime lit exclusivement `DISCORD_TOKEN` depuis l'environnement.

Linux/macOS :

```bash
export DISCORD_TOKEN="votre_token"
cargo run
```

PowerShell :

```powershell
$env:DISCORD_TOKEN="votre_token"
cargo run
```

Une variable absente fait échouer `App::from_env()` avant la connexion. Aucun fallback vers un secret en dur n'est prévu, ce qui est volontaire.

## Démarrage du runtime

`App::run()` construit le framework Poise, enregistre les commandes globales puis démarre le client Serenity. Les commandes exposées actuellement sont `config`, `help` et `status`.

L'enregistrement global Discord peut demander un délai de propagation côté plateforme après une modification de commande.

## Persistance SQLite

Le module de base de données fournit un chemin par défaut :

```text
data/foxsecura.sqlite3
```

Lorsqu'une `Database` est ouverte, le parent du fichier est créé si nécessaire, SQLite active les clés étrangères, utilise `synchronous = NORMAL`, tente le mode WAL et applique les migrations versionnées.

Le `AppData` du runtime actuel reste minimal. Il ne faut donc pas supposer que chaque service de bibliothèque est déjà instancié automatiquement au démarrage du bot.

## Modération IA

Le dépôt contient une architecture de modération IA avec fournisseur OpenAI, taxonomie, politique locale, préfiltrage, timeout et règles de décision. Cette couche doit être considérée comme un moteur séparé dont l'activation et le branchement opérationnel doivent être explicitement configurés.

Ne placez jamais une clé fournisseur dans le code, un fichier Markdown, un log ou un commit. Utilisez uniquement un mécanisme de secret adapté au futur environnement de déploiement.

## Première vérification

Après lancement, vérifiez au minimum :

1. que le bot se connecte avec le bon compte ;
2. que les commandes globales apparaissent ;
3. que `/status`, `/help` et `/config` répondent ;
4. que les permissions Discord du bot correspondent aux actions réellement activées ;
5. qu'aucun secret n'apparaît dans la sortie ou l'historique Git.

Pour comprendre le flux interne, continuez avec [Architecture](https://github.com/FoxSecura/FoxSecura/wiki/Architecture).
