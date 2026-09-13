# Runtime et activation des protections

Depuis la version 0.1.1, les 43 clés de protection du dépôt sont raccordées au Gateway Discord. Les détecteurs restent testables sans réseau ; le runtime traduit leurs décisions en actions et journalise leur résultat.

## Configurer un serveur

1. Copier [`protection.example.json`](https://github.com/FoxSecura/FoxSecura/blob/main/protection.example.json) hors du dépôt si les identifiants sont privés.
2. Remplacer la clé du serveur et les identifiants de salons/rôles par ceux de votre serveur. Retirer de `enabled` les modules non souhaités et adapter les noms protégés. Le salon honeypot doit être réservé à cet usage.
3. Définir `FOXSECURA_PROTECTION_CONFIG` vers ce fichier avant de démarrer le bot.
4. Vérifier les observations dans les logs et le mode affiché par `/status`. Passer `enforce` à `true` puis redémarrer pour demander les actions automatiques.

```bash
export DISCORD_TOKEN="votre_token"
export FOXSECURA_PROTECTION_CONFIG="/chemin/protection.json"
export FOXSECURA_DATABASE_PATH="data/foxsecura.sqlite3"
cargo run
```

Le fichier contient un objet par identifiant de serveur. Un fichier absent de l'environnement laisse les protections désactivées. Une configuration invalide empêche le démarrage : les clés inconnues et les identifiants nuls sont refusés. Les changements prennent effet au redémarrage ; `/config` ne modifie pas ce fichier.

`enforce: false`, valeur par défaut, produit les observations et ignore les sanctions. Les règles natives précédemment gérées sont désactivées lors de la synchronisation, y compris lorsque le serveur est retiré de la configuration, à condition de conserver la base SQLite et les permissions Discord. Les conflits de règles ou erreurs API sont journalisés ; un échec de synchronisation exige une vérification dans Discord.

## Modules raccordés

| Événements | Clés dans `enabled` | Réponse prévue en mode actif |
| --- | --- | --- |
| Messages et modifications | `anti_everyone`, `anti_mass_mention`, `anti_scam`, `attachment_filter`, `invisible_char_filter`, `malicious_link`, `adult_link`, `anti_invite`, `bad_words` | Alerte et suppression du message détecté |
| Nouveaux messages | `message_flood`, `anti_ping_owner`, `anti_spam_ping` | Alerte et suppression selon les seuils des moteurs |
| Messages/modifications/suppressions | `anti_ghost_ping` | Suivi des mentions ; suppression non attribuée : alerte seule ; récidive par modification : timeout |
| Activité de salon | `auto_slowmode` | Ralentissement temporaire à 10 secondes, restauration après 120 secondes |
| Arrivées et profils | `anti_bot`, `anti_new_account`, `anti_double_account`, `anti_impersonation`, `anti_nickname_hoisting`, `join_burst` | Expulsion des bots non exemptés ; alertes sur âge/identité ; nettoyage du pseudo ; alerte et timeout lors d'une rafale d'arrivées |
| Messages dans le salon désigné | `honeypot` | Alerte et suppression |
| Messages webhook et journal d'audit | `webhook_message`, `webhook_watch` | Suppression des messages détectés et retrait du webhook selon le signal |
| Journal d'audit : membres | `anti_mass_ban`, `anti_mass_kick`, `anti_mass_timeout`, `anti_mass_unban`, `anti_mass_role_grant` | Alerte et retrait des rôles dangereux de l'exécuteur identifié |
| Journal d'audit : ressources | `anti_channel_delete`, `anti_role_delete`, `anti_mass_channel_create`, `anti_mass_role_create`, `anti_emoji_sticker_nuke` | Alerte et confinement de l'exécuteur |
| Journal d'audit : intégrité | `anti_permissions`, `anti_external_application`, `anti_server_edit`, `anti_vanity_change` | Confinement ; restauration conditionnelle des permissions de rôle |
| Membres : attribution de rôle | `limit_role` | Retrait d'un rôle nouvellement attribué lorsque son quota est dépassé |
| Signaux anti-nuke corrélés | `panic_mode` | Ralentissement à 30 secondes pendant 15 minutes dans les salons texte/annonces non ignorés |
| Démarrage et audit AutoMod | `native_rules`, `member_profile`, `automod_rule_guard` | Réconciliation des règles natives et réparation des règles gérées |
| Messages éligibles | `ai_moderation` | Préfiltrage, classification OpenAI, alerte et suppression selon la politique existante |

Les seuils temporels sont ceux des moteurs du dépôt, conservés en mémoire et isolés par serveur. Une reconnexion ou un redémarrage ne permet pas de reconstituer les événements non reçus.

`native_rules` active la gestion des règles natives liées aux modules `anti_invite`, `adult_link`, `bad_words`, `anti_mass_mention`, `message_flood` et `member_profile`. Les règles appartenant à un autre créateur sont préservées ; les conflits de règles uniques sont signalés. Les identifiants et noms canoniques des règles gérées sont persistés pour retrouver une règle renommée.

## Options et exemptions

- `exempt_users`, `exempt_roles` : exemptions explicites. Le propriétaire et FoxSecura sont protégés des sanctions. Les administrateurs et gestionnaires du serveur sont exemptés des filtres locaux de messages/profil ; cette exemption implicite ne contourne pas l'anti-nuke, `anti_bot` ou `limit_role`.
- `ignored_channels` : salons ignorés par les filtres locaux de messages, le ralentissement de panique et les règles natives compatibles.
- `honeypot_channel` : obligatoire avec `honeypot`.
- `limited_roles` : objet identifiant de rôle → nombre maximum de membres, obligatoire avec `limit_role`.
- `protected_names` : noms de référence, obligatoires avec `anti_impersonation`.
- `blocked_words` : liste personnalisée ; à défaut, liste française du dépôt. Maximum 1 000 entrées de 60 caractères.
- `minimum_account_age_days` : de 0 à 365, défaut 7. Un compte récent ne déclenche qu'une alerte.
- `log_channel` : destination des incidents, sinon salon de modération configuré en SQLite. Les logs locaux restent disponibles.

`member_profile` exige `native_rules`. Discord accepte au maximum 20 rôles exemptés et 50 salons ignorés pour cette configuration. Les exemptions natives suivent les règles de Discord ; les utilisateurs individuels exemptés localement ne deviennent pas automatiquement exemptés des règles natives.

## Permissions et intents

Activer **Server Members Intent** et **Message Content Intent** dans le portail développeur Discord. Le runtime demande les intents guilds, membres, modération, messages, contenu, webhooks et AutoMod.

Selon les modules, autoriser l'accès au journal d'audit, la lecture des salons et de l'historique, la gestion des messages, membres modérés, expulsions, pseudos, rôles, salons, webhooks et AutoMod (`Manage Server`). Le bot doit pouvoir envoyer les logs. Son rôle doit être au-dessus des membres et rôles à modifier. Les permissions manquantes, la hiérarchie ou un état corrigé peuvent empêcher une action ; `/status` indique la configuration demandée, pas une garantie de succès.

## Persistance et limites

Les ralentissements sont enregistrés avant l'appel Discord. La maintenance tente de restaurer leur valeur initiale toutes les 30 secondes après expiration ; elle conserve les modifications manuelles différentes des valeurs suivies et reprend après redémarrage. Garder la même base SQLite est nécessaire à cette reprise et au suivi des règles natives renommées.

Le contenu, les pièces jointes et les mentions sont relus avant suppression pour éviter d'effacer une version corrigée. Le pseudo analysé est également comparé avant sa normalisation. Une suppression de message sans auteur d'action fiable ne sanctionne pas l'auteur du message. Les événements d'audit vieux de plus de cinq minutes sont ignorés ; un exécuteur non résolu ne déclenche pas de confinement.

`limit_role` exige un état précédent et un cache complet des membres. Le bot demande les membres au démarrage ; tant que ces données sont incomplètes, le contrôle de quota est ignoré. La détection de double compte compare seulement les identités disponibles dans ce cache. Les signaux d'âge, d'imitation ou de doublon restent des alertes à examiner.

Le confinement retire les rôles dangereux que le bot peut gérer. Il ne reconstruit pas les salons, rôles, emojis ou stickers détruits, et ne restaure pas les paramètres généraux ou la vanity URL. Le mode panique applique un ralentissement, sans verrouillage intégral du serveur.

L'IA exige à la fois `ai_moderation` et `OPENAI_API_KEY`. Elle transmet le message éligible au fournisseur existant, sans historique de conversation. Admission, cache, coupe-circuit et délai maximal de cinq secondes limitent les appels. Une panne ou une réponse invalide ne provoque pas de sanction IA.

Les tests automatisés couvrent les décisions, les seuils, les exemptions, les doublons d'événements, les modifications, SQLite et un fournisseur IA simulé. La compilation vérifie les adaptateurs Serenity ; aucun test ne sanctionne de membre sur un serveur Discord réel.
