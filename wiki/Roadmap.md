# Roadmap

Cette roadmap décrit les axes techniques visibles dans l'état actuel du dépôt. Elle ne constitue pas une promesse de date de livraison.

## 1. Consolider le runtime Discord

Le principal chantier est de relier progressivement les moteurs déjà testables aux événements Serenity : messages, membres, audit logs, créations/suppressions de ressources, webhooks et changements de serveur.

Chaque branchement doit conserver la séparation `snapshot → détection → décision → action → log` et éviter de déplacer la logique métier dans le handler global.

**Fait (tranche 1)** : `AppData` porte la base SQLite et l'état des protections, l'intent `GUILD_MESSAGES` est demandé et l'événement `Message` alimente un pipeline de protection isolé des erreurs. L'anti-spam (rafales de messages) y est branché de bout en bout. Les tranches suivantes réutiliseront ce pipeline pour les autres modules.

**Fait (tranche 3)** : six filtres de contenu (caractères invisibles, liens malveillants, liens adultes, invitations, `@everyone`/`@here`, mentions de masse) branchés sur les créations **et modifications** de messages, dans l'ordre de la V1 avec court-circuit, avant l'anti-spam, appliqués aussi aux auteurs exemptés (suppression sans sanction). Intent `MESSAGE_CONTENT` demandé, avec un message explicite en cas de refus 4014. Activation par module persistée dans une table générique (migration 4) et gérée depuis `/config`. **Reste** : seuil de mentions de masse réglable.

**Fait (tranche 4)** : socle partagé des sanctions (timeout, ban) avec cœur pur testé (propriétaire et bot jamais sanctionnés, liste blanche → `ignore_exempt_member`, permission et hiérarchie vérifiées d'après le cache, échecs classés) ; `attachment_filter`, `anti_scam` gradué (revue, timeout 1 h, ban avec purge de 7 jours) et `bad_words` (liste intégrée par langue et mots personnalisés, migration 5) ; ordre complet de la V1 ; cache de configuration par guilde invalidé à chaque écriture ; correction des modifications partielles. **Reste** : anti-nuke capable d'ignorer les sanctions de FoxSecura (raison préfixée `FoxSecura` + exécuteur), sanction d'un membre déjà parti (ban par identifiant), réglage des seuils de l'anti-arnaque.

**Fait (tranche 5)** : pipeline des membres (`GUILD_MEMBER_ADD`, `GUILD_MEMBER_UPDATE`) dans l'ordre de la V1, avec arrêt sur résultat terminal ; liste noire (migration 6, exclusive avec la liste blanche, ban à l'arrivée, terminal même en cas d'échec) ; anti-bot (expulsion, socle étendu à `Kick`) ; nouveaux comptes (âge minimal persisté, ban avec purge de 7 jours) ; pseudos hoistés (règle Unicode V1, renommage sans boucle). **Reste** : anti-raid (rafales d'arrivées), verrouillage, honeypot et doubles comptes (tranche 7).

**Fait (tranche 6)** : quarantaine (migration 7) : rôle créé ou choisi depuis `/config` (permissions dangereuses refusées), verrou du rôle sur les catégories et salons désynchronisés (réappliqué sur `CHANNEL_CREATE`), verrou au niveau du membre avec état d'origine à trois états enregistré avant chaque modification, opérations sérialisées par membre, repli timeout, libération avec restauration exacte, libérations en attente reprises toutes les 5 minutes, restauration quand le rôle est retiré à la main ; usurpation d'identité branchée (quarantaine, terminale) ; quarantaine de repli des nouveaux comptes. **Reste** : vérification des membres (déclencheur de libération de la V1), réapplication du verrou du membre sur un salon créé pendant une quarantaine, limitation du volume d'appels API pendant un raid, état partagé si plusieurs instances.

**Fait (tranche 2)** : liste blanche (utilisateurs, rôles) et salons ignorés, persistés (migration 3), appliqués par le pipeline de messages dans l'ordre de la V1 et gérés depuis `/config` → Contrôle d'accès. **Fait (tranche 4)** : cache par guilde. **Fait (tranche 6)** : le rôle de quarantaine n'exempte jamais. **Reste** : prise en compte des fils de salons ignorés, et rôles de vérification et rôle limité à exclure de l'exemption quand ces modules seront portés.

## 2. Rendre `/config` réellement persistant

Le tableau de bord expose déjà les grandes catégories produit. Les prochaines étapes sont de définir les modèles de configuration par guild, leurs migrations, la validation des permissions et le chargement efficace des paramètres.

L'interface ne doit afficher un état « actif » que si la valeur est réellement persistée et utilisée par le moteur concerné.

**Fait** : autorisation propriétaire / `ADMINISTRATOR` / `MANAGE_GUILD`, catégorie Anti-Spam persistée (activation, seuil, fenêtre, six filtres de contenu dont l'anti-arnaque), catégorie AutoMod (liens adultes, invitations, mots interdits avec liste intégrée et mots personnalisés), catégorie Contrôle d'accès (listes blanche et noire réservées au propriétaire et à `ADMINISTRATOR`, salons ignorés) et catégorie Anti-Raid (anti-bot, nouveaux comptes avec âge minimal, usurpation d'identité, pseudos hoistés, rôle de quarantaine et libération d'un membre réservés au propriétaire et à `ADMINISTRATOR`). **Reste** : les autres catégories et la configuration des salons de logs depuis `/config`.

## 3. Finaliser la chaîne d'incidents

Le modèle `SecurityIncident` et les résultats d'action offrent une base pour unifier les logs. Il reste à brancher les détecteurs et exécuteurs de manière cohérente, puis à distribuer les incidents vers les salons configurés.

## 4. Anti-Nuke opérationnel

Priorités : corrélation avec les audit logs, identification fiable de l'exécuteur, seuils par guild, exemptions contrôlées, réactions réversibles et tests de concurrence.

## 5. Anti-Raid et Anti-Spam

Priorités : états temporels efficaces, nettoyage des fenêtres, configuration par serveur, cohérence des exemptions et contrôle des faux positifs.

L'anti-spam par rafales est branché au runtime. La liste blanche et les salons ignorés sont appliqués. Les neuf filtres de contenu sont branchés, dont l'anti-arnaque avec sanctions. Côté arrivées : liste noire, anti-bot, nouveaux comptes (avec quarantaine de repli), usurpation d'identité et pseudos hoistés sont branchés, ainsi que la quarantaine ; restent l'anti-raid par rafales, le verrouillage, le honeypot et les doubles comptes. Restent notamment : limitation du volume d'incidents pendant une rafale et, si le bot doit tourner sur plusieurs instances, un état partagé (anti-spam et invalidation du cache de configuration).

## 6. AutoMod natif

Le modèle `spec + reconciler` doit devenir la voie principale pour synchroniser les règles Discord attendues. Les opérations doivent rester idempotentes et tolérer les modifications externes de manière explicite.

## 7. Modération IA

Avant activation générale : gestion sûre des secrets, branchement au runtime, limites de contexte, observabilité, circuit breaker, politique de fallback, coût maîtrisé et tests d'intégration avec fournisseurs simulés.

## 8. Persistance

Étendre les migrations au rythme des paramètres réellement consommés. Éviter de créer prématurément un grand schéma pour des fonctionnalités non branchées.

## 9. CI et qualité

Conserver `cargo check` et les tests sur chaque PR. Ajouter progressivement format/lint lorsque la convention est stabilisée, ainsi que des vérifications ciblées pour la documentation et la sécurité des dépendances si elles apportent un signal fiable.

Le wiki est désormais versionné et publié automatiquement, ce qui doit réduire la dérive entre code et documentation.

## 10. Critère de maturité

Une fonctionnalité FoxSecura peut être considérée mature lorsqu'elle dispose d'une configuration explicite, de tests positifs/négatifs/limites, d'une intégration runtime, d'une gestion des permissions et échecs, d'incidents structurés, d'une documentation utilisateur et d'un comportement de rollback ou fallback défini lorsque nécessaire.
