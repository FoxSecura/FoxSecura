# Roadmap

Cette roadmap décrit les axes techniques visibles dans l'état actuel du dépôt. Elle ne constitue pas une promesse de date de livraison.

## 1. Consolider le runtime Discord

Le principal chantier est de relier progressivement les moteurs déjà testables aux événements Serenity : messages, membres, audit logs, créations/suppressions de ressources, webhooks et changements de serveur.

Chaque branchement doit conserver la séparation `snapshot → détection → décision → action → log` et éviter de déplacer la logique métier dans le handler global.

## 2. Rendre `/config` réellement persistant

Le tableau de bord expose déjà les grandes catégories produit. Les prochaines étapes sont de définir les modèles de configuration par guild, leurs migrations, la validation des permissions et le chargement efficace des paramètres.

L'interface ne doit afficher un état « actif » que si la valeur est réellement persistée et utilisée par le moteur concerné.

## 3. Finaliser la chaîne d'incidents

Le modèle `SecurityIncident` et les résultats d'action offrent une base pour unifier les logs. Il reste à brancher les détecteurs et exécuteurs de manière cohérente, puis à distribuer les incidents vers les salons configurés.

## 4. Anti-Nuke opérationnel

Priorités : corrélation avec les audit logs, identification fiable de l'exécuteur, seuils par guild, exemptions contrôlées, réactions réversibles et tests de concurrence.

## 5. Anti-Raid et Anti-Spam

Priorités : états temporels efficaces, nettoyage des fenêtres, configuration par serveur, cohérence des exemptions et contrôle des faux positifs.

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
