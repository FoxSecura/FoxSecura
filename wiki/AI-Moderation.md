# Modération IA

La modération IA de FoxSecura est conçue comme une couche **assistée**, isolée du reste du bot. Elle ne doit pas devenir un appel réseau directement enfoui dans un event handler Discord.

## Organisation du module

`src/protection/ai_moderation` contient des sous-systèmes dédiés à l'action, l'analyse, la disponibilité, le contexte, les diagnostics, les entrées modèle, les notices, la politique, le préfiltrage, les fournisseurs, les règles, le runtime, le mapping de sécurité, le schéma, les paramètres, la télémétrie et les types partagés.

Cette granularité permet de changer un fournisseur ou une politique sans réécrire toute la chaîne.

## Catégories

Le vocabulaire stable actuel contient treize catégories : toxicité, insultes, cyberharcèlement, harcèlement ciblé, menaces, intimidation, discours haineux, contenu sexuel, contenu sexuel explicite, sollicitation sexuelle, doxxing, comportement dangereux et autre contenu nuisible.

## Sévérité

Les niveaux sont ordonnés : `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

Les actions recommandées possibles dans le domaine sont : `NONE`, `LOG`, `WARN`, `DELETE`, `DELETE_WARN` et `ESCALATE`.

Une recommandation fournisseur n'est pas une permission d'exécution. La politique locale FoxSecura reste responsable de la décision finale.

## Paramètres par défaut

`AiModerationSettings::default()` désactive la fonction. Toutes les catégories sont disponibles, mais le seuil minimal est `Medium`; les seuils de suppression et d'alerte sont `High`; les listes de salons et rôles ignorés sont vides; le timeout fournisseur est de 5 secondes.

Le choix **désactivé par défaut** est important : une intégration externe ne doit pas modifier automatiquement le comportement de modération d'un serveur sans activation explicite.

## Pipeline recommandé

```text
message Discord
   ↓
snapshot minimal
   ↓
exemptions / salons / rôles ignorés
   ↓
préfiltrage
   ↓
construction du contexte
   ↓
fournisseur IA
   ↓
validation du schéma
   ↓
mapping de taxonomie
   ↓
politique FoxSecura
   ↓
décision / action / log
```

## Résultats et échecs

Le type `AiAnalysisOutcome` différencie une classification réussie, un traitement ignoré et un échec. Les raisons d'ignorance comprennent notamment module désactivé, aucune catégorie active, non configuré, salon/rôle ignoré, auteur exempté, préfiltrage, file pleine ou circuit ouvert.

Les échecs distinguent timeout, transport, erreur fournisseur, rate limit, réponse vide, JSON invalide et violation de schéma. Cette distinction est essentielle pour éviter de traiter un problème d'infrastructure comme une décision de modération.

## Fournisseur OpenAI

Le dépôt contient une implémentation de fournisseur OpenAI et un adaptateur séparé. La taxonomie `OpenAiModeration` est explicitement représentée dans le domaine.

Les clés API ne doivent jamais apparaître dans les logs, snapshots, raisons de décision ou tests versionnés. Les erreurs retournées à Discord doivent rester suffisamment génériques pour ne pas exposer de détails d'authentification.

## Données envoyées au modèle

`AiAnalysisRequest` contient un identifiant de guild, un salon, une révision facultative, le message courant, des messages récents, une cible facultative et les catégories activées. La présence de ces champs ne signifie pas que tout doit systématiquement être envoyé : l'intégration runtime doit appliquer un principe de minimisation des données.

## Sécurité et gouvernance

Avant une activation complète en production, la modération IA doit disposer au minimum de : limites de contexte, politique de rétention claire, gestion des timeouts/rate limits, circuit breaker, exemptions contrôlées, logs ne recopiant pas inutilement du contenu sensible, tests de schéma et stratégie explicite de fallback.

FoxSecura doit continuer à fonctionner de manière sûre lorsque le fournisseur est indisponible.
