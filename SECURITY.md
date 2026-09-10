# Politique de sécurité

FoxSecura est un logiciel de sécurité. Les vulnérabilités exploitables, secrets exposés et mécanismes permettant de contourner une protection doivent être traités avec prudence.

## Versions prises en charge

FoxSecura V2 est en développement actif. La branche `main` représente l'état actuellement maintenu du projet.

| Version | Support sécurité |
| --- | --- |
| `main` / développement V2 | Oui |
| Anciennes versions ou forks non maintenus | Non garanti |

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique contenant les détails exploitables d'une vulnérabilité.**

Utilisez en priorité le mécanisme privé GitHub du dépôt lorsqu'il est disponible : **Security → Advisories → Report a vulnerability**. Si cette option n'est pas disponible, contactez un mainteneur via GitHub en demandant un canal privé, sans publier le secret, le payload ou la procédure d'exploitation.

Incluez, lorsque possible :

- la zone affectée ;
- l'impact attendu ;
- les préconditions ;
- une reproduction minimale ;
- la version, branche ou commit concerné ;
- les permissions Discord nécessaires ;
- les journaux pertinents après suppression des secrets et données personnelles ;
- une proposition de correctif si vous en avez une.

## Ce qui est considéré comme sensible

Exemples :

- contournement fiable d'une protection anti-raid, anti-spam, anti-nuke ou AutoMod ;
- élévation de privilèges ou action exécutée avec un niveau d'autorisation incorrect ;
- exposition d'un token Discord, d'une clé API, d'un secret ou d'informations privées ;
- injection ou validation insuffisante permettant une action non prévue ;
- corruption ou fuite de données SQLite ;
- défaut de contrôle d'accès dans une commande ou interaction Discord ;
- mécanisme de modération IA permettant une sanction dangereuse à partir d'une réponse fournisseur invalide ;
- vulnérabilité d'une dépendance réellement exploitable dans le contexte FoxSecura.

Une simple demande de durcissement sans scénario exploitable peut être ouverte comme issue normale.

## Divulgation coordonnée

Merci de laisser aux mainteneurs une possibilité raisonnable d'analyser et corriger le problème avant publication détaillée. Évitez de partager un proof-of-concept offensif ou un secret réel dans un canal public tant qu'un correctif ou une mitigation n'est pas disponible.

FoxSecura ne promet pas de délai fixe de correction : la priorité dépend de la sévérité, de l'exploitabilité et de la disponibilité des mainteneurs. Un problème critique peut conduire à une mitigation temporaire avant un correctif complet.

## Secrets exposés

Si vous découvrez un secret valide dans le dépôt ou ses artefacts :

1. ne le recopiez pas dans une issue publique ;
2. signalez-le par le canal privé ;
3. considérez le secret comme compromis ;
4. révoquez ou faites révoquer le secret concerné ;
5. nettoyez l'historique si nécessaire après rotation.

Supprimer uniquement le fichier ou le commit visible ne rend pas un secret de nouveau sûr.

## Recherche de sécurité

Les tests doivent être réalisés sur vos propres environnements, bots et serveurs Discord, ou avec une autorisation explicite. Ne perturbez pas de serveurs tiers et ne collectez pas de données auxquelles vous n'êtes pas autorisé à accéder.

## Correctifs de sécurité

Une PR publique de correctif peut elle-même révéler une vulnérabilité avant que les utilisateurs puissent se protéger. Pour un problème sensible, coordonnez d'abord la stratégie de correction avec les mainteneurs via le canal privé.

Une fois le risque de divulgation levé, le correctif doit normalement inclure des tests de non-régression et la documentation des changements de comportement pertinents.
