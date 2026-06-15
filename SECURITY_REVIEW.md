# Revue de sécurité — Défi Double TC Morgins

Date : 2026-06-15
Périmètre : `index.html` (SPA vanilla JS + Firebase Firestore), hébergement GitHub Pages.

> **Mise à jour (posture « petit club » retenue)** — Firebase Auth et Cloud
> Functions jugés surdimensionnés pour un tournoi amical. Appliqué :
> correctifs de code (problèmes 6 et 7) directement dans `index.html`, et
> `firestore.rules` fourni en version **sans authentification** qui sort du
> mode test sans casser le panneau admin. Reste à faire côté infra :
> **déployer `firestore.rules`** (essentiel) et, en option, activer App Check.

---

## Résumé exécutif

L'application chiffre soigneusement les PINs et hashe le code admin, mais **toute cette
mécanique cryptographique est appliquée uniquement côté navigateur**. Tant que les règles
de sécurité Firestore restent en « mode test » (lecture/écriture publiques), n'importe qui
sur Internet peut lire **et modifier** l'intégralité de la base sans jamais passer par
l'application — donc sans jamais rencontrer un PIN, un hash ou un déchiffrement.

> Le verrou n'est pas sur la porte de la base de données ; il est dessiné sur l'écran.

**La faille critique n'est pas dans le code JavaScript : c'est l'absence de règles Firestore
restrictives.** Tant qu'elle n'est pas corrigée, le reste relève du cosmétique.

| # | Gravité | Problème |
|---|---------|----------|
| 1 | 🔴 Critique | Firestore en mode test → lecture/écriture/suppression publiques de toutes les collections |
| 2 | 🔴 Critique | Toute la sécurité (PIN, admin) est vérifiée côté client uniquement → contournable |
| 3 | 🟠 Élevé | PIN à 4 chiffres + SHA-256 sans sel → 10 000 combinaisons, cassables instantanément depuis le `pinHash` public |
| 4 | 🟠 Élevé | `config/admin.pinHash` lisible publiquement + SHA-256 sans sel ni itérations → brute-force hors ligne |
| 5 | 🟡 Moyen | Pas de Firebase App Check → l'API et la base sont appelables depuis n'importe quel script |
| 6 | 🟡 Moyen | XSS stockée possible via champs numériques non échappés (`pointsA`, `pointsB`) écrits directement en base |
| 7 | 🔵 Faible | `Math.random()` pour générer les PINs (non cryptographique) |
| 8 | 🔵 Faible | Portes dérobées de démo (`0000`, `demo000`) inactives en prod mais présentes dans le source |

---

## 1. 🔴 Firestore en mode test — base publiquement modifiable

Le commentaire d'installation (index.html, ~ligne 2087) indique :
« Activer Firestore en mode "test" (ou règles publiques en lecture) ».

En mode test, les règles ressemblent à `allow read, write: if true;`. Conséquences, **sans
ouvrir l'application**, avec uniquement la config Firebase (visible dans le source) et la
console du navigateur :

- **Lire** toutes les équipes/joueurs, y compris `pinHash`, `pinEnc` et `config/admin.pinHash`.
- **Écrire** n'importe quel match avec n'importe quel score/points.
- **Modifier** directement les points/étoiles d'une équipe (`points: 999999`).
- **Supprimer** toutes les collections (vandalisme).

Exemple d'attaque, copiable dans la console de n'importe quel visiteur :

```js
// Mettre son équipe en tête sans jouer
db.collection('teams').get().then(s => s.forEach(d =>
  db.collection('teams').doc(d.id).update({ points: 0 })
));
```

**C'est le point à corriger en priorité.** Voir `firestore.rules` fourni et la section
« Recommandations ».

## 2. 🔴 Sécurité 100 % côté client

`verifyPin()`, `verifyJPin()`, `onAdminPinInput()` et toutes les opérations admin (seed,
reset, recompute, suppression) lisent un document, comparent un hash **dans le navigateur**,
puis écrivent. Les règles Firestore ne participant pas à la décision, un attaquant ne lance
jamais ce code : il écrit directement.

La « double vérification du PIN juste avant l'écriture » (confirmAndSave, ligne ~2694) ne
protège donc rien côté serveur : c'est du confort d'interface, pas un contrôle d'accès.

Tant qu'il n'y a pas d'authentification Firebase, **Firestore ne peut pas distinguer un
incrément de points légitime d'un incrément malveillant** : c'est pourquoi des règles
restrictives seules ne suffisent pas — il faut une identité (voir reco 2 et 3).

## 3. 🟠 PINs à 4 chiffres, hash sans sel

`sha256Hex(pin)` sur un PIN à 4 chiffres = 10 000 hashes possibles. Comme `pinHash` est
lisible publiquement (problème 1), n'importe qui précalcule les 10 000 SHA-256 et retrouve
**tous les PINs en clair en quelques millisecondes**. Le `pinEnc`/AES devient inutile : le
hash seul suffit à divulguer le PIN.

Un PIN court reste acceptable **uniquement** si :
- le `pinHash` n'est jamais lisible publiquement, **et**
- la vérification se fait côté serveur avec limitation du débit (anti brute-force en ligne).

## 4. 🟠 Hash admin faible et lisible

`config/admin.pinHash` = SHA-256 simple (sans sel, sans itérations), et le document est lu
par le client à chaque connexion → donc lisible par tous avec le mode test. Un code de 6 à
20 caractères choisi par un humain est devinable par brute-force/dictionnaire hors ligne sur
un SHA-256 non itéré (des milliards d'essais/seconde sur GPU).

Note : la dérivation AES utilise PBKDF2 100 000 itérations (correct), mais le **hash de
connexion** admin, lui, n'est pas itéré. C'est le maillon faible.

## 5. 🟡 Pas d'App Check

Sans [Firebase App Check](https://firebase.google.com/docs/app-check), l'API Firestore
répond à n'importe quel client (script, curl). App Check (avec reCAPTCHA v3) limite l'accès
aux requêtes provenant réellement de votre site et freine fortement l'automatisation/brute-force.
La clé d'API Firebase exposée dans le source **n'est pas** une faille en soi (c'est normal
pour une app web Firebase) — la protection repose sur les règles + App Check, pas sur le
secret de la clé.

## 6. 🟡 XSS stockée via champs numériques

Les noms et scores sont bien passés par `escapeHtml()`. En revanche `+${m.pointsA}` /
`+${m.pointsB}` (renderMatchCard, ~ligne 2441) et plusieurs champs numériques sont insérés
en `innerHTML` **sans échappement**, en supposant que ce sont des nombres. Avec une base
publiquement modifiable (problème 1), un attaquant peut écrire
`pointsA: "<img src=x onerror=alert(document.cookie)>"` et déclencher une XSS chez tout
visiteur consultant l'historique. Échapper aussi ces valeurs (ou forcer `Number(...)` au
rendu) supprime ce vecteur même si la base est ouverte.

## 7. 🔵 PINs générés avec `Math.random()`

`randomPin()` (ligne ~2150) utilise `Math.random()`, non cryptographique. Risque faible
pour un tournoi de club, mais `crypto.getRandomValues()` est trivial à utiliser et
préférable pour générer des secrets.

## 8. 🔵 Portes dérobées de démo

`verifyPin` renvoie `true` pour `'0000'` et l'admin s'ouvre avec `'demo000'` quand
`!firebaseReady`. Inactif en production (Firebase est configuré), mais à retirer du source
livré pour éviter toute réactivation accidentelle.

---

## Recommandations (par priorité)

### Reco 1 — Déployer des règles Firestore (immédiat, sans changer l'architecture)
Sortir du mode test. Même sans authentification, on peut au minimum :
- **valider la forme et les bornes** des matchs créés (whitelist de champs, types, plages de
  points plausibles, `date == request.time`) — bloque les payloads XSS et les valeurs absurdes ;
- **restreindre les `update` d'équipe** aux seuls champs attendus (`points`, `pinHash`, `pinEnc`)
  pour empêcher de renommer une équipe ou de trafiquer sa cote.

⚠️ Limite honnête : sans identité, Firestore **ne peut pas** empêcher un incrément de points
malveillant ni une suppression, car ils sont indiscernables des opérations légitimes de
l'app (qui sont elles-mêmes anonymes). D'où la reco 2.

### Reco 2 — Ajouter une identité Firebase (recommandé, reste un seul fichier HTML)
- **Auth anonyme** pour tous les visiteurs : permet d'exiger `request.auth != null` en écriture
  et active App Check correctement.
- **Compte admin réel** (Auth e-mail/mot de passe + custom claim `admin: true`) : les opérations
  destructrices (seed, reset, recompute, suppression/édition de match, gestion des PINs) ne
  sont alors autorisées par les règles **que** pour `request.auth.token.admin == true`.
  Cela protège enfin le panneau admin au niveau serveur, pas seulement à l'écran.
  Le code admin actuel (hash dans Firestore, lu côté client) peut alors être abandonné.

  Tout cela se fait avec les SDK Firebase déjà chargés — l'app reste un unique `index.html`.

### Reco 3 — Validation des PINs côté serveur (idéal, pour l'intégrité des résultats)
La seule façon d'empêcher un participant de saisir un match en se faisant passer pour une
autre équipe est de valider le PIN **côté serveur**. Comme les règles Firestore ne savent pas
calculer un SHA-256, cela nécessite une **Cloud Function** (callable) `submitMatch` qui :
1. reçoit les noms d'équipes + PINs + score,
2. hashe et compare aux hash stockés (jamais exposés au client),
3. calcule les points et écrit le match de façon atomique.

Les règles Firestore interdisent alors toute écriture directe sur `matches`/`teams` côté
client. Les `pinHash`/`pinEnc` peuvent être déplacés dans une collection à lecture interdite.
(Nécessite le plan Blaze ; gratuit en pratique au volume d'un club.)

### Reco 4 — Activer App Check (reCAPTCHA v3)
Limite l'accès Firestore aux requêtes issues de votre domaine et freine le brute-force.

### Reco 5 — Durcissements de code (rapides, dans `index.html`) — ✅ APPLIQUÉ
- ✅ Coercition numérique (`num()`) sur `points`/`pointsA`/`pointsB`/`stars`/`starsA`/`starsB`/`cote` au rendu → ferme la XSS #6.
- ✅ `randomPin()` utilise désormais `crypto.getRandomValues()`.
- ✅ `onclick` des profils (équipe/joueur) sécurisés via `data-name` + `dataset` (plus d'interpolation de nom dans du JS inline).
- ⚪ Portes dérobées de démo (`0000`/`demo000`) laissées : inactives en prod (ne s'activent que si Firebase n'est pas configuré) et utiles pour tester en local.
- ⚪ Option : allonger les PINs à 6 chiffres si l'on garde une validation en ligne.

---

## Priorisation

1. **Aujourd'hui** : déployer des règles (Reco 1) + App Check (Reco 4) + correctifs code (Reco 5).
2. **Court terme** : Auth anonyme + compte admin avec custom claim (Reco 2) → protège réellement
   l'admin et les suppressions.
3. **Quand possible** : Cloud Function de saisie (Reco 3) → garantit l'intégrité des résultats.

Voir `firestore.rules` dans ce dépôt : version **sans authentification** prête à
déployer (garde le panneau admin fonctionnel), avec la variante authentifiée
documentée en commentaire pour le jour où les enjeux augmenteraient.
