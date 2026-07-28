# Serveur Défi Double (Raspberry Pi)

Ce petit serveur est le **seul autorisé à écrire les matchs** dans Firestore.
Le site web ne fait plus qu'afficher (lecture) et **demander** à ce serveur de
valider les PINs et d'enregistrer les matchs. Résultat : impossible de tricher
en écrivant un match directement, et les PINs ne sont plus crackables (leurs
hash ne sont jamais envoyés au navigateur).

> ⚠️ Le serveur doit être **allumé et joignable** pendant tout le tournoi pour
> que la saisie fonctionne. La **consultation** du classement marche même s'il
> est éteint.

---

## 1. Installer Node.js sur le Raspberry

```bash
sudo apt update
sudo apt install -y nodejs npm
node -v        # vérifie : v18 ou plus, idéalement
```

## 2. Récupérer la clé Firebase (compte de service)

1. Console Firebase → ⚙️ **Paramètres du projet** → onglet **Comptes de service**.
2. Clique **« Générer une nouvelle clé privée »** → un fichier `.json` se télécharge.
3. Renomme-le **`serviceAccountKey.json`** et place-le **dans ce dossier `server/`**,
   à côté de `server.js`.

> 🔒 Ce fichier est un SECRET. Il est déjà dans `.gitignore` : ne le mets JAMAIS
> sur GitHub, ne le partage pas.

## 3. Installer et lancer

```bash
cd server
npm install
npm start
```

Tu dois voir : `Serveur Défi Double démarré sur le port 8080`.
Teste en local : ouvre `http://localhost:8080/health` → tu dois voir `{"ok":true,...}`.

## 4. Rendre le serveur joignable en HTTPS (Cloudflare Tunnel)

Le site est en HTTPS : il faut donc une URL HTTPS pour le Pi.

```bash
# Installer cloudflared (une fois)
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/

# Lancer un tunnel rapide vers le serveur local
cloudflared tunnel --url http://localhost:8080
```

Cloudflared affiche une URL du type `https://xxxx-yyyy.trycloudflare.com`.
**C'est cette URL** que tu donneras à l'app (étape suivante, dans `index.html`).
Teste : ouvre `https://xxxx-yyyy.trycloudflare.com/health` → `{"ok":true,...}`.

> Astuce : pour une URL **stable** (qui ne change pas à chaque redémarrage),
> on peut créer un tunnel nommé Cloudflare (gratuit) lié à un domaine. Le
> tunnel rapide ci-dessus suffit pour tester ; demande-moi pour la version
> stable.

## 5. Mise à jour de sécurité — ordre de déploiement

Le serveur, le site et les règles Firestore ont été durcis ensemble. **L'ordre
compte** : le serveur est compatible avec l'ancien site, mais l'inverse n'est
pas vrai. Suis les étapes dans l'ordre, rien n'est perdu si tu t'arrêtes en
cours de route.

> 💾 **Avant de commencer**, fais un export Firestore (Console Firebase >
> Firestore > Importer/Exporter). Rien dans cette procédure n'efface de
> données, mais une sauvegarde ne coûte rien.

**Étape 1 — mettre à jour le Pi (aucune coupure)**

```bash
cd ~/defi-double-Morgins        # adapte le chemin
git pull
cd server
npm install
# puis redémarre le serveur (Ctrl-C puis `npm start`, ou `sudo systemctl restart ...`)
```

Le nouveau serveur accepte encore les appels de l'ancien site : à ce stade,
tout continue de fonctionner exactement comme avant.

**Étape 2 — mettre le nouveau site en ligne**

Fusionne la branche dans `main` : GitHub Pages publie le nouveau site en une
minute environ. Ouvre l'admin et connecte-toi **avec ton code habituel** — il
est reconnu, puis converti automatiquement au nouveau format (PBKDF2 salé,
rangé dans la zone privée). Aucun risque de te retrouver bloqué dehors.

**Étape 3 — déplacer les PINs chiffrés hors des documents publics**

```bash
curl -X POST https://TON-URL/admin/migrate-pinenc -H "Content-Type: application/json" \
  -d '{"adminCode":"TON_CODE_ADMIN"}'
curl -X POST https://TON-URL/admin/cleanup-hashes -H "Content-Type: application/json" \
  -d '{"adminCode":"TON_CODE_ADMIN"}'
```

La première commande copie les PINs chiffrés dans la zone privée, la seconde
retire des documents publics tout ce qui était sensible (`pinHash`, `pinEnc`,
`pin`). Les deux sont **rejouables sans risque** : elles n'écrasent jamais un
secret déjà en place.

**Étape 4 — publier les nouvelles règles Firestore**

Console Firebase > Firestore > Règles > colle le contenu de `firestore.rules`
> Publier. À partir de là, plus aucune écriture n'est possible depuis un
navigateur : tout passe par ce serveur.

**Étape 5 — changer le code admin (recommandé)**

Dans le panneau admin, section « Changer le code admin ». Utile parce que
l'ancienne empreinte a été publiquement lisible pendant un temps : si ton code
était court ou devinable, considère-le comme compromis. Les PINs sont
rechiffrés automatiquement au passage.

---

## Ce qui a été corrigé

| Avant | Maintenant |
|-------|-----------|
| La limite anti-brute-force se contournait avec un en-tête HTTP falsifié, rendant les PINs à 4 chiffres cassables en quelques minutes | Blocage **par équipe/joueur** après 10 essais faux, insensible au changement d'IP |
| L'empreinte du code admin était lisible par tout le monde, en SHA-256 non salé (cassable hors ligne) | PBKDF2 salé, 210 000 itérations, dans une zone que le navigateur ne peut pas lire |
| Les PINs chiffrés étaient publics : deuxième voie d'attaque sur le code admin | Servis uniquement à un admin authentifié |
| N'importe qui pouvait supprimer équipes, joueurs et matchs depuis la console du navigateur | Suppressions réservées à l'admin, côté serveur |
| N'importe qui pouvait écrire les champs de PIN et le drapeau « catégorie verte » | Écriture impossible depuis le navigateur |
| Le code admin ne pouvait plus jamais être changé | Rotation possible depuis le panneau admin |
| La liste des tentatives grossissait sans fin en mémoire | Purge périodique et bornage |

---

## Endpoints (pour info)

Les endpoints `/admin/*` acceptent soit `adminToken` (jeton de session obtenu
via `/admin/login`), soit `adminCode` (compatibilité).

| Méthode | Chemin | Rôle |
|--------|--------|------|
| GET  | `/health` | Vérifier que le serveur tourne |
| GET  | `/admin/status` | Le code admin est-il déjà défini ? |
| POST | `/verify-pin` | Valider un PIN (retour à l'écran pendant la saisie) |
| POST | `/submit-match` | Enregistrer un match adulte (vérifie 2 PINs, calcule les points) |
| POST | `/submit-jmatch` | Enregistrer un match junior |
| POST | `/admin/login` | Se connecter et obtenir un jeton de session |
| POST | `/admin/setup` | Définir le tout premier code admin |
| POST | `/admin/change-code` | Changer le code admin (rechiffre les PINs) |
| POST | `/admin/pins` | Lire les PINs chiffrés (affichage admin) |
| POST | `/admin/set-pin` | Définir/changer le PIN d'une équipe/joueur |
| POST | `/admin/add-team` · `/admin/add-junior` | Créer une équipe / un joueur |
| POST | `/admin/delete-team` · `/admin/delete-junior` | Supprimer une équipe / un joueur |
| POST | `/admin/delete-match` · `/admin/delete-jmatch` | Supprimer un match |
| POST | `/admin/set-green` | Basculer la catégorie verte d'un junior |
| POST | `/admin/edit-match` · `/admin/edit-jmatch` | Corriger un score (points recalculés) |
| POST | `/admin/migrate` · `/admin/migrate-pinenc` | Migrations (rejouables) |
| POST | `/admin/cleanup-hashes` | Retirer les champs sensibles des documents publics |

Variables d'environnement optionnelles : `PORT` (défaut 8080),
`ALLOWED_ORIGIN` (défaut `https://wirfox.github.io`),
`TRUST_CF_HEADER` (défaut activé — mettre `0` si le serveur est exposé
directement, sans tunnel Cloudflare),
`SETUP_TOKEN` (si défini, exigé pour créer le tout premier code admin).

> ⚠️ **Si tu perds le code admin** : supprime le document `secrets/admin` dans
> la console Firebase, puis rouvre l'admin sur le site — il te proposera d'en
> définir un nouveau.
