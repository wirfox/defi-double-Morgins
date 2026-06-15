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

## 5. Migration unique (à faire une seule fois, quand tout est prêt)

Une fois le serveur joignable, on lancera **une fois** la migration qui déplace
les hash des PINs vers la zone privée et les retire des documents publics.
Cette étape sera déclenchée depuis l'app (je te guiderai), ou via :

```bash
curl -X POST https://TON-URL/admin/migrate -H "Content-Type: application/json" \
  -d '{"adminCode":"TON_CODE_ADMIN"}'
```

---

## Endpoints (pour info)

| Méthode | Chemin | Rôle |
|--------|--------|------|
| GET  | `/health` | Vérifier que le serveur tourne |
| POST | `/verify-pin` | Valider un PIN (retour à l'écran pendant la saisie) |
| POST | `/submit-match` | Enregistrer un match adulte (vérifie 2 PINs, calcule les points) |
| POST | `/submit-jmatch` | Enregistrer un match junior |
| POST | `/admin/set-pin` | Définir/changer le PIN d'une équipe/joueur (code admin requis) |
| POST | `/admin/migrate` | Migration unique des hash (code admin requis) |

Variables d'environnement optionnelles : `PORT` (défaut 8080),
`ALLOWED_ORIGIN` (défaut `https://wirfox.github.io`).
