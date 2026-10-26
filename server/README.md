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

Il faut **Node.js 22 ou plus** (exigé par `firebase-admin` 14 ; les versions
18 et 20 ne reçoivent plus de correctifs de sécurité). Le paquet `nodejs` de
Debian/Raspberry Pi OS est trop ancien : passe par le dépôt NodeSource.

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node -v        # doit afficher v22.x
```

Si `apt` signale un conflit avec le paquet `npm` de Debian : `sudo apt remove -y npm`,
puis relance `sudo apt install -y nodejs` (celui de NodeSource contient déjà npm).

Si `pm2` était déjà installé avec une ancienne version de Node :
`sudo npm install -g pm2 && pm2 update`.

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

> ✅ Les étapes 1 à 4 ont été faites (juillet et octobre 2026) : elles restent ici pour l'historique.
> Pour mettre le Pi à jour aujourd'hui : `cd ~/defi-double-Morgins && git pull && cd server && npm install && pm2 restart defi-double`.

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

> ✅ Faite en octobre 2026. Depuis, les actions admin exigent le jeton de connexion
> (`adminToken` obtenu via `/admin/login`), et la route `/admin/migrate-pinenc` a été
> retirée : les commandes ci-dessous ne sont gardées que pour l'historique.

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
| La limite anti-brute-force se contournait avec un en-tête HTTP falsifié, rendant les PINs à 4 chiffres cassables en quelques minutes | Blocage **par appareil** après 10 PIN faux (15 min), et **par équipe/joueur**, tous appareils confondus, après 30 PIN faux d'affilée ou 100 sur 30 jours (jusqu'au déblocage par l'admin), insensible au changement d'IP |
| L'empreinte du code admin était lisible par tout le monde, en SHA-256 non salé (cassable hors ligne) | PBKDF2 salé, 210 000 itérations, dans une zone que le navigateur ne peut pas lire |
| Les PINs chiffrés étaient publics : deuxième voie d'attaque sur le code admin | Servis uniquement à un admin authentifié |
| N'importe qui pouvait supprimer équipes, joueurs et matchs depuis la console du navigateur | Suppressions réservées à l'admin, côté serveur |
| N'importe qui pouvait écrire les champs de PIN et le drapeau « catégorie verte » | Écriture impossible depuis le navigateur |
| Le code admin ne pouvait plus jamais être changé | Rotation possible depuis le panneau admin |
| La liste des tentatives grossissait sans fin en mémoire | Purge périodique et bornage |
| Les empreintes des PIN (SHA-256 d'un PIN à 4 chiffres) se cassaient en une seconde si la base fuitait | HMAC avec un poivre gardé seulement sur le Pi (voir « Poivre des PIN ») |
| Le limiteur du code admin pouvait être « vidé » en l'inondant depuis des milliers d'adresses IPv6 | Limiteur qui refuse les nouvelles adresses quand il est plein, et plafond **global** : au-delà de 50 codes faux en une heure, la connexion admin est suspendue, sauf depuis les adresses d'où l'admin s'est déjà connecté |
| Une erreur (JSON mal formé…) renvoyait une page HTML avec les chemins internes du Pi | Réponse JSON courte, avec l'en-tête CORS |
| Changer une cote obligeait à supprimer puis recréer l'équipe (nouveau PIN, et risque de mélanger les historiques) | Bouton « Cote » dans l'admin ; chaque match garde la cote du jour, utilisée si on corrige son score plus tard |

---

## Endpoints (pour info)

Les endpoints `/admin/*` exigent `adminToken`, le jeton de session obtenu via
`/admin/login` (valable 8 h, perdu au redémarrage du serveur).

| Méthode | Chemin | Rôle |
|--------|--------|------|
| GET  | `/health` | Vérifier que le serveur tourne |
| GET  | `/admin/status` | Le code admin est-il déjà défini ? |
| POST | `/verify-pin` | Valider un PIN (retour à l'écran pendant la saisie) |
| POST | `/submit-match` | Enregistrer un match adulte (vérifie 2 PINs, calcule les points) |
| POST | `/submit-jmatch` | Enregistrer un match junior |
| POST | `/admin/login` | Se connecter et obtenir un jeton de session |
| POST | `/admin/logout` | Oublier le jeton de session tout de suite |
| POST | `/admin/setup` | Définir le tout premier code admin (depuis le Pi uniquement) |
| POST | `/admin/change-code` | Changer le code admin (rechiffre les PINs) |
| POST | `/admin/pins` | Lire les PINs chiffrés (affichage admin) |
| POST | `/admin/set-pin` | Définir/changer le PIN d'une équipe/joueur |
| POST | `/admin/add-team` · `/admin/add-junior` | Créer une équipe / un joueur |
| POST | `/admin/delete-team` · `/admin/delete-junior` | Supprimer une équipe / un joueur |
| POST | `/admin/delete-match` · `/admin/delete-jmatch` | Supprimer un match |
| POST | `/admin/set-green` | Basculer la catégorie verte d'un junior |
| POST | `/admin/set-cote` | Changer la cote d'une équipe (sans toucher aux points ni au PIN) |
| POST | `/admin/add-jmatch-draw` | Enregistrer une égalité junior (+1⭐ chacun) |
| POST | `/admin/locks` | Lister les saisies bloquées (trop de PIN faux) |
| POST | `/admin/unlock-pin` | Débloquer la saisie de PIN d'une équipe / d'un joueur |
| POST | `/admin/edit-match` · `/admin/edit-jmatch` | Corriger un score (points recalculés) |
| POST | `/admin/cleanup-hashes` | Retirer les champs sensibles des documents publics |

Variables d'environnement optionnelles : `PORT` (défaut 8080),
`ALLOWED_ORIGIN` (défaut `https://wirfox.github.io`),
`TRUST_CF_HEADER` (défaut activé — mettre `0` si le serveur est exposé
directement, sans tunnel Cloudflare),
`SETUP_TOKEN` (si défini, exigé pour créer le tout premier code admin),
`LISTEN_HOST` (par défaut, le serveur n'écoute que le Pi lui-même, `127.0.0.1` et `::1`,
pour que le tunnel soit la seule porte d'entrée ; `LISTEN_HOST=0.0.0.0` rétablit l'écoute
sur tout le réseau local).

> ⚠️ **Si la connexion admin est suspendue** (« Trop de codes admin faux… ») : quelqu'un a
> essayé plus de 50 codes en une heure. Le blocage est en mémoire : sur le Pi,
> `pm2 restart defi-double` le lève, puis connecte-toi tout de suite. Les adresses d'où tu
> t'es déjà connecté restent autorisées pendant le blocage, et une commande lancée sur le Pi
> lui-même n'est jamais bloquée.

> ⚠️ **Si tu perds le code admin** : supprime le document `secrets/admin` dans
> la console Firebase, puis, **sur le Raspberry Pi**, crée le nouveau code
> (12 à 64 caractères, demandé deux fois sans s'afficher) :
>
> ```bash
> cd ~/defi-double-Morgins/server && npm run admin-setup
> ```
>
> Les PINs chiffrés avec l'ancien code ne sont plus lisibles dans l'admin :
> retape-les avec « Modifier » (les mêmes si tu les as encore, sinon de
> nouveaux à redonner aux équipes). La vérification des PINs, elle, continue
> de marcher.
>
> Par sécurité, le serveur refuse de créer le code admin depuis le site ou
> depuis un autre appareil : personne ne peut donc prendre ta place pendant
> la procédure. Recharge ensuite l'admin sur le site et connecte-toi.

## Poivre des PIN (clé `pinPepper.key`)

Les empreintes des PIN rangées dans Firestore (`secrets/{id}.hmac`) sont calculées avec une
clé secrète de 32 octets, le **poivre**, qui n'existe **que sur le Pi** : HMAC-SHA256(poivre, PIN).
Sans elle, quelqu'un qui récupère la base (règles mal écrites, export, sauvegarde en clair) ne
peut tester aucun des 10 000 PIN possibles **à partir des empreintes**.

Attention, deux limites :
- la base contient aussi `pinEnc` (le PIN chiffré avec le **code admin**, pour l'affichage
  dans l'admin). Une copie de la base permet donc d'essayer de deviner le code admin hors
  ligne : c'est pour ça qu'il doit être **long et aléatoire** (12 caractères minimum, idéalement
  20 et plus, généré par Proton Pass) ;
- les sauvegardes faites **avant** le poivre (dont `…-avant-poivre-….json.gz`) contiennent
  encore les anciennes empreintes, cassables : garde-les sur le Pi seulement, la rotation des
  30 jours les supprime.

Le poivre n'est **ni dans Firestore, ni dans les sauvegardes, ni sur GitHub**. S'il est perdu,
plus aucun PIN n'est reconnu (il faudrait en redonner de nouveaux à toutes les équipes) :
**garde-en une copie dans Proton Pass.** Le serveur refuse de démarrer sans lui.

Mise en place (une seule fois, sur le Pi) :

```bash
cd ~/defi-double-Morgins/server
(umask 077 && openssl rand -hex 32 > pinPepper.key)   # crée la clé, lisible par toi seul
cat pinPepper.key                                       # copie ces 64 caractères dans Proton Pass
pm2 restart defi-double                                 # le serveur utilise la clé
npm run pepper-migrate                                  # simulation : combien de PIN à convertir
npm run pepper-migrate -- --apply                       # conversion (sauvegarde avant, vérification après)
```

La conversion ne change **pas** les PIN des joueurs : elle retrouve chaque PIN à partir de
l'ancienne empreinte SHA-256 et la remplace par la nouvelle. Elle est rejouable sans risque.
L'ancien format reste accepté par le serveur tant qu'il en reste ; après la restauration
d'une sauvegarde d'avant le poivre, relance `npm run pepper-migrate -- --apply`.

Si le Pi est reconstruit : remets **le même** `pinPepper.key` (depuis Proton Pass, avec
`chmod 600`), à côté de `serviceAccountKey.json`.

---

## Sauvegarde et restauration de la base

Deux scripts, à lancer **sur le Pi** depuis le dossier `server` (ils utilisent la
même clé `serviceAccountKey.json` que le serveur) :

```bash
# Sauvegarde complète (toutes les collections, PIN compris) : ne fait que LIRE la base
node scripts/backup-export.js                 # -> ~/backups/defi-double/defi-double-AAAA-MM-JJ.json.gz
node scripts/backup-export.js /autre/dossier  # dossier au choix

# Restauration : montre d'abord ce qui changerait, sans rien écrire
node scripts/backup-restore.js ~/backups/defi-double/defi-double-2026-10-14.json.gz
node scripts/backup-restore.js <fichier> --details           # + la liste des documents
node scripts/backup-restore.js <fichier> --apply             # recrée les documents disparus
node scripts/backup-restore.js <fichier> --apply --only matches
node scripts/backup-restore.js <fichier> --apply --mode overwrite   # remet aussi les modifiés
```

- Le fichier est compressé et lisible seulement par ton utilisateur (`600`, dossier `700`).
  Code de sortie `0` = réussi, `1` = échec : utilisable tel quel dans un script bash et cron.
- La restauration **ne supprime jamais rien**. Avant d'écrire (`--apply`), elle sauvegarde
  l'état actuel à côté (`…-avant-restauration-HHMMSS.json.gz`).
- En mode `overwrite`, `config/server` (l'adresse actuelle du tunnel) n'est jamais remis, ni
  le code admin (`secrets/admin`) sauf avec `--include-admin`.
- Une sauvegarde d'un autre projet Firebase est refusée.
- Dans cron, mets le chemin complet de node (`which node`) : cron ne connaît pas le même PATH que toi.

### Si le Pi est perdu : déchiffrer la copie OneDrive depuis un PC Windows

Il suffit de rclone (rclone.org/downloads), des deux mots de passe du chiffrement
(mot de passe + salt) et de `scripts/dechiffrer-sauvegarde.ps1` (à télécharger depuis GitHub) :

1. Sur onedrive.com, télécharge les fichiers de `Sauvegardes/defi-double` **sans les renommer**
   (leur nom illisible est chiffré lui aussi), dans un dossier, par exemple `Downloads\chiffre`.
2. Dans PowerShell, dans le dossier de rclone ou du script :
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\dechiffrer-sauvegarde.ps1 -Source C:\Users\Moi\Downloads\chiffre
   ```
3. Les mots de passe sont demandés masqués. Les fichiers déchiffrés arrivent dans un dossier
   `dechiffre-…` à côté de la source, et les `.json.gz` sont décompressés en `.json`.


## Tests

Les tests du serveur tournent sans Firebase (une fausse base en mémoire remplace
Firestore) :

```bash
cd server
npm install
npm test
```
