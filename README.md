# Défi Double — TC Morgins

Application du tournoi de double du Tennis Club de Morgins : classement, cotes,
saisie des matchs (adultes et juniors) et calculatrice de points.

**Site :** https://wirfox.github.io/defi-double-Morgins/

## Architecture

```
Navigateur ──lecture seule──────────────────────────► Firestore (Firebase)
    │                                                      ▲
    │ PIN + match (HTTPS)                                  │ seul à écrire
    ▼                                                      │ (SDK Admin)
Tunnel Cloudflare ──► Serveur Node.js sur un Raspberry Pi ─┘
```

| Élément | Où | Rôle |
|---|---|---|
| `index.html` | GitHub Pages | Toute l'interface. Lit le classement directement dans Firestore. |
| `firestore.rules` | Firebase | Lecture publique du classement, **aucune écriture** depuis un navigateur, `secrets` et `config/admin` illisibles. |
| `server/` | Raspberry Pi (pm2) | Vérifie les PIN et le code admin, puis écrit dans Firestore. Écoute uniquement en local, exposé par un tunnel Cloudflare. |

Le serveur publie l'adresse de son tunnel dans `config/server` ; le site ne
l'accepte que si elle a la forme `https://….trycloudflare.com`.

## Sécurité : choix assumés

- **PIN à 4 chiffres par équipe.** Choix d'usage (saisie au bord du court).
  Compensé côté serveur : blocage par appareil pendant 15 minutes après 10 PIN faux, par équipe
  (tous appareils confondus) après 30 PIN faux d'affilée ou 100 sur 30 jours,
  jusqu'au déblocage par l'admin.
- **Empreintes des PIN poivrées** : `HMAC-SHA256(poivre, PIN)`. Le poivre
  (32 octets aléatoires) n'existe que sur le Pi, jamais dans Firestore ni dans
  les sauvegardes : une fuite de la base ne permet pas de retrouver les PIN.
- **Code admin** : 12 caractères minimum, PBKDF2-SHA256 salé (210 000
  itérations), limité à 5 essais par 15 minutes par adresse, plus un plafond
  global de 50 échecs par heure. Sessions admin par jeton, révocables.
- **Affichage des PIN dans l'admin** : les PIN sont aussi stockés chiffrés
  (AES-GCM) avec une clé dérivée du code admin (PBKDF2, 100 000 itérations,
  dans le navigateur). Cette copie n'est servie qu'à un admin connecté.
- **Site** : politique de sécurité du contenu (CSP) qui limite les scripts et
  les connexions à Firebase et au tunnel ; scripts Firebase vérifiés par
  empreinte (SRI). `'unsafe-inline'` reste nécessaire tant que l'interface
  utilise des `onclick`.
- **Secrets** : clé de compte de service Firebase, poivre et configuration des
  sauvegardes restent sur le Pi (voir `.gitignore`). La clé Firebase présente
  dans `index.html` est une clé web publique par conception ; la sécurité
  repose sur les règles Firestore.
- **Sauvegardes** : export nocturne de la base, chiffré (rclone crypt) vers un
  stockage externe, plus copies locales.

## Développement

```bash
cd server
npm install
npm test        # Node.js 22 ou plus ; Firestore est simulé en mémoire
```

Installation et exploitation du Pi : voir [`server/README.md`](server/README.md).
