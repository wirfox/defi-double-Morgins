/* ============================================================================
 *  Défi Double — TC Morgins — Serveur de validation (Raspberry Pi)
 * ----------------------------------------------------------------------------
 *  Rôle : être le SEUL à pouvoir écrire des matchs dans Firestore.
 *  Le navigateur n'écrit plus les matchs ni ne voit les hash des PINs ;
 *  il demande à ce serveur, qui vérifie les PINs côté serveur (hors de portée
 *  d'un tricheur) puis calcule les points lui-même et écrit le match.
 *
 *  Les hash des PINs sont stockés dans une collection Firestore `secrets`
 *  (interdite en lecture/écriture aux clients par les règles) ; seul ce
 *  serveur, via le SDK Admin, peut les lire.
 *
 *  Démarrage :  npm install  puis  npm start
 *  Pré-requis : serviceAccountKey.json (clé de compte de service Firebase)
 *               à côté de ce fichier. Voir README.md.
 * ========================================================================== */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const http = require('http');
const admin = require('firebase-admin');

// --- Configuration ---------------------------------------------------------
const PORT = process.env.PORT || 8080;
// Origine autorisée à appeler ce serveur (ton site GitHub Pages).
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://wirfox.github.io';

// --- Initialisation Firebase Admin -----------------------------------------
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

// --- Outils ----------------------------------------------------------------
const sha256 = (str) =>
  crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');

// Calcul des points adulte — DOIT rester identique à computePoints() du site.
function computePoints(coteA, coteB, winner, threeSet) {
  const coteW = winner === 'A' ? coteA : coteB;
  const coteL = winner === 'A' ? coteB : coteA;
  const gainW = coteL;
  let participation;
  if (coteW > coteL) participation = 3;
  else if (coteW === coteL) participation = 2;
  else participation = 1;
  const gainL = participation + (threeSet ? 1 : 0);
  return {
    deltaA: winner === 'A' ? gainW : gainL,
    deltaB: winner === 'B' ? gainW : gainL,
  };
}

// Déduit le vainqueur ('A'/'B') à partir des scores "a-b" (a = jeux équipe A).
// Renvoie null si incohérent (set à égalité, 1 set partout, scores incomplets)
// → le serveur refuse alors le match. C'est la garantie « pas de score à l'envers » :
// le vainqueur n'est jamais cru sur parole, il est recalculé à partir des sets.
function deriveWinner(scores) {
  let setsA = 0, setsB = 0, entered = 0;
  for (const k of ['set1', 'set2', 'set3']) {
    const v = scores[k];
    if (v === undefined || v === '') continue;
    const parts = String(v).split('-');
    if (parts.length !== 2) return null;
    const a = parseInt(parts[0], 10), b = parseInt(parts[1], 10);
    if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || b < 0 || a === b) return null;
    entered++;
    if (a > b) setsA++; else setsB++;
  }
  if (entered < 2 || setsA === setsB) return null;
  return setsA > setsB ? 'A' : 'B';
}

function isValidScore(s) {
  return typeof s === 'string' && s.length >= 1 && s.length <= 12;
}
function cleanScores(scores) {
  if (!scores || typeof scores !== 'object') return null;
  const { set1, set2, set3 } = scores;
  if (!isValidScore(set1) || !isValidScore(set2)) return null;
  if (set3 !== undefined && set3 !== '' && !isValidScore(set3)) return null;
  const out = { set1, set2 };
  if (set3) out.set3 = set3;
  return out;
}

// Récupère un document d'équipe/joueur par son NOM (les matchs référencent le nom).
async function findByName(collection, name) {
  if (typeof name !== 'string' || !name) return null;
  const snap = await db.collection(collection).where('name', '==', name).limit(1).get();
  if (snap.empty) return null;
  const doc = snap.docs[0];
  return { id: doc.id, ...doc.data() };
}

// Lit le hash du PIN depuis la collection privée `secrets` (jamais exposée aux clients).
async function getPinHash(docId) {
  const s = await db.collection('secrets').doc(docId).get();
  return s.exists ? s.data().hash : null;
}

async function pinIsValid(docId, pin) {
  const hash = await getPinHash(docId);
  if (!hash) return false;
  return sha256(pin) === hash;
}

// Vérifie le code admin contre config/admin.pinHash (lu via Admin SDK).
async function adminCodeIsValid(code) {
  if (typeof code !== 'string' || !code) return false;
  const doc = await db.collection('config').doc('admin').get();
  if (!doc.exists) return false;
  return sha256(code) === doc.data().pinHash;
}

// --- Anti brute-force simple (en mémoire, par IP) --------------------------
const hits = new Map(); // ip -> { count, ts }
function rateLimit(ip, max = 30, windowMs = 60_000) {
  const now = Date.now();
  const rec = hits.get(ip);
  if (!rec || now - rec.ts > windowMs) {
    hits.set(ip, { count: 1, ts: now });
    return true;
  }
  rec.count += 1;
  return rec.count <= max;
}

// --- App -------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '16kb' }));
app.use(cors({ origin: ALLOWED_ORIGIN }));

app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!rateLimit(String(ip))) {
    return res.status(429).json({ ok: false, error: 'Trop de requêtes, réessaie dans une minute.' });
  }
  next();
});

app.get('/health', (req, res) => res.json({ ok: true, service: 'defi-double-pin-server' }));

// Vérification d'un PIN (utilisée par les étapes de saisie, pour le retour à l'écran)
app.post('/verify-pin', async (req, res) => {
  try {
    const { scope, name, pin } = req.body || {};
    const collection = scope === 'junior' ? 'juniors' : 'teams';
    const doc = await findByName(collection, name);
    if (!doc) return res.json({ ok: false });
    const ok = await pinIsValid(doc.id, pin);
    console.log(`[verify-pin] ${collection} "${name}" -> ${ok ? 'OK' : 'refusé'}`);
    return res.json({ ok });
  } catch (e) {
    console.error('verify-pin:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Saisie d'un match ADULTE : vérifie les 2 PINs, calcule les points, écrit le match.
app.post('/submit-match', async (req, res) => {
  try {
    const { teamA, pinA, teamB, pinB, scores } = req.body || {};
    if (teamA === teamB) return res.status(400).json({ ok: false, error: 'Une équipe ne peut pas jouer contre elle-même' });
    const sc = cleanScores(scores);
    if (!sc) return res.status(400).json({ ok: false, error: 'Scores invalides' });
    const winner = deriveWinner(sc);
    if (!winner) return res.status(400).json({ ok: false, error: 'Scores incohérents : vainqueur indéterminable' });

    const tA = await findByName('teams', teamA);
    const tB = await findByName('teams', teamB);
    if (!tA || !tB) return res.status(400).json({ ok: false, error: 'Équipe introuvable' });

    const [okA, okB] = await Promise.all([pinIsValid(tA.id, pinA), pinIsValid(tB.id, pinB)]);
    if (!okA || !okB) return res.status(403).json({ ok: false, error: 'PIN incorrect' });

    const threeSet = !!sc.set3;
    const { deltaA, deltaB } = computePoints(Number(tA.cote), Number(tB.cote), winner, threeSet);

    await db.collection('matches').add({
      equipeA: tA.name, equipeB: tB.name,
      vainqueur: winner, scores: sc,
      pointsA: deltaA, pointsB: deltaB,
      date: FieldValue.serverTimestamp(),
    });
    console.log(`[submit-match] ${tA.name} vs ${tB.name} | vainqueur ${winner} | +${deltaA}/+${deltaB}`);
    return res.json({ ok: true, pointsA: deltaA, pointsB: deltaB });
  } catch (e) {
    console.error('submit-match:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Saisie d'un match JUNIOR : vérifie les 2 PINs, calcule les étoiles, écrit le match.
app.post('/submit-jmatch', async (req, res) => {
  try {
    const { joueurA, pinA, joueurB, pinB, scores } = req.body || {};
    if (joueurA === joueurB) return res.status(400).json({ ok: false, error: 'Un joueur ne peut pas jouer contre lui-même' });
    const sc = cleanScores(scores);
    if (!sc) return res.status(400).json({ ok: false, error: 'Scores invalides' });
    const winner = deriveWinner(sc);
    if (!winner) return res.status(400).json({ ok: false, error: 'Scores incohérents : vainqueur indéterminable' });

    const jA = await findByName('juniors', joueurA);
    const jB = await findByName('juniors', joueurB);
    if (!jA || !jB) return res.status(400).json({ ok: false, error: 'Joueur introuvable' });

    const [okA, okB] = await Promise.all([pinIsValid(jA.id, pinA), pinIsValid(jB.id, pinB)]);
    if (!okA || !okB) return res.status(403).json({ ok: false, error: 'PIN incorrect' });

    const starsA = winner === 'A' ? 2 : 1;
    const starsB = winner === 'B' ? 2 : 1;
    const greenBalls = !!(jA.green || jB.green);

    await db.collection('juniors_matches').add({
      joueurA: jA.name, joueurB: jB.name,
      vainqueur: winner, scores: sc,
      starsA, starsB, greenBalls,
      date: FieldValue.serverTimestamp(),
    });
    console.log(`[submit-jmatch] ${jA.name} vs ${jB.name} | vainqueur ${winner} | +${starsA}⭐/+${starsB}⭐`);
    return res.json({ ok: true, starsA, starsB, greenBalls });
  } catch (e) {
    console.error('submit-jmatch:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// ----- Endpoints ADMIN (protégés par le code admin) ------------------------

// Définit / met à jour le hash d'un PIN dans `secrets` (utilisé au seed, à
// l'ajout d'une équipe/joueur, et au changement de PIN). Le navigateur envoie
// le PIN en clair sur HTTPS ; le serveur stocke uniquement son hash.
app.post('/admin/set-pin', async (req, res) => {
  try {
    const { adminCode, scope, name, pin } = req.body || {};
    if (!(await adminCodeIsValid(adminCode))) return res.status(403).json({ ok: false, error: 'Code admin invalide' });
    if (!/^\d{4}$/.test(String(pin || ''))) return res.status(400).json({ ok: false, error: 'PIN = 4 chiffres' });
    const collection = scope === 'junior' ? 'juniors' : 'teams';
    const doc = await findByName(collection, name);
    if (!doc) return res.status(400).json({ ok: false, error: 'Introuvable' });
    await db.collection('secrets').doc(doc.id).set({ hash: sha256(pin) });
    return res.json({ ok: true });
  } catch (e) {
    console.error('set-pin:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Étape 1 de migration : COPIE les pinHash existants (teams/juniors) vers
// `secrets`. Ne supprime rien → l'ancien site continue de marcher pendant la
// bascule (zéro coupure). À lancer avant de mettre le nouveau code en ligne.
app.post('/admin/migrate', async (req, res) => {
  try {
    const { adminCode } = req.body || {};
    if (!(await adminCodeIsValid(adminCode))) return res.status(403).json({ ok: false, error: 'Code admin invalide' });
    let copied = 0;
    for (const coll of ['teams', 'juniors']) {
      const snap = await db.collection(coll).get();
      for (const doc of snap.docs) {
        const h = doc.data().pinHash;
        if (!h) continue;
        await db.collection('secrets').doc(doc.id).set({ hash: h });
        copied++;
      }
    }
    return res.json({ ok: true, copied });
  } catch (e) {
    console.error('migrate:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Étape 2 de migration : SUPPRIME le champ pinHash des documents publics
// (à lancer APRÈS la mise en ligne du nouveau code, qui ne lit plus pinHash).
// C'est ce qui rend les PINs non crackables (le hash n'est plus exposé).
app.post('/admin/cleanup-hashes', async (req, res) => {
  try {
    const { adminCode } = req.body || {};
    if (!(await adminCodeIsValid(adminCode))) return res.status(403).json({ ok: false, error: 'Code admin invalide' });
    let removed = 0;
    for (const coll of ['teams', 'juniors']) {
      const snap = await db.collection(coll).get();
      for (const doc of snap.docs) {
        if (doc.data().pinHash === undefined) continue;
        await doc.ref.update({ pinHash: FieldValue.delete() });
        removed++;
      }
    }
    return res.json({ ok: true, removed });
  } catch (e) {
    console.error('cleanup-hashes:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Édition d'un match ADULTE (admin) : le serveur recalcule les points.
app.post('/admin/edit-match', async (req, res) => {
  try {
    const { adminCode, matchId, scores } = req.body || {};
    if (!(await adminCodeIsValid(adminCode))) return res.status(403).json({ ok: false, error: 'Code admin invalide' });
    const sc = cleanScores(scores);
    if (!sc) return res.status(400).json({ ok: false, error: 'Scores invalides' });
    const winner = deriveWinner(sc);
    if (!winner) return res.status(400).json({ ok: false, error: 'Scores incohérents : vainqueur indéterminable' });
    const ref = db.collection('matches').doc(String(matchId));
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ ok: false, error: 'Match introuvable' });
    const old = snap.data();
    const tA = await findByName('teams', old.equipeA);
    const tB = await findByName('teams', old.equipeB);
    if (!tA || !tB) return res.status(400).json({ ok: false, error: 'Équipes introuvables' });
    const { deltaA, deltaB } = computePoints(Number(tA.cote), Number(tB.cote), winner, !!sc.set3);
    await ref.update({ vainqueur: winner, scores: sc, pointsA: deltaA, pointsB: deltaB, editedAt: FieldValue.serverTimestamp() });
    return res.json({ ok: true, pointsA: deltaA, pointsB: deltaB });
  } catch (e) {
    console.error('edit-match:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Édition d'un match JUNIOR (admin).
app.post('/admin/edit-jmatch', async (req, res) => {
  try {
    const { adminCode, matchId, scores } = req.body || {};
    if (!(await adminCodeIsValid(adminCode))) return res.status(403).json({ ok: false, error: 'Code admin invalide' });
    const sc = cleanScores(scores);
    if (!sc) return res.status(400).json({ ok: false, error: 'Scores invalides' });
    const winner = deriveWinner(sc);
    if (!winner) return res.status(400).json({ ok: false, error: 'Scores incohérents : vainqueur indéterminable' });
    const ref = db.collection('juniors_matches').doc(String(matchId));
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ ok: false, error: 'Match introuvable' });
    const starsA = winner === 'A' ? 2 : 1;
    const starsB = winner === 'B' ? 2 : 1;
    const update = { vainqueur: winner, scores: sc, starsA, starsB, editedAt: FieldValue.serverTimestamp() };
    if (snap.data().score !== undefined) update.score = FieldValue.delete();
    await ref.update(update);
    return res.json({ ok: true, starsA, starsB });
  } catch (e) {
    console.error('edit-jmatch:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// ----- Publication automatique de l'URL du tunnel dans Firestore -----------
// Le tunnel gratuit Cloudflare change d'URL à chaque redémarrage. Le serveur
// interroge les métriques de cloudflared pour connaître l'URL publique
// courante, et l'écrit dans config/server.url → l'app la lit toute seule.
// (Si ça échoue, on peut toujours définir config/server.url à la main dans la
//  console Firebase.)
const CF_METRICS = process.env.CF_METRICS || '127.0.0.1:20241';
let lastPublishedUrl = null;
function fetchQuickTunnelHostname() {
  return new Promise((resolve) => {
    const req = http.get(`http://${CF_METRICS}/quicktunnel`, (r) => {
      let body = '';
      r.on('data', (c) => (body += c));
      r.on('end', () => { try { resolve(JSON.parse(body).hostname || null); } catch (e) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(3000, () => { req.destroy(); resolve(null); });
  });
}
async function publishTunnelUrl() {
  const host = await fetchQuickTunnelHostname();
  if (!host) return;
  const url = 'https://' + host;
  if (url === lastPublishedUrl) return;
  try {
    await db.collection('config').doc('server').set(
      { url, updatedAt: FieldValue.serverTimestamp() },
      { merge: true }
    );
    lastPublishedUrl = url;
    console.log('URL du tunnel publiée dans Firestore :', url);
  } catch (e) {
    console.error('publishTunnelUrl:', e.message);
  }
}
setTimeout(publishTunnelUrl, 4000);
setInterval(publishTunnelUrl, 60_000);

app.listen(PORT, () => {
  console.log(`Serveur Défi Double démarré sur le port ${PORT}`);
  console.log(`Origine autorisée : ${ALLOWED_ORIGIN}`);
});
