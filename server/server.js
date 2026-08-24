/* ============================================================================
 *  Défi Double — TC Morgins — Serveur de validation (Raspberry Pi)
 * ----------------------------------------------------------------------------
 *  Rôle : être le SEUL à pouvoir écrire dans Firestore (matchs, équipes,
 *  joueurs, PINs). Le navigateur ne fait plus que LIRE les classements ; tout
 *  le reste passe par ici, où les PINs et le code admin sont vérifiés hors de
 *  portée d'un tricheur.
 *
 *  Ce qui est gardé secret (collection `secrets`, interdite aux clients) :
 *    - le hash du PIN de chaque équipe/joueur       → secrets/{docId}.hash
 *    - le PIN chiffré pour l'affichage admin        → secrets/{docId}.pinEnc
 *    - l'empreinte PBKDF2 du code admin             → secrets/admin
 *
 *  Compatibilité : les anciens appels (code admin envoyé à chaque requête,
 *  pinEnc encore sur les documents publics, empreinte admin encore dans
 *  config/admin) restent acceptés, pour que l'ancien site continue de marcher
 *  pendant la bascule. La conversion se fait toute seule, sans coupure.
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
// Le trafic arrive par le tunnel Cloudflare, qui pose lui-même l'en-tête
// CF-Connecting-IP (et écrase celui qu'un client tenterait d'envoyer). Mettre
// TRUST_CF_HEADER=0 si un jour le serveur est exposé en direct, sans tunnel.
const TRUST_CF_HEADER = process.env.TRUST_CF_HEADER !== '0';
// Si défini, exige ce jeton pour créer le tout premier code admin (empêche
// qu'un inconnu prenne la place avant l'organisateur).
const SETUP_TOKEN = process.env.SETUP_TOKEN || '';

// --- Initialisation Firebase Admin -----------------------------------------
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

// --- Outils crypto ---------------------------------------------------------
const sha256 = (str) =>
  crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');

// Comparaison à temps constant : ne révèle pas, par sa durée, combien de
// caractères du secret sont corrects.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Le code admin est dérivé avec PBKDF2 (salé, 210 000 itérations) et non plus
// avec un simple SHA-256 : même si l'empreinte fuitait, la casser hors-ligne
// coûterait des ordres de grandeur plus cher.
const PBKDF2_ITERATIONS = 210_000;
const PBKDF2_KEYLEN = 32;

function pbkdf2(code, saltHex, iterations) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      String(code), Buffer.from(saltHex, 'hex'),
      iterations, PBKDF2_KEYLEN, 'sha256',
      (err, dk) => (err ? reject(err) : resolve(dk.toString('hex')))
    );
  });
}

async function buildAdminRecord(code) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await pbkdf2(code, salt, PBKDF2_ITERATIONS);
  return { algo: 'pbkdf2-sha256', salt, iterations: PBKDF2_ITERATIONS, hash };
}

// --- Calcul des points -----------------------------------------------------
// Calcul des points adulte — DOIT rester identique à computePoints() du site.
function computePoints(coteA, coteB, winner, threeSet) {
  const coteW = winner === 'A' ? coteA : coteB;
  const coteL = winner === 'A' ? coteB : coteA;
  const gainW = coteL;
  let participation;
  if (coteW > coteL) participation = 3;
  else if (coteW === coteL) participation = 2;
  else participation = 1;
  // Règle B : le perdant ne peut jamais gagner plus que le vainqueur.
  // Le vainqueur gagne coteL, donc on plafonne le perdant à (coteL - 1).
  const gainL = Math.max(0, Math.min(participation + (threeSet ? 1 : 0), coteL - 1));
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

// Nom d'équipe / de joueur : les créations passent désormais par ici, donc
// c'est le bon endroit pour refuser les caractères de contrôle et les balises
// (défense en profondeur contre une injection via un nom).
function cleanName(name) {
  if (typeof name !== 'string') return null;
  const n = name.trim().replace(/[\x00-\x1f\x7f]/g, '');
  if (n.length < 1 || n.length > 80) return null;
  if (/[<>]/.test(n)) return null;
  return n;
}

const isPin = (pin) => /^\d{4}$/.test(String(pin || ''));
// Le PIN chiffré est produit par le navigateur (AES-GCM) : on ne sait pas le
// déchiffrer ici, on vérifie juste que ça ressemble à de l'hexadécimal borné.
const isPinEnc = (v) => typeof v === 'string' && /^[0-9a-f]{24,512}$/i.test(v);

// --- Accès Firestore -------------------------------------------------------
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
  return safeEqual(sha256(pin), hash);
}

// --- Limiteurs -------------------------------------------------------------
// Limiteur générique à fenêtre glissante. La Map est purgée périodiquement et
// bornée : sans ça, un attaquant qui varie sa clé la ferait grossir sans fin
// (fuite mémoire sur le Raspberry).
function createLimiter({ max, windowMs, maxKeys = 10_000 }) {
  const hits = new Map();
  function purge() {
    const now = Date.now();
    for (const [k, rec] of hits) if (now - rec.ts > windowMs) hits.delete(k);
  }
  function allow(key) {
    const now = Date.now();
    if (hits.size > maxKeys) {
      purge();
      // Toujours saturée : on repart à zéro plutôt que de gonfler indéfiniment.
      // La vraie protection des PINs est le verrou par cible ci-dessous, dont
      // le nombre de clés est borné par le nombre d'équipes/joueurs.
      if (hits.size > maxKeys) hits.clear();
    }
    const rec = hits.get(key);
    if (!rec || now - rec.ts > windowMs) { hits.set(key, { count: 1, ts: now }); return true; }
    rec.count += 1;
    return rec.count <= max;
  }
  return { allow, purge, reset: (k) => hits.delete(k) };
}

// Plafond global par IP — filet de sécurité, facilement contourné par qui
// change d'IP, d'où le verrou par cible qui suit.
const ipLimiter = createLimiter({ max: 60, windowMs: 60_000 });
// Tentatives de connexion admin : beaucoup plus strict.
const adminLoginLimiter = createLimiter({ max: 5, windowMs: 15 * 60_000 });

// Verrou par cible : au bout de PIN_MAX_FAILS PINs faux pour une même équipe /
// un même joueur, cette cible est bloquée pendant PIN_LOCK_MS — quelle que
// soit l'IP de l'attaquant. C'est ce qui rend inatteignables les 10 000
// combinaisons d'un PIN à 4 chiffres.
const PIN_MAX_FAILS = 10;
const PIN_LOCK_MS = 15 * 60_000;
const pinFails = new Map(); // docId -> { count, ts }

function pinTargetLocked(docId) {
  const rec = pinFails.get(docId);
  if (!rec) return false;
  if (Date.now() - rec.ts > PIN_LOCK_MS) { pinFails.delete(docId); return false; }
  return rec.count >= PIN_MAX_FAILS;
}
function pinTargetFail(docId) {
  const now = Date.now();
  const rec = pinFails.get(docId);
  if (!rec || now - rec.ts > PIN_LOCK_MS) pinFails.set(docId, { count: 1, ts: now });
  else rec.count += 1;
}
function pinTargetReset(docId) { pinFails.delete(docId); }

// Vérifie un PIN en tenant compte du verrou par cible.
// Renvoie 'ok' | 'bad' | 'locked'.
async function checkPin(docId, pin) {
  if (pinTargetLocked(docId)) return 'locked';
  if (await pinIsValid(docId, pin)) { pinTargetReset(docId); return 'ok'; }
  pinTargetFail(docId);
  return 'bad';
}

// --- Authentification admin ------------------------------------------------
// Jetons de session : le site s'authentifie une fois, puis présente un jeton.
// Le code admin ne circule donc plus à chaque requête.
const ADMIN_TOKEN_TTL = 8 * 3600_000;
const adminTokens = new Map(); // token -> expiration

function issueAdminToken() {
  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.set(token, Date.now() + ADMIN_TOKEN_TTL);
  return token;
}
function adminTokenIsValid(token) {
  if (typeof token !== 'string' || !token) return false;
  const exp = adminTokens.get(token);
  if (!exp) return false;
  if (Date.now() > exp) { adminTokens.delete(token); return false; }
  return true;
}

// Ménage périodique : sans ça, les Map des limiteurs et des jetons grossiraient
// indéfiniment (le Raspberry n'a pas beaucoup de mémoire).
setInterval(() => {
  ipLimiter.purge();
  adminLoginLimiter.purge();
  const now = Date.now();
  for (const [k, rec] of pinFails) if (now - rec.ts > PIN_LOCK_MS) pinFails.delete(k);
  for (const [t, exp] of adminTokens) if (now > exp) adminTokens.delete(t);
}, 60_000).unref();

// Vérifie le code admin. Nouveau format : secrets/admin (PBKDF2 salé).
// Ancien format accepté en repli (config/admin.pinHash, SHA-256 non salé) puis
// converti automatiquement → personne ne peut se retrouver enfermé dehors.
async function adminCodeIsValid(code) {
  if (typeof code !== 'string' || code.length < 6 || code.length > 200) return false;

  const ref = db.collection('secrets').doc('admin');
  const snap = await ref.get();
  if (snap.exists && snap.data().hash) {
    const rec = snap.data();
    const computed = await pbkdf2(code, rec.salt, rec.iterations || PBKDF2_ITERATIONS);
    return safeEqual(computed, rec.hash);
  }

  const legacy = await db.collection('config').doc('admin').get();
  if (!legacy.exists || typeof legacy.data().pinHash !== 'string') return false;
  if (!safeEqual(sha256(code), legacy.data().pinHash)) return false;

  await ref.set({ ...(await buildAdminRecord(code)), updatedAt: FieldValue.serverTimestamp() });
  console.log('[admin] ancien code converti au format PBKDF2 (secrets/admin)');
  return true;
}

async function adminExists() {
  const s = await db.collection('secrets').doc('admin').get();
  if (s.exists && s.data().hash) return true;
  const legacy = await db.collection('config').doc('admin').get();
  return legacy.exists && typeof legacy.data().pinHash === 'string';
}

function clientIp(req) {
  if (TRUST_CF_HEADER) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return cf.trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// Garde d'accès admin : accepte un jeton de session (nouveau site) ou le code
// admin en clair (ancien site, le temps de la bascule). Répond elle-même en
// cas de refus ; l'appelant s'arrête si elle renvoie false.
async function requireAdmin(req, res) {
  const { adminToken, adminCode } = req.body || {};
  if (adminTokenIsValid(adminToken)) return true;

  const ip = clientIp(req);
  if (!adminLoginLimiter.allow(ip)) {
    res.status(429).json({ ok: false, error: 'Trop de tentatives. Réessaie dans 15 minutes.' });
    return false;
  }
  if (await adminCodeIsValid(adminCode)) {
    // Seuls les échecs doivent consommer le quota : sinon un admin légitime
    // enchaînant des actions (l'ancien site renvoie son code à chaque appel)
    // se ferait bloquer au bout de cinq requêtes.
    adminLoginLimiter.reset(ip);
    return true;
  }

  res.status(403).json({ ok: false, error: 'Code admin invalide' });
  return false;
}

// --- App -------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '64kb' }));
// Rappel : le CORS ne protège que les navigateurs — il n'empêche pas un script
// d'appeler le serveur. La vraie protection, ce sont les PINs et le verrou
// anti-brute-force ci-dessus.
app.use(cors({ origin: ALLOWED_ORIGIN }));

app.use((req, res, next) => {
  if (!ipLimiter.allow(clientIp(req))) {
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
    const verdict = await checkPin(doc.id, pin);
    if (verdict === 'locked') {
      console.log(`[verify-pin] ${collection} "${name}" -> BLOQUÉ (trop d'essais)`);
      return res.status(429).json({ ok: false, locked: true, error: 'Trop de PINs faux pour cette équipe. Réessaie dans 15 minutes.' });
    }
    console.log(`[verify-pin] ${collection} "${name}" -> ${verdict === 'ok' ? 'OK' : 'refusé'}`);
    return res.json({ ok: verdict === 'ok' });
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

    const [vA, vB] = await Promise.all([checkPin(tA.id, pinA), checkPin(tB.id, pinB)]);
    if (vA === 'locked' || vB === 'locked') {
      return res.status(429).json({ ok: false, locked: true, error: 'Trop de PINs faux pour cette équipe. Réessaie dans 15 minutes.' });
    }
    if (vA !== 'ok' || vB !== 'ok') return res.status(403).json({ ok: false, error: 'PIN incorrect' });

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

    const [vA, vB] = await Promise.all([checkPin(jA.id, pinA), checkPin(jB.id, pinB)]);
    if (vA === 'locked' || vB === 'locked') {
      return res.status(429).json({ ok: false, locked: true, error: 'Trop de PINs faux pour ce joueur. Réessaie dans 15 minutes.' });
    }
    if (vA !== 'ok' || vB !== 'ok') return res.status(403).json({ ok: false, error: 'PIN incorrect' });

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

// ----- Connexion admin -----------------------------------------------------

// Indique au site s'il doit proposer l'initialisation ou la connexion.
// (Avant, le site lisait config/admin directement — donc l'empreinte du code
//  admin était publique. Elle ne l'est plus.)
app.get('/admin/status', async (req, res) => {
  try {
    return res.json({ ok: true, initialized: await adminExists() });
  } catch (e) {
    console.error('admin/status:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Première utilisation : définit le code admin. Impossible s'il en existe déjà
// un. Si SETUP_TOKEN est défini côté serveur, il est exigé ici.
app.post('/admin/setup', async (req, res) => {
  try {
    const { code, setupToken } = req.body || {};
    if (await adminExists()) return res.status(409).json({ ok: false, error: 'Un code admin est déjà défini.' });
    if (SETUP_TOKEN && !safeEqual(String(setupToken || ''), SETUP_TOKEN)) {
      return res.status(403).json({ ok: false, error: 'Jeton d\'initialisation invalide.' });
    }
    if (typeof code !== 'string' || code.length < 8 || code.length > 200) {
      return res.status(400).json({ ok: false, error: 'Le code doit faire au moins 8 caractères.' });
    }
    await db.collection('secrets').doc('admin').set({
      ...(await buildAdminRecord(code)),
      updatedAt: FieldValue.serverTimestamp(),
    });
    console.log('[admin] code admin initialisé');
    return res.json({ ok: true, token: issueAdminToken() });
  } catch (e) {
    console.error('admin/setup:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Connexion : la vérification se fait ici, plus dans le navigateur.
app.post('/admin/login', async (req, res) => {
  try {
    const ip = clientIp(req);
    if (!adminLoginLimiter.allow(ip)) {
      return res.status(429).json({ ok: false, error: 'Trop de tentatives. Réessaie dans 15 minutes.' });
    }
    const { code } = req.body || {};
    if (!(await adminCodeIsValid(code))) {
      console.log(`[admin] connexion refusée (${ip})`);
      return res.status(403).json({ ok: false, error: 'Code admin invalide' });
    }
    adminLoginLimiter.reset(ip);
    console.log('[admin] connexion réussie');
    return res.json({ ok: true, token: issueAdminToken() });
  } catch (e) {
    console.error('admin/login:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Changement du code admin — impossible auparavant (les règles interdisaient
// de réécrire config/admin depuis le navigateur). Les PINs étant chiffrés avec
// le code admin, le site renvoie ici la liste des pinEnc rechiffrés.
app.post('/admin/change-code', async (req, res) => {
  try {
    const { currentCode, newCode, pins } = req.body || {};
    const ip = clientIp(req);
    if (!adminLoginLimiter.allow(ip)) {
      return res.status(429).json({ ok: false, error: 'Trop de tentatives. Réessaie dans 15 minutes.' });
    }
    if (!(await adminCodeIsValid(currentCode))) {
      return res.status(403).json({ ok: false, error: 'Code admin actuel invalide' });
    }
    if (typeof newCode !== 'string' || newCode.length < 8 || newCode.length > 200) {
      return res.status(400).json({ ok: false, error: 'Le nouveau code doit faire au moins 8 caractères.' });
    }

    const batch = db.batch();
    let reencrypted = 0;
    if (Array.isArray(pins)) {
      for (const p of pins.slice(0, 500)) {
        if (!p || typeof p.id !== 'string' || !isPinEnc(p.pinEnc)) continue;
        batch.set(db.collection('secrets').doc(p.id), { pinEnc: p.pinEnc }, { merge: true });
        reencrypted++;
      }
    }
    batch.set(db.collection('secrets').doc('admin'), {
      ...(await buildAdminRecord(newCode)),
      updatedAt: FieldValue.serverTimestamp(),
    });
    await batch.commit();

    // L'ancienne empreinte publique ne doit plus servir de porte d'entrée.
    const legacy = await db.collection('config').doc('admin').get();
    if (legacy.exists && legacy.data().pinHash !== undefined) {
      await legacy.ref.update({ pinHash: FieldValue.delete() });
    }
    adminTokens.clear();
    console.log(`[admin] code changé (${reencrypted} PINs rechiffrés)`);
    return res.json({ ok: true, token: issueAdminToken(), reencrypted });
  } catch (e) {
    console.error('admin/change-code:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// ----- Endpoints ADMIN (protégés par le code admin ou un jeton) ------------

// Définit / met à jour le hash d'un PIN dans `secrets` (utilisé au seed, à
// l'ajout d'une équipe/joueur, et au changement de PIN). Le navigateur envoie
// le PIN en clair sur HTTPS ; le serveur stocke uniquement son hash, plus la
// version chiffrée (pinEnc) que seul l'admin peut relire.
app.post('/admin/set-pin', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { scope, name, pin, pinEnc } = req.body || {};
    if (!isPin(pin)) return res.status(400).json({ ok: false, error: 'PIN = 4 chiffres' });
    const collection = scope === 'junior' ? 'juniors' : 'teams';
    const doc = await findByName(collection, name);
    if (!doc) return res.status(400).json({ ok: false, error: 'Introuvable' });
    const payload = { hash: sha256(pin) };
    if (isPinEnc(pinEnc)) payload.pinEnc = pinEnc;
    await db.collection('secrets').doc(doc.id).set(payload, { merge: true });
    pinTargetReset(doc.id);
    return res.json({ ok: true });
  } catch (e) {
    console.error('set-pin:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Liste des PINs chiffrés, pour l'affichage admin. Ils ne sont plus posés sur
// les documents publics : il faut être admin pour les obtenir.
app.post('/admin/pins', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const out = { teams: [], juniors: [] };
    for (const coll of ['teams', 'juniors']) {
      const snap = await db.collection(coll).get();
      for (const doc of snap.docs) {
        const secret = await db.collection('secrets').doc(doc.id).get();
        // Repli sur l'ancien emplacement tant que le nettoyage n'a pas tourné.
        const pinEnc = (secret.exists && secret.data().pinEnc) || doc.data().pinEnc || null;
        out[coll].push({ id: doc.id, name: doc.data().name, pinEnc });
      }
    }
    return res.json({ ok: true, ...out });
  } catch (e) {
    console.error('admin/pins:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Ajout d'une équipe : passe par le serveur pour que les règles Firestore
// puissent interdire toute création depuis le navigateur.
app.post('/admin/add-team', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { name, cote, pin, pinEnc } = req.body || {};
    const n = cleanName(name);
    if (!n) return res.status(400).json({ ok: false, error: 'Nom invalide' });
    const c = Number(cote);
    if (!Number.isFinite(c) || c < 1 || c > 30) return res.status(400).json({ ok: false, error: 'Cote invalide (1 à 30)' });
    if (!isPin(pin)) return res.status(400).json({ ok: false, error: 'PIN = 4 chiffres' });
    if (await findByName('teams', n)) return res.status(409).json({ ok: false, error: 'Cette équipe existe déjà' });

    const ref = await db.collection('teams').add({ name: n, cote: c, points: 0 });
    const payload = { hash: sha256(pin) };
    if (isPinEnc(pinEnc)) payload.pinEnc = pinEnc;
    await db.collection('secrets').doc(ref.id).set(payload);
    console.log(`[admin] équipe ajoutée : ${n} (cote ${c})`);
    return res.json({ ok: true, id: ref.id });
  } catch (e) {
    console.error('add-team:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Ajout d'un joueur junior.
app.post('/admin/add-junior', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { name, green, pin, pinEnc } = req.body || {};
    const n = cleanName(name);
    if (!n) return res.status(400).json({ ok: false, error: 'Nom invalide' });
    if (!isPin(pin)) return res.status(400).json({ ok: false, error: 'PIN = 4 chiffres' });
    if (await findByName('juniors', n)) return res.status(409).json({ ok: false, error: 'Ce joueur existe déjà' });

    const ref = await db.collection('juniors').add({ name: n, green: !!green, stars: 0 });
    const payload = { hash: sha256(pin) };
    if (isPinEnc(pinEnc)) payload.pinEnc = pinEnc;
    await db.collection('secrets').doc(ref.id).set(payload);
    console.log(`[admin] junior ajouté : ${n}${green ? ' 🟢' : ''}`);
    return res.json({ ok: true, id: ref.id });
  } catch (e) {
    console.error('add-junior:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Bascule de la catégorie verte d'un junior (avant : modifiable par n'importe
// qui depuis le navigateur, sans authentification).
app.post('/admin/set-green', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { id, green } = req.body || {};
    if (typeof id !== 'string' || !id) return res.status(400).json({ ok: false, error: 'Identifiant manquant' });
    const ref = db.collection('juniors').doc(id);
    if (!(await ref.get()).exists) return res.status(400).json({ ok: false, error: 'Joueur introuvable' });
    await ref.update({ green: !!green });
    return res.json({ ok: true });
  } catch (e) {
    console.error('set-green:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Suppressions — réservées à l'admin (avant : ouvertes à tout visiteur, qui
// pouvait donc vider le tournoi depuis la console du navigateur).
async function deleteDoc(req, res, collection, alsoSecret) {
  if (!(await requireAdmin(req, res))) return;
  const { id } = req.body || {};
  if (typeof id !== 'string' || !id) return res.status(400).json({ ok: false, error: 'Identifiant manquant' });
  const ref = db.collection(collection).doc(id);
  const snap = await ref.get();
  if (!snap.exists) return res.status(400).json({ ok: false, error: 'Introuvable' });
  await ref.delete();
  if (alsoSecret) await db.collection('secrets').doc(id).delete().catch(() => {});
  console.log(`[admin] suppression ${collection}/${id}`);
  return res.json({ ok: true });
}

app.post('/admin/delete-team',    async (req, res) => {
  try { await deleteDoc(req, res, 'teams', true); }
  catch (e) { console.error('delete-team:', e); res.status(500).json({ ok: false, error: 'Erreur serveur' }); }
});
app.post('/admin/delete-junior',  async (req, res) => {
  try { await deleteDoc(req, res, 'juniors', true); }
  catch (e) { console.error('delete-junior:', e); res.status(500).json({ ok: false, error: 'Erreur serveur' }); }
});
app.post('/admin/delete-match',   async (req, res) => {
  try { await deleteDoc(req, res, 'matches', false); }
  catch (e) { console.error('delete-match:', e); res.status(500).json({ ok: false, error: 'Erreur serveur' }); }
});
app.post('/admin/delete-jmatch',  async (req, res) => {
  try { await deleteDoc(req, res, 'juniors_matches', false); }
  catch (e) { console.error('delete-jmatch:', e); res.status(500).json({ ok: false, error: 'Erreur serveur' }); }
});

// Étape 1 de migration : COPIE les pinHash existants (teams/juniors) vers
// `secrets`. Ne supprime rien → l'ancien site continue de marcher pendant la
// bascule (zéro coupure). À lancer avant de mettre le nouveau code en ligne.
// N'écrase jamais un secret déjà en place : sinon, quelqu'un qui aurait écrit
// un pinHash choisi sur un document public pourrait s'imposer un PIN connu.
app.post('/admin/migrate', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    let copied = 0, skipped = 0;
    for (const coll of ['teams', 'juniors']) {
      const snap = await db.collection(coll).get();
      for (const doc of snap.docs) {
        const h = doc.data().pinHash;
        if (!h) continue;
        const existing = await db.collection('secrets').doc(doc.id).get();
        if (existing.exists && existing.data().hash) { skipped++; continue; }
        await db.collection('secrets').doc(doc.id).set({ hash: h }, { merge: true });
        copied++;
      }
    }
    return res.json({ ok: true, copied, skipped });
  } catch (e) {
    console.error('migrate:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Migration des pinEnc : les déplace des documents publics vers `secrets`.
// Idempotent, n'écrase pas un pinEnc déjà présent côté serveur.
app.post('/admin/migrate-pinenc', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    let copied = 0;
    for (const coll of ['teams', 'juniors']) {
      const snap = await db.collection(coll).get();
      for (const doc of snap.docs) {
        const enc = doc.data().pinEnc;
        if (!isPinEnc(enc)) continue;
        const existing = await db.collection('secrets').doc(doc.id).get();
        if (existing.exists && existing.data().pinEnc) continue;
        await db.collection('secrets').doc(doc.id).set({ pinEnc: enc }, { merge: true });
        copied++;
      }
    }
    return res.json({ ok: true, copied });
  } catch (e) {
    console.error('migrate-pinenc:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Étape 2 de migration : SUPPRIME des documents publics les champs sensibles
// (pinHash, pin en clair, pinEnc). À lancer APRÈS la mise en ligne du nouveau
// site, qui ne les lit plus. C'est ce qui retire la matière permettant de
// s'attaquer hors-ligne au code admin.
app.post('/admin/cleanup-hashes', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    let removed = 0;
    for (const coll of ['teams', 'juniors']) {
      const snap = await db.collection(coll).get();
      for (const doc of snap.docs) {
        const d = doc.data();
        const patch = {};
        if (d.pinHash !== undefined) patch.pinHash = FieldValue.delete();
        if (d.pin !== undefined) patch.pin = FieldValue.delete();
        // On ne retire pinEnc que s'il a bien été recopié dans `secrets`.
        if (d.pinEnc !== undefined) {
          const secret = await db.collection('secrets').doc(doc.id).get();
          if (secret.exists && secret.data().pinEnc) patch.pinEnc = FieldValue.delete();
        }
        if (Object.keys(patch).length === 0) continue;
        await doc.ref.update(patch);
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
    if (!(await requireAdmin(req, res))) return;
    const { matchId, scores } = req.body || {};
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
    if (!(await requireAdmin(req, res))) return;
    const { matchId, scores } = req.body || {};
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

// Enregistrement d'un match JUNIOR ÉGALITÉ : l'admin enregistre un match qui s'est
// terminé 3:3 (ou toute autre égalité) et attribue 1 point à chacun. Aucune saisie
// de PIN requise puisque c'est l'admin qui décide.
app.post('/admin/add-jmatch-draw', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { joueurA, joueurB } = req.body || {};
    if (joueurA === joueurB) return res.status(400).json({ ok: false, error: 'Un joueur ne peut pas jouer contre lui-même' });

    const jA = await findByName('juniors', joueurA);
    const jB = await findByName('juniors', joueurB);
    if (!jA || !jB) return res.status(400).json({ ok: false, error: 'Joueur introuvable' });

    const greenBalls = !!(jA.green || jB.green);
    await db.collection('juniors_matches').add({
      joueurA: jA.name, joueurB: jB.name,
      vainqueur: null, scores: { set1: '3-3', set2: '3-3' },
      starsA: 1, starsB: 1, greenBalls,
      date: FieldValue.serverTimestamp(),
    });
    console.log(`[add-jmatch-draw] ${jA.name} vs ${jB.name} | égalité 3-3 | +1⭐/+1⭐`);
    return res.json({ ok: true, starsA: 1, starsB: 1 });
  } catch (e) {
    console.error('add-jmatch-draw:', e);
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
setTimeout(publishTunnelUrl, 4000).unref();
setInterval(publishTunnelUrl, 60_000).unref();

// Démarrage seulement si le fichier est lancé directement (`npm start`), pour
// qu'il puisse aussi être chargé par les tests sans ouvrir de port.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Serveur Défi Double démarré sur le port ${PORT}`);
    console.log(`Origine autorisée : ${ALLOWED_ORIGIN}`);
    console.log(`IP client lue depuis : ${TRUST_CF_HEADER ? 'CF-Connecting-IP (tunnel Cloudflare)' : 'la connexion directe'}`);
  });
}

module.exports = { app, computePoints, deriveWinner, cleanScores, cleanName, isPinEnc };
