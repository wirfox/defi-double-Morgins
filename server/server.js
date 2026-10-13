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
// Renvoie null si incohérent (set à égalité, 1 set partout, scores incomplets,
// 3ᵉ set alors que le match était déjà gagné 2-0) → le serveur refuse alors le
// match. C'est la garantie « pas de score à l'envers » : le vainqueur n'est
// jamais cru sur parole, il est recalculé à partir des sets.
function deriveWinner(scores) {
  const setWinners = [];
  for (const k of ['set1', 'set2', 'set3']) {
    const v = scores[k];
    if (v === undefined || v === '') continue;
    const parts = String(v).split('-');
    if (parts.length !== 2) return null;
    const a = parseInt(parts[0], 10), b = parseInt(parts[1], 10);
    if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || b < 0 || a === b) return null;
    setWinners.push(a > b ? 'A' : 'B');
  }
  if (setWinners.length < 2) return null;
  // Un faux 3ᵉ set après un 2-0 donnerait le bonus « 3 sets » au perdant.
  if (setWinners.length === 3 && setWinners[0] === setWinners[1]) return null;
  const setsA = setWinners.filter((w) => w === 'A').length;
  const setsB = setWinners.length - setsA;
  if (setsA === setsB) return null;
  return setsA > setsB ? 'A' : 'B';
}
const SCORE_ERROR = 'Scores incohérents : set à égalité, 3ᵉ set manquant, ou 3ᵉ set alors que le match était déjà gagné 2-0.';

// Un score de set = des jeux de 0 à 99 de chaque côté (« 6-4 », super tie-break « 10-8 »).
function isValidScore(s) {
  return typeof s === 'string' && /^\d{1,2}-\d{1,2}$/.test(s);
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

// Scores d'un match ÉGALITÉ (junior) : au moins un set, chaque score au format
// "a-b" valide, et le résultat global doit être une VRAIE égalité (autant de
// sets gagnés de chaque côté — un set 3-3 compte pour personne). Renvoie l'objet
// scores nettoyé, ou null si ce n'est pas une égalité cohérente.
function cleanDrawScores(scores) {
  if (!scores || typeof scores !== 'object') return null;
  const out = {};
  let setsA = 0, setsB = 0, entered = 0;
  for (const k of ['set1', 'set2', 'set3']) {
    const v = scores[k];
    if (v === undefined || v === '') continue;
    if (!isValidScore(v)) return null;
    const parts = String(v).split('-');
    if (parts.length !== 2) return null;
    const a = parseInt(parts[0], 10), b = parseInt(parts[1], 10);
    if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || b < 0) return null;
    if (a > b) setsA++; else if (b > a) setsB++;
    out[k] = v;
    entered++;
  }
  if (entered < 1) return null;      // au moins un set saisi
  if (setsA !== setsB) return null;  // sinon il y a un vainqueur → pas une égalité
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

// Verrous des PINs, à deux niveaux :
//  - par appareil : PIN_DEVICE_MAX_FAILS PINs faux depuis une même adresse pour
//    une même équipe / un même joueur bloquent CET appareil pendant PIN_LOCK_MS.
//    Celui qui se trompe se bloque lui-même, sans gêner les vrais joueurs ;
//  - par équipe / joueur : PIN_TARGET_MAX_FAILS PINs faux d'affilée, tous
//    appareils confondus, bloquent la cible jusqu'au déblocage par l'admin
//    (ou au redémarrage du serveur). Un bon PIN remet ce compteur à zéro.
// Un attaquant n'a donc qu'une trentaine d'essais sur les 10 000 PINs possibles.
const PIN_DEVICE_MAX_FAILS = 10;
const PIN_LOCK_MS = 15 * 60_000;
const PIN_TARGET_MAX_FAILS = 30;
const PIN_TARGET_FORGET_MS = 24 * 3600_000; // échecs oubliés après 24 h sans nouvel échec
const deviceFails = new Map(); // `${docId}|${ip}` -> { count, ts }
const targetFails = new Map(); // docId -> { count, ts }

const isFrozen = (rec) => !!rec && rec.count >= PIN_TARGET_MAX_FAILS;

function deviceRecord(key, now) {
  const rec = deviceFails.get(key);
  if (rec && now - rec.ts > PIN_LOCK_MS) { deviceFails.delete(key); return null; }
  return rec || null;
}

// Minutes restantes avant qu'un appareil bloqué puisse réessayer.
function deviceRetryMinutes(docId, ip) {
  const rec = deviceFails.get(docId + '|' + ip);
  if (!rec) return 1;
  return Math.max(1, Math.ceil((rec.ts + PIN_LOCK_MS - Date.now()) / 60_000));
}

function pinLocksReset(docId) {
  targetFails.delete(docId);
  for (const k of deviceFails.keys()) if (k.startsWith(docId + '|')) deviceFails.delete(k);
}

// État des verrous d'une cible, pour l'écran admin.
function lockInfo(docId) {
  const now = Date.now();
  const t = targetFails.get(docId);
  let devicesLocked = 0;
  for (const [k, rec] of deviceFails) {
    if (k.startsWith(docId + '|') && now - rec.ts <= PIN_LOCK_MS && rec.count >= PIN_DEVICE_MAX_FAILS) devicesLocked++;
  }
  return { frozen: isFrozen(t), fails: t ? t.count : 0, devicesLocked };
}

// Vérifie un PIN en tenant compte des deux verrous.
// Renvoie 'ok' | 'bad' | 'locked' (cet appareil) | 'frozen' (toute la cible).
async function checkPin(docId, pin, ip) {
  const now = Date.now();
  let target = targetFails.get(docId);
  if (target && !isFrozen(target) && now - target.ts > PIN_TARGET_FORGET_MS) { targetFails.delete(docId); target = null; }
  if (isFrozen(target)) return 'frozen';
  const key = docId + '|' + ip;
  let device = deviceRecord(key, now);
  if (device && device.count >= PIN_DEVICE_MAX_FAILS) return 'locked';

  // L'essai est compté AVANT d'interroger Firestore : sinon des essais envoyés
  // en même temps passeraient tous le contrôle ci-dessus avant que le premier
  // échec soit noté. Un bon PIN efface ensuite ces compteurs.
  if (!device) { device = { count: 0, ts: now }; deviceFails.set(key, device); }
  device.count += 1;
  if (!target) { target = { count: 0, ts: now }; targetFails.set(docId, target); }
  target.count += 1;
  target.ts = now;

  if (await pinIsValid(docId, pin)) {
    deviceFails.delete(key);
    targetFails.delete(docId);
    return 'ok';
  }
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
  for (const [k, rec] of deviceFails) if (now - rec.ts > PIN_LOCK_MS) deviceFails.delete(k);
  for (const [k, rec] of targetFails) if (!isFrozen(rec) && now - rec.ts > PIN_TARGET_FORGET_MS) targetFails.delete(k);
  for (const [t, exp] of adminTokens) if (now > exp) adminTokens.delete(t);
  for (const [k, v] of submissions) if (now - v.at > DUP_WINDOW_MS) submissions.delete(k);
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

// Une adresse IPv6 change facilement (un abonné en reçoit des milliards) : on
// regroupe donc par bloc /64, qui correspond à une box ou à un téléphone.
function ipBucket(ip) {
  if (typeof ip !== 'string' || !ip) return 'unknown';
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return mapped[1];
  if (!ip.includes(':')) return ip;
  const [head, tail = ''] = ip.split('%')[0].split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  return groups.slice(0, 4).map((g) => (g.toLowerCase().replace(/^0+(?=.)/, ''))).join(':') + '::/64';
}

function clientIp(req) {
  if (TRUST_CF_HEADER) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return ipBucket(cf.trim());
  }
  return ipBucket(req.socket.remoteAddress || 'unknown');
}

// Vrai seulement pour une commande lancée sur le Pi lui-même (curl localhost) :
// tout ce qui vient d'Internet passe par le tunnel, qui ajoute toujours
// l'en-tête CF-Connecting-IP, et un appareil du réseau local n'a pas une
// adresse 127.0.0.1.
function fromPiItself(req) {
  if (req.headers['cf-connecting-ip'] !== undefined) return false;
  const a = req.socket.remoteAddress || '';
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
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

// Réponse quand un PIN est bloqué, ou null s'il ne l'est pas.
// `who` : « cette équipe », « ce joueur » ou le nom entre guillemets.
function pinLockError(verdict, docId, ip, who) {
  if (verdict === 'frozen') {
    return { ok: false, locked: true, frozen: true,
      error: `Trop de PIN faux pour ${who} : la saisie est bloquée. Demande à l'organisateur de la débloquer.` };
  }
  if (verdict === 'locked') {
    return { ok: false, locked: true,
      error: `Trop de PIN faux pour ${who} depuis cet appareil. Réessaie dans ${deviceRetryMinutes(docId, ip)} min, ou demande à l'organisateur.` };
  }
  return null;
}

// --- Anti-doublon ----------------------------------------------------------
// Un même match ne doit être enregistré qu'une fois : double appui, renvoi
// après une coupure réseau, ou les deux équipes qui le saisissent chacune.
const DUP_WINDOW_MS = 10 * 60_000;
const submissions = new Map(); // identifiant d'envoi -> { at, response }
const inFlight = new Set();     // matchs en cours d'écriture
const isSubmissionId = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{6,64}$/.test(v);
const DUP_ERROR = "Ce match est déjà enregistré (mêmes adversaires, même score, il y a moins de 10 minutes). S'il s'agit d'un autre match, demande à l'organisateur.";

// Empreinte d'un match qui ne dépend pas de l'ordre des adversaires.
function matchKey(nameA, nameB, sc) {
  const sets = ['set1', 'set2', 'set3'].filter((k) => sc[k]).map((k) => String(sc[k]));
  if (nameA <= nameB) return JSON.stringify([nameA, nameB, sets]);
  return JSON.stringify([nameB, nameA, sets.map((v) => v.split('-').reverse().join('-'))]);
}
const toMillis = (d) => (!d ? 0 : typeof d.toMillis === 'function' ? d.toMillis() : new Date(d).getTime());

// Le même match a-t-il été enregistré il y a moins de DUP_WINDOW_MS ?
async function recentDuplicate(collection, fieldA, fieldB, key) {
  const snap = await db.collection(collection).orderBy('date', 'desc').limit(20).get();
  const now = Date.now();
  return snap.docs.some((d) => {
    const m = d.data();
    return now - toMillis(m.date) < DUP_WINDOW_MS && m.scores && matchKey(m[fieldA], m[fieldB], m.scores) === key;
  });
}

// Écrit un match une seule fois. `write` fait l'écriture et renvoie la réponse.
async function writeOnce(res, { kind, collection, fieldA, fieldB, nameA, nameB, scores, sid }, write) {
  const key = matchKey(nameA, nameB, scores);
  const flightKey = kind + ':' + key;
  if (inFlight.has(flightKey)) return res.status(409).json({ ok: false, duplicate: true, error: DUP_ERROR });
  inFlight.add(flightKey);
  try {
    if (await recentDuplicate(collection, fieldA, fieldB, key)) {
      console.log(`[${kind}] doublon refusé : ${nameA} vs ${nameB}`);
      return res.status(409).json({ ok: false, duplicate: true, error: DUP_ERROR });
    }
    const response = await write();
    if (sid) submissions.set(sid, { at: Date.now(), response });
    return res.json(response);
  } finally {
    inFlight.delete(flightKey);
  }
}

// Vérification d'un PIN (utilisée par les étapes de saisie, pour le retour à l'écran)
app.post('/verify-pin', async (req, res) => {
  try {
    const { scope, name, pin } = req.body || {};
    const collection = scope === 'junior' ? 'juniors' : 'teams';
    const doc = await findByName(collection, name);
    if (!doc) return res.json({ ok: false });
    const ip = clientIp(req);
    const verdict = await checkPin(doc.id, pin, ip);
    const lock = pinLockError(verdict, doc.id, ip, scope === 'junior' ? 'ce joueur' : 'cette équipe');
    if (lock) {
      console.log(`[verify-pin] ${collection} "${name}" -> BLOQUÉ (${verdict === 'frozen' ? "jusqu'au déblocage par l'admin" : 'cet appareil'})`);
      return res.status(429).json(lock);
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
    const { teamA, pinA, teamB, pinB, scores, submissionId } = req.body || {};
    // Renvoi d'une saisie déjà enregistrée (réponse perdue, double appui) : même réponse, rien de réécrit.
    const sid = isSubmissionId(submissionId) ? 'm:' + submissionId : null;
    if (sid && submissions.has(sid)) return res.json({ ...submissions.get(sid).response, duplicate: true });

    if (teamA === teamB) return res.status(400).json({ ok: false, error: 'Une équipe ne peut pas jouer contre elle-même' });
    const sc = cleanScores(scores);
    if (!sc) return res.status(400).json({ ok: false, error: 'Scores invalides' });
    const winner = deriveWinner(sc);
    if (!winner) return res.status(400).json({ ok: false, error: SCORE_ERROR });

    const tA = await findByName('teams', teamA);
    const tB = await findByName('teams', teamB);
    if (!tA || !tB) return res.status(400).json({ ok: false, error: 'Équipe introuvable' });

    const ip = clientIp(req);
    const [vA, vB] = await Promise.all([checkPin(tA.id, pinA, ip), checkPin(tB.id, pinB, ip)]);
    const lock = pinLockError(vA, tA.id, ip, `« ${tA.name} »`) || pinLockError(vB, tB.id, ip, `« ${tB.name} »`);
    if (lock) return res.status(429).json(lock);
    if (vA !== 'ok' || vB !== 'ok') return res.status(403).json({ ok: false, error: 'PIN incorrect' });

    return await writeOnce(res,
      { kind: 'submit-match', collection: 'matches', fieldA: 'equipeA', fieldB: 'equipeB', nameA: tA.name, nameB: tB.name, scores: sc, sid },
      async () => {
        const threeSet = !!sc.set3;
        const { deltaA, deltaB } = computePoints(Number(tA.cote), Number(tB.cote), winner, threeSet);
        await db.collection('matches').add({
          equipeA: tA.name, equipeB: tB.name,
          vainqueur: winner, scores: sc,
          pointsA: deltaA, pointsB: deltaB,
          date: FieldValue.serverTimestamp(),
        });
        console.log(`[submit-match] ${tA.name} vs ${tB.name} | vainqueur ${winner} | +${deltaA}/+${deltaB}`);
        return { ok: true, pointsA: deltaA, pointsB: deltaB };
      });
  } catch (e) {
    console.error('submit-match:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Saisie d'un match JUNIOR : vérifie les 2 PINs, calcule les étoiles, écrit le match.
app.post('/submit-jmatch', async (req, res) => {
  try {
    const { joueurA, pinA, joueurB, pinB, scores, submissionId } = req.body || {};
    const sid = isSubmissionId(submissionId) ? 'j:' + submissionId : null;
    if (sid && submissions.has(sid)) return res.json({ ...submissions.get(sid).response, duplicate: true });

    if (joueurA === joueurB) return res.status(400).json({ ok: false, error: 'Un joueur ne peut pas jouer contre lui-même' });
    const sc = cleanScores(scores);
    if (!sc) return res.status(400).json({ ok: false, error: 'Scores invalides' });
    const winner = deriveWinner(sc);
    if (!winner) return res.status(400).json({ ok: false, error: SCORE_ERROR });

    const jA = await findByName('juniors', joueurA);
    const jB = await findByName('juniors', joueurB);
    if (!jA || !jB) return res.status(400).json({ ok: false, error: 'Joueur introuvable' });

    const ip = clientIp(req);
    const [vA, vB] = await Promise.all([checkPin(jA.id, pinA, ip), checkPin(jB.id, pinB, ip)]);
    const lock = pinLockError(vA, jA.id, ip, `« ${jA.name} »`) || pinLockError(vB, jB.id, ip, `« ${jB.name} »`);
    if (lock) return res.status(429).json(lock);
    if (vA !== 'ok' || vB !== 'ok') return res.status(403).json({ ok: false, error: 'PIN incorrect' });

    return await writeOnce(res,
      { kind: 'submit-jmatch', collection: 'juniors_matches', fieldA: 'joueurA', fieldB: 'joueurB', nameA: jA.name, nameB: jB.name, scores: sc, sid },
      async () => {
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
        return { ok: true, starsA, starsB, greenBalls };
      });
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
// un, et seulement depuis le Pi lui-même (voir README, « code admin perdu ») :
// sinon, pendant la procédure, n'importe qui pourrait créer le code avant toi.
// Si SETUP_TOKEN est défini côté serveur, il est exigé en plus.
app.post('/admin/setup', async (req, res) => {
  try {
    if (!fromPiItself(req)) {
      console.log(`[admin] création du code admin refusée : demande venue d'Internet (${clientIp(req)})`);
      return res.status(403).json({ ok: false, error: 'Par sécurité, le code admin se crée depuis le Raspberry Pi lui-même (voir server/README.md).' });
    }
    const { code, setupToken } = req.body || {};
    if (await adminExists()) return res.status(409).json({ ok: false, error: 'Un code admin est déjà défini.' });
    if (SETUP_TOKEN && !safeEqual(String(setupToken || ''), SETUP_TOKEN)) {
      return res.status(403).json({ ok: false, error: 'Jeton d\'initialisation invalide.' });
    }
    if (typeof code !== 'string' || code.length < 8 || code.length > 200) {
      return res.status(400).json({ ok: false, error: 'Le code doit faire au moins 8 caractères.' });
    }
    try {
      // create() échoue si le document existe déjà : deux créations simultanées ne peuvent pas réussir toutes les deux.
      await db.collection('secrets').doc('admin').create({
        ...(await buildAdminRecord(code)),
        updatedAt: FieldValue.serverTimestamp(),
      });
    } catch (e) {
      if (e && e.code === 6) return res.status(409).json({ ok: false, error: 'Un code admin est déjà défini.' });
      throw e;
    }
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
    pinLocksReset(doc.id);
    return res.json({ ok: true });
  } catch (e) {
    console.error('set-pin:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Équipes et joueurs dont la saisie de PIN est bloquée (écran admin).
app.post('/admin/locks', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const ids = new Set([...targetFails.keys(), ...[...deviceFails.keys()].map((k) => k.split('|')[0])]);
    const locks = [];
    for (const id of ids) {
      const info = lockInfo(id);
      if (!info.frozen && info.devicesLocked === 0) continue;
      let scope = 'team';
      let doc = await db.collection('teams').doc(id).get();
      if (!doc.exists) { scope = 'junior'; doc = await db.collection('juniors').doc(id).get(); }
      if (!doc.exists) continue;
      locks.push({ id, scope, name: doc.data().name, ...info });
    }
    locks.sort((a, b) => Number(b.frozen) - Number(a.frozen) || a.name.localeCompare(b.name, 'fr'));
    return res.json({ ok: true, locks });
  } catch (e) {
    console.error('admin/locks:', e);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Débloque la saisie de PIN d'une équipe ou d'un joueur (tous appareils).
app.post('/admin/unlock-pin', async (req, res) => {
  try {
    if (!(await requireAdmin(req, res))) return;
    const { id } = req.body || {};
    if (typeof id !== 'string' || !id) return res.status(400).json({ ok: false, error: 'Identifiant manquant' });
    pinLocksReset(id);
    console.log(`[admin] saisie de PIN débloquée pour ${id}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error('admin/unlock-pin:', e);
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
    if (!winner) return res.status(400).json({ ok: false, error: SCORE_ERROR });
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
    if (!winner) return res.status(400).json({ ok: false, error: SCORE_ERROR });
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
    const { joueurA, joueurB, scores } = req.body || {};
    if (joueurA === joueurB) return res.status(400).json({ ok: false, error: 'Un joueur ne peut pas jouer contre lui-même' });

    const sc = cleanDrawScores(scores);
    if (!sc) return res.status(400).json({ ok: false, error: 'Score invalide : ce n\'est pas une égalité (ex. 3-3 sur un set).' });

    const jA = await findByName('juniors', joueurA);
    const jB = await findByName('juniors', joueurB);
    if (!jA || !jB) return res.status(400).json({ ok: false, error: 'Joueur introuvable' });

    const greenBalls = !!(jA.green || jB.green);
    await db.collection('juniors_matches').add({
      joueurA: jA.name, joueurB: jB.name,
      vainqueur: null, scores: sc,
      starsA: 1, starsB: 1, greenBalls,
      date: FieldValue.serverTimestamp(),
    });
    const setsTxt = Object.values(sc).join(' / ');
    console.log(`[add-jmatch-draw] ${jA.name} vs ${jB.name} | égalité ${setsTxt} | +1⭐/+1⭐`);
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

// Le serveur n'écoute que le Pi lui-même : le tunnel Cloudflare tourne sur le Pi
// et s'y connecte par localhost, en IPv4 (127.0.0.1) ou en IPv6 (::1) selon le
// système — on écoute donc les deux. Les autres appareils du réseau local ne
// peuvent plus lui parler directement : sinon ils pourraient se faire passer
// pour plusieurs appareils avec un faux en-tête CF-Connecting-IP.
// LISTEN_HOST=0.0.0.0 rétablit l'écoute sur tout le réseau si besoin.
const LISTEN_HOSTS = process.env.LISTEN_HOST ? [process.env.LISTEN_HOST] : ['127.0.0.1', '::1'];

function startServer(port = PORT, hosts = LISTEN_HOSTS) {
  return Promise.all(hosts.map((host) => new Promise((resolve) => {
    const srv = http.createServer(app);
    // Pas d'IPv6 sur le Pi, port déjà pris… : on le signale sans tout arrêter.
    srv.once('error', (e) => { console.error(`Écoute impossible sur ${host}:${port} (${e.code})`); resolve(null); });
    srv.listen(port, host, () => resolve(srv));
  }))).then((list) => {
    const servers = list.filter(Boolean);
    if (servers.length === 0) throw new Error(`Impossible d'écouter sur le port ${port}`);
    return servers;
  });
}

// Démarrage seulement si le fichier est lancé directement (`npm start`), pour
// qu'il puisse aussi être chargé par les tests sans ouvrir de port.
if (require.main === module) {
  startServer().then((servers) => {
    console.log(`Serveur Défi Double démarré sur le port ${PORT} (écoute : ${servers.map((s) => s.address().address).join(', ')})`);
    console.log(`Origine autorisée : ${ALLOWED_ORIGIN}`);
    console.log(`IP client lue depuis : ${TRUST_CF_HEADER ? 'CF-Connecting-IP (tunnel Cloudflare)' : 'la connexion directe'}`);
  }).catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = { app, startServer, computePoints, deriveWinner, cleanScores, cleanDrawScores, cleanName, isPinEnc };
