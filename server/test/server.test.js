// Tests du serveur, sans Firebase : une fausse base Firestore en mémoire remplace
// le SDK Admin. Lancer : cd server && npm test  (Node 18 ou plus)
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const Module = require('module');

// ---------- Fausse base Firestore (seulement ce que le serveur utilise) ----------
const store = new Map(); // nom de collection -> Map(id -> données)
const failing = new Set(); // documents dont la lecture échoue (« collection/id »), pour simuler une panne
const coll = (name) => { if (!store.has(name)) store.set(name, new Map()); return store.get(name); };
const SERVER_TS = Symbol('serverTimestamp');
const DELETE = Symbol('delete');
const later = () => new Promise((r) => setTimeout(r, 5)); // latence réseau simulée
let autoId = 0;

function resolve(data, old = {}) {
  const out = { ...old };
  for (const [k, v] of Object.entries(data)) {
    if (v === DELETE) delete out[k];
    else out[k] = v === SERVER_TS ? new Date() : v;
  }
  return out;
}
function snap(name, id) {
  const d = coll(name).get(id);
  return { id, exists: d !== undefined, data: () => (d ? { ...d } : undefined), ref: docRef(name, id) };
}
function docRef(name, id) {
  return {
    id,
    async get() { await later(); if (failing.has(name + '/' + id)) throw new Error('Firestore indisponible'); return snap(name, id); },
    async set(data, opts) { await later(); coll(name).set(id, resolve(data, opts && opts.merge ? coll(name).get(id) : {})); },
    async create(data) {
      await later();
      if (coll(name).has(id)) { const e = new Error('ALREADY_EXISTS'); e.code = 6; throw e; }
      coll(name).set(id, resolve(data));
    },
    async update(data) { await later(); coll(name).set(id, resolve(data, coll(name).get(id))); },
    async delete() { await later(); coll(name).delete(id); },
  };
}
function query(name, filters = [], order = null, max = Infinity) {
  return {
    where: (f, op, v) => query(name, [...filters, [f, v]], order, max),
    orderBy: (f, dir) => query(name, filters, [f, dir], max),
    limit: (n) => query(name, filters, order, n),
    async get() {
      await later();
      let ids = [...coll(name).keys()].filter((id) => filters.every(([f, v]) => coll(name).get(id)[f] === v));
      if (order) {
        const [f, dir] = order;
        ids.sort((a, b) => (coll(name).get(a)[f] - coll(name).get(b)[f]) * (dir === 'desc' ? -1 : 1));
      }
      const docs = ids.slice(0, max).map((id) => snap(name, id));
      return { empty: docs.length === 0, docs, size: docs.length };
    },
  };
}
const db = {
  collection: (name) => ({
    ...query(name),
    doc: (id) => docRef(name, id),
    async add(data) { await later(); const id = 'auto' + ++autoId; coll(name).set(id, resolve(data)); return { id }; },
  }),
  batch() {
    const ops = [];
    return { set: (ref, data, opts) => ops.push(() => ref.set(data, opts)), async commit() { for (const op of ops) await op(); } };
  },
};
const fakeAdmin = {
  initializeApp() {},
  credential: { cert: () => ({}) },
  firestore: Object.assign(() => db, { FieldValue: { serverTimestamp: () => SERVER_TS, delete: () => DELETE } }),
};
const origLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === 'firebase-admin') return fakeAdmin;
  if (request.endsWith('serviceAccountKey.json')) return {};
  return origLoad.call(this, request, ...rest);
};

// ---------- Données de test ----------
const PIN = '1234';
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
function addTeam(id, cote = 10) { coll('teams').set(id, { name: id, cote, points: 0 }); coll('secrets').set(id, { hash: sha(PIN) }); }
function addJunior(id) { coll('juniors').set(id, { name: id, green: false, stars: 0 }); coll('secrets').set(id, { hash: sha(PIN) }); }
for (let i = 1; i <= 32; i++) addTeam('T' + i, 5 + i);
for (let i = 1; i <= 4; i++) addJunior('J' + i);

// ---------- Serveur ----------
let base, server, token;
let ipSeq = 0;
const newIp = () => `203.0.113.${++ipSeq}`; // une adresse = un appareil

async function call(path, body, ip) {
  const headers = { 'Content-Type': 'application/json' };
  if (ip) headers['CF-Connecting-IP'] = ip; // passage par le tunnel Cloudflare
  const res = await fetch(base + path, { method: 'POST', headers, body: JSON.stringify(body || {}) });
  let data = {};
  try { data = await res.json(); } catch (e) {}
  return { status: res.status, ...data };
}
const verify = (name, pin, ip, scope = 'team') => call('/verify-pin', { scope, name, pin }, ip);
const matchCount = (c = 'matches') => coll(c).size;

before(async () => {
  const { app } = require('../server.js');
  await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

// ---------- Création du code admin (point 6) ----------
test('création du code admin refusée quand la demande vient du tunnel', async () => {
  const r = await call('/admin/setup', { code: 'un-code-admin-solide' }, newIp());
  assert.strictEqual(r.status, 403);
  assert.ok(!r.token);
});

test('création du code admin acceptée depuis le Pi lui-même', async () => {
  const r = await call('/admin/setup', { code: 'un-code-admin-solide' });
  assert.strictEqual(r.ok, true);
  token = r.token;
});

// ---------- Blocage des PIN (points 1, 2, 3) ----------
test('30 PIN faux envoyés en même temps depuis un appareil : au plus 10 sont réellement testés', async () => {
  const ip = newIp();
  const rs = await Promise.all(Array.from({ length: 30 }, () => verify('T1', '0000', ip)));
  const tested = rs.filter((r) => r.status === 200).length;
  assert.ok(tested <= 10, `${tested} PIN testés au lieu de 10 au maximum`);
  assert.ok(rs.some((r) => r.status === 429 && r.locked), 'les essais en trop doivent être bloqués');
});

test('un appareil bloqué ne bloque pas les autres appareils de la même équipe', async () => {
  const bad = newIp();
  for (let i = 0; i < 12; i++) await verify('T2', '0000', bad);
  const blocked = await verify('T2', PIN, bad);
  assert.strictEqual(blocked.status, 429);
  assert.match(blocked.error, /appareil/);
  const other = await verify('T2', PIN, newIp());
  assert.strictEqual(other.ok, true);
});

test("après 30 PIN faux sur une équipe, même le bon PIN est refusé jusqu'au déblocage", async () => {
  for (let d = 0; d < 3; d++) { const ip = newIp(); for (let i = 0; i < 10; i++) await verify('T3', '0000', ip); }
  const r = await verify('T3', PIN, newIp());
  assert.strictEqual(r.status, 429);
  assert.strictEqual(r.frozen, true);
  assert.match(r.error, /organisateur/);
});

test("un bon PIN remet à zéro le compteur d'échecs de l'équipe", async () => {
  for (let d = 0; d < 3; d++) { const ip = newIp(); for (let i = 0; i < 8; i++) await verify('T4', '0000', ip); } // 24 échecs
  assert.strictEqual((await verify('T4', PIN, newIp())).ok, true);
  for (let d = 0; d < 3; d++) { const ip = newIp(); for (let i = 0; i < 8; i++) await verify('T4', '0000', ip); } // 24 de plus
  assert.strictEqual((await verify('T4', PIN, newIp())).ok, true);
});

test('le blocage par appareil vaut aussi pour la saisie de match', async () => {
  const ip = newIp();
  for (let i = 0; i < 10; i++) await call('/submit-match', { teamA: 'T5', pinA: '0000', teamB: 'T6', pinB: PIN, scores: { set1: '6-1', set2: '6-2' } }, ip);
  const r = await call('/submit-match', { teamA: 'T5', pinA: PIN, teamB: 'T6', pinB: PIN, scores: { set1: '6-1', set2: '6-2' } }, ip);
  assert.strictEqual(r.status, 429);
  assert.match(r.error, /T5/);
});

// ---------- Déblocage par l'admin (point 4) ----------
test("l'admin voit les équipes bloquées et peut les débloquer", async () => {
  for (let d = 0; d < 3; d++) { const ip = newIp(); for (let i = 0; i < 10; i++) await verify('T7', '0000', ip); }
  assert.strictEqual((await verify('T7', PIN, newIp())).frozen, true);

  const locks = await call('/admin/locks', { adminToken: token }, newIp());
  assert.strictEqual(locks.ok, true);
  const t7 = locks.locks.find((l) => l.name === 'T7');
  assert.ok(t7 && t7.frozen, 'T7 doit apparaître comme bloquée');
  assert.strictEqual(t7.scope, 'team');

  const un = await call('/admin/unlock-pin', { adminToken: token, id: t7.id }, newIp());
  assert.strictEqual(un.ok, true);
  assert.strictEqual((await verify('T7', PIN, newIp())).ok, true);
});

test('le déblocage est réservé à l’admin', async () => {
  const r = await call('/admin/unlock-pin', { id: 'T7' }, newIp());
  assert.strictEqual(r.status, 403);
});

// ---------- Contrôle des scores (point 9) ----------
const submit = (teamA, teamB, scores, extra = {}, ip = newIp()) =>
  call('/submit-match', { teamA, pinA: PIN, teamB, pinB: PIN, scores, ...extra }, ip);

test('un score qui ne contient pas que des chiffres est refusé', async () => {
  const before = matchCount();
  const r = await submit('T8', 'T9', { set1: '6 nuls!-0', set2: '6-0' });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(matchCount(), before);
});

test('un 3e set après un match déjà gagné 2-0 est refusé', async () => {
  const before = matchCount();
  const r = await submit('T8', 'T9', { set1: '6-0', set2: '6-0', set3: '0-6' });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(matchCount(), before);
});

test('un match en 3 sets avec super tie-break est accepté', async () => {
  const r = await submit('T10', 'T11', { set1: '6-4', set2: '3-6', set3: '10-8' });
  assert.strictEqual(r.ok, true);
});

// ---------- Anti-doublon (point 10) ----------
test('le même envoi répété (même identifiant) ne crée qu’un seul match', async () => {
  const before = matchCount();
  const body = { scores: { set1: '6-2', set2: '6-3' } };
  const a = await submit('T12', 'T13', body.scores, { submissionId: 'essai-1' });
  const b = await submit('T12', 'T13', body.scores, { submissionId: 'essai-1' });
  assert.strictEqual(a.ok, true);
  assert.strictEqual(b.ok, true);
  assert.strictEqual(b.duplicate, true);
  assert.strictEqual(b.pointsA, a.pointsA);
  assert.strictEqual(matchCount(), before + 1);
});

test('le même match ressaisi par l’autre équipe dans les 10 minutes est refusé', async () => {
  const before = matchCount();
  assert.strictEqual((await submit('T14', 'T15', { set1: '6-2', set2: '7-5' })).ok, true);
  const r = await submit('T15', 'T14', { set1: '2-6', set2: '5-7' }); // vu depuis l'autre équipe
  assert.strictEqual(r.status, 409);
  assert.match(r.error, /déjà/);
  assert.strictEqual(matchCount(), before + 1);
});

test('deux envois identiques au même instant ne créent qu’un seul match', async () => {
  const before = matchCount();
  const rs = await Promise.all([submit('T16', 'T17', { set1: '6-1', set2: '6-1' }), submit('T16', 'T17', { set1: '6-1', set2: '6-1' })]);
  assert.strictEqual(rs.filter((r) => r.ok).length, 1);
  assert.strictEqual(matchCount(), before + 1);
});

test('un autre score entre les mêmes équipes reste possible', async () => {
  assert.strictEqual((await submit('T18', 'T19', { set1: '6-1', set2: '6-1' })).ok, true);
  assert.strictEqual((await submit('T18', 'T19', { set1: '4-6', set2: '6-3', set3: '10-7' })).ok, true);
});

test('juniors : anti-doublon et contrôle des scores', async () => {
  const sj = (scores, extra = {}) => call('/submit-jmatch', { joueurA: 'J1', pinA: PIN, joueurB: 'J2', pinB: PIN, scores, ...extra }, newIp());
  const before = matchCount('juniors_matches');
  assert.strictEqual((await sj({ set1: '4-1', set2: '1x-4' })).status, 400);
  assert.strictEqual((await sj({ set1: '4-1', set2: '4-2' })).ok, true);
  assert.strictEqual((await sj({ set1: '4-1', set2: '4-2' })).status, 409);
  assert.strictEqual(matchCount('juniors_matches'), before + 1);
});

// ---------- Écoute limitée au Pi lui-même (point 7) ----------
test("le serveur n'écoute que sur le Pi lui-même, en IPv4 et en IPv6", async () => {
  const net = require('net');
  const os = require('os');
  const { startServer } = require('../server.js');
  const port = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
  const servers = await startServer(port);
  try {
    const health = async (host) => (await fetch(`http://${host}:${port}/health`)).status;
    assert.strictEqual(await health('127.0.0.1'), 200);
    const hasIPv6Loopback = Object.values(os.networkInterfaces()).flat().some((i) => i && i.address === '::1');
    if (hasIPv6Loopback) assert.strictEqual(await health('[::1]'), 200);
    const lan = Object.values(os.networkInterfaces()).flat().find((i) => i && i.family === 'IPv4' && !i.internal);
    if (lan) {
      const refused = await new Promise((r) => { const c = net.connect(port, lan.address); c.once('connect', () => { c.destroy(); r(false); }); c.once('error', () => r(true)); });
      assert.ok(refused, `le serveur ne doit pas répondre sur ${lan.address}`);
    }
  } finally {
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  }
});

// ---------- Fin des chemins de compatibilité (point 8) ----------
test("les actions admin exigent le jeton de connexion : le code admin seul ne suffit plus", async () => {
  const r = await call('/admin/locks', { adminCode: 'un-code-admin-solide' }, newIp());
  assert.strictEqual(r.status, 403);
  const ok = await call('/admin/locks', { adminToken: token }, newIp());
  assert.strictEqual(ok.ok, true);
});

test("l'ancien format du code admin (config/admin) n'est plus accepté", async () => {
  const saved = coll('secrets').get('admin');
  coll('secrets').delete('admin');
  coll('config').set('admin', { pinHash: sha('ancien-code-admin') });
  try {
    const r = await call('/admin/login', { code: 'ancien-code-admin' }, newIp());
    assert.strictEqual(r.status, 403);
    assert.strictEqual(coll('secrets').has('admin'), false, "l'ancien code ne doit pas être converti");
  } finally {
    coll('config').delete('admin');
    coll('secrets').set('admin', saved);
  }
});

test('la liste des PIN chiffrés ne relit plus les fiches publiques des équipes', async () => {
  coll('teams').set('T20', { ...coll('teams').get('T20'), pinEnc: 'ab'.repeat(20) }); // reste d'avant la migration
  const r = await call('/admin/pins', { adminToken: token }, newIp());
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.teams.find((t) => t.id === 'T20').pinEnc, null);
});


// ---------- Corrections après relecture et tests de bout en bout ----------
// Horloge simulée du serveur (Date.now), rétablie après chaque usage.
async function withClock(start, fn) {
  const real = Date.now;
  let now = start;
  Date.now = () => now;
  try { return await fn({ advance: (ms) => { now += ms; } }); } finally { Date.now = real; }
}

test("le blocage d'un appareil dure 15 minutes à partir du 10e PIN faux", async () => {
  const ip = newIp();
  await withClock(Date.now(), async (clock) => {
    await verify('T21', '0000', ip);
    clock.advance(14 * 60_000 + 55_000);
    for (let i = 0; i < 9; i++) await verify('T21', '0000', ip); // 10e échec
    clock.advance(6_000);
    const r = await verify('T21', PIN, ip);
    assert.strictEqual(r.status, 429, "l'appareil doit rester bloqué juste après son 10e échec");
    assert.match(r.error, /15 min/);
    clock.advance(15 * 60_000);
    assert.strictEqual((await verify('T21', PIN, ip)).ok, true);
  });
});

test('un zéro en tête est normalisé : « 06-4 » est enregistré « 6-4 » et reconnu comme doublon', async () => {
  const a = await submit('T22', 'T23', { set1: '06-4', set2: '6-3' });
  assert.strictEqual(a.ok, true);
  const saved = [...coll('matches').values()].find((m) => m.equipeA === 'T22' && m.equipeB === 'T23');
  assert.strictEqual(saved.scores.set1, '6-4');
  assert.strictEqual((await submit('T22', 'T23', { set1: '6-4', set2: '6-3' })).status, 409);
});

test("un identifiant d'envoi réutilisé pour un autre score crée bien le nouveau match", async () => {
  const before = matchCount();
  assert.strictEqual((await submit('T24', 'T25', { set1: '6-1', set2: '6-1' }, { submissionId: 'reutilise-1' })).ok, true);
  const b = await submit('T24', 'T25', { set1: '6-2', set2: '6-2' }, { submissionId: 'reutilise-1' });
  assert.strictEqual(b.ok, true);
  assert.notStrictEqual(b.duplicate, true);
  assert.strictEqual(matchCount(), before + 2);
});

test("un identifiant d'envoi déjà connu n'exempte pas de la vérification des PIN", async () => {
  assert.strictEqual((await submit('T26', 'T27', { set1: '6-1', set2: '6-1' }, { submissionId: 'avec-pin-1' })).ok, true);
  const r = await call('/submit-match', { teamA: 'T26', pinA: '0000', teamB: 'T27', pinB: PIN, scores: { set1: '6-1', set2: '6-1' }, submissionId: 'avec-pin-1' }, newIp());
  assert.strictEqual(r.status, 403);
});

test('une panne de Firestore ne compte pas comme un PIN faux', async () => {
  const ip = newIp();
  failing.add('secrets/T28');
  try {
    for (let i = 0; i < 12; i++) assert.strictEqual((await verify('T28', PIN, ip)).status, 500);
  } finally { failing.delete('secrets/T28'); }
  assert.strictEqual((await verify('T28', PIN, ip)).ok, true);
});

test("un match en cours d'enregistrement sur un autre appareil donne un message distinct", async () => {
  const rs = await Promise.all([submit('T29', 'T30', { set1: '6-3', set2: '6-3' }), submit('T29', 'T30', { set1: '6-3', set2: '6-3' })]);
  const refused = rs.find((r) => !r.ok);
  assert.ok(refused, 'un des deux envois doit être refusé');
  assert.match(refused.error, /en cours/);
});

test("un Pi en retard sur l'heure ne prend pas un match ancien pour un doublon", async () => {
  coll('matches').set('ancien-1', { equipeA: 'T31', equipeB: 'T32', vainqueur: 'A', scores: { set1: '6-0', set2: '6-0' }, pointsA: 1, pointsB: 1, date: new Date() });
  await withClock(Date.now() - 20 * 60_000, async () => {
    assert.strictEqual((await submit('T31', 'T32', { set1: '6-0', set2: '6-0' })).ok, true);
  });
});

test("100 PIN faux sur 30 jours bloquent l'équipe même avec des bons PIN entre-temps", async () => {
  for (let round = 0; round < 4; round++) {
    for (const n of [10, 10, 5]) { const ip = newIp(); for (let i = 0; i < n; i++) await verify('T20', '0000', ip); }
    if (round < 3) assert.strictEqual((await verify('T20', PIN, newIp())).ok, true);
  }
  const r = await verify('T20', PIN, newIp());
  assert.strictEqual(r.status, 429);
  assert.strictEqual(r.frozen, true);
});

test("le démarrage échoue si le port est déjà pris, au lieu de tourner à moitié", async () => {
  const net = require('net');
  const { startServer } = require('../server.js');
  const blocker = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => r(s)); });
  const port = blocker.address().port;
  try {
    let servers = null, failed = false;
    try { servers = await startServer(port, ['127.0.0.1', '127.0.0.2']); } catch (e) { failed = true; }
    if (servers) await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
    assert.ok(failed, 'startServer doit échouer quand 127.0.0.1 est déjà utilisé');
  } finally { blocker.close(); }
});

test("le script de création du code admin (npm run admin-setup) fonctionne depuis le Pi", async () => {
  const { spawn } = require('child_process');
  const path = require('path');
  const saved = coll('secrets').get('admin');
  coll('secrets').delete('admin');
  try {
    const port = new URL(base).port;
    const out = await new Promise((resolve) => {
      const child = spawn(process.execPath, [path.join(__dirname, '..', 'scripts', 'admin-setup.js')], { env: { ...process.env, PORT: port } });
      let text = '';
      child.stdout.on('data', (d) => { text += d; });
      child.stderr.on('data', (d) => { text += d; });
      child.on('close', (code) => resolve({ code, text }));
      child.stdin.end('un "code" avec des guillemets\nun "code" avec des guillemets\n');
    });
    assert.strictEqual(out.code, 0, out.text);
    assert.ok(coll('secrets').has('admin'));
    const login = await call('/admin/login', { code: 'un "code" avec des guillemets' }, newIp());
    assert.strictEqual(login.ok, true);
  } finally {
    coll('secrets').set('admin', saved);
  }
});
