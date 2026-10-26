// Tests du poivre des PIN : démarrage du serveur, et script de conversion des
// anciennes empreintes (lancé pour de vrai, sur une fausse base).
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { pinHmac } = require('../pin-pepper');
const { planMigration } = require('../scripts/pin-pepper-migrate');

const PEPPER_HEX = 'cd'.repeat(32);
const PEPPER = Buffer.from(PEPPER_HEX, 'hex');
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

let tmp, home;
before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dd-pepper-test-'));
  home = path.join(tmp, 'home');
  fs.mkdirSync(home);
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

function startServer(env) {
  const e = { ...process.env, ...env };
  delete e.PIN_PEPPER;
  if (env.PIN_PEPPER) e.PIN_PEPPER = env.PIN_PEPPER;
  return spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js')], { env: e, encoding: 'utf8', timeout: 10000 });
}

test('le serveur refuse de démarrer sans poivre, et explique comment le créer', () => {
  const r = startServer({ PIN_PEPPER_FILE: path.join(tmp, 'absent.key') });
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /openssl rand -hex 32/);
  assert.match(r.stderr, /Proton Pass/);
});

test('le serveur refuse un poivre mal formé', () => {
  const file = path.join(tmp, 'court.key');
  fs.writeFileSync(file, 'abc123\n');
  const r = startServer({ PIN_PEPPER_FILE: file });
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /64 caractères hexadécimaux/);
});

test('la conversion retrouve chaque PIN et prépare la nouvelle empreinte, sans toucher au code admin', () => {
  const docs = [
    { id: 'T1', data: { hash: sha('0420'), pinEnc: 'e1' } },
    { id: 'T2', data: { hmac: pinHmac(PEPPER, '1111') } },
    { id: 'T3', data: { hash: 'pas-une-empreinte' } },
    { id: 'T4', data: { hash: sha('2222'), hmac: pinHmac(PEPPER, '3333') } },
    { id: 'admin', data: { hash: 'empreinte-pbkdf2-du-code-admin', salt: 'x' } },
  ];
  const plan = planMigration(docs, PEPPER);
  assert.deepStrictEqual(plan.writes, [{ id: 'T1', data: { pinEnc: 'e1', hmac: pinHmac(PEPPER, '0420') } }]);
  assert.strictEqual(plan.done, 1);
  assert.deepStrictEqual(plan.unknown, ['T3']);
  assert.deepStrictEqual(plan.conflicts, ['T4']);
});

let runId = 0;
function runMigrate(args, db) {
  runId++;
  const inFile = path.join(tmp, `in-${runId}.json`);
  const outFile = path.join(tmp, `out-${runId}.json`);
  fs.writeFileSync(inFile, JSON.stringify(db));
  const r = spawnSync(process.execPath, ['-r', path.join(__dirname, 'mock-firebase-admin.js'), path.join(__dirname, '..', 'scripts', 'pin-pepper-migrate.js'), ...args], {
    env: { ...process.env, HOME: home, FAKE_DB_IN: inFile, FAKE_DB_OUT: outFile, PIN_PEPPER: PEPPER_HEX },
    encoding: 'utf8',
  });
  const out = r.stdout + r.stderr;
  return { code: r.status, out, db: fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, 'utf8')) : null };
}

const DB = {
  teams: { T1: { name: 'Alice / Bob', cote: 12 }, T2: { name: 'Carl / Dan', cote: 8 } },
  secrets: {
    T1: { hash: sha('4821'), pinEnc: 'e1' },
    T2: { hash: sha('0007'), pinEnc: 'e2' },
    admin: { hash: 'empreinte-pbkdf2', salt: 'aa', iterations: 210000 },
  },
};

test('sans --apply, la conversion montre ce qui changerait sans rien écrire ni afficher de PIN', () => {
  const r = runMigrate([], DB);
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /PIN à convertir : 2/);
  assert.deepStrictEqual(r.db.secrets, DB.secrets);
  assert.ok(!/4821|0007/.test(r.out), 'aucun PIN ne doit apparaître');
});

test('avec --apply, les empreintes sont converties, vérifiées et sauvegardées avant ; relancer ne change rien', () => {
  const r = runMigrate(['--apply'], DB);
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /Conversion terminée et vérifiée : 2 PIN/);
  assert.ok(!/4821|0007/.test(r.out), 'aucun PIN ne doit apparaître');
  assert.deepStrictEqual(r.db.secrets.T1, { pinEnc: 'e1', hmac: pinHmac(PEPPER, '4821') });
  assert.deepStrictEqual(r.db.secrets.T2, { pinEnc: 'e2', hmac: pinHmac(PEPPER, '0007') });
  assert.deepStrictEqual(r.db.secrets.admin, DB.secrets.admin, 'le code admin ne doit pas être touché');
  assert.deepStrictEqual(r.db.teams, DB.teams);
  const saved = fs.readdirSync(path.join(home, 'backups', 'defi-double')).filter((f) => f.includes('avant-poivre'));
  assert.strictEqual(saved.length, 1);

  const again = runMigrate(['--apply'], r.db);
  assert.strictEqual(again.code, 0, again.out);
  assert.match(again.out, /PIN à convertir : 0 · déjà convertis : 2/);
});
