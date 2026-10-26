// Tests de la sauvegarde et de la restauration, sans Firebase ni réseau.
// Les scripts tournent pour de vrai, avec une fausse base (test/mock-firebase-admin.js)
// et un dossier personnel temporaire supprimé à la fin.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { spawnSync } = require('child_process');
const lib = require('../scripts/backup-lib');
const { createDb, Timestamp, GeoPoint } = require('./fake-firestore');

const ts = (s) => ({ __type: 'timestamp', seconds: s, nanoseconds: 0 });
const BASE = {
  teams: { T1: { name: 'Alice / Bob', cote: 12, points: 0 }, T2: { name: 'Carl / Dan', cote: 8, points: 0 } },
  matches: { M1: { equipeA: 'Alice / Bob', equipeB: 'Carl / Dan', vainqueur: 'A', scores: { set1: '6-4', set2: '6-3' }, pointsA: 8, pointsB: 3, date: ts(1790000000) } },
  juniors: { J1: { name: 'Léa', green: true } },
  juniors_matches: { JM1: { joueurA: 'Léa', joueurB: 'Tom', date: ts(1790000500) } },
  secrets: { T1: { hash: 'h1', pinEnc: 'e1' }, T2: { hash: 'h2', pinEnc: 'e2' }, admin: { hash: 'adminhash-ancien' } },
  config: { server: { url: 'https://ancienne-adresse.trycloudflare.com', updatedAt: ts(1790000000) } },
};

let tmp, home;
before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dd-backup-test-'));
  home = path.join(tmp, 'home');
  fs.mkdirSync(home);
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

let runId = 0;
function run(script, args, db, extraEnv = {}) {
  runId++;
  const inFile = path.join(tmp, `in-${runId}.json`);
  const outFile = path.join(tmp, `out-${runId}.json`);
  fs.writeFileSync(inFile, JSON.stringify(db));
  const r = spawnSync(process.execPath, ['-r', path.join(__dirname, 'mock-firebase-admin.js'), path.join(__dirname, '..', 'scripts', script), ...args], {
    env: { ...process.env, HOME: home, FAKE_DB_IN: inFile, FAKE_DB_OUT: outFile, ...extraEnv },
    encoding: 'utf8',
  });
  const after = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, 'utf8')) : null;
  return { code: r.status, out: r.stdout + r.stderr, db: after };
}
const clone = (o) => JSON.parse(JSON.stringify(o));
const backupDir = () => path.join(home, 'backups', 'defi-double');
function exportNow(db = BASE) {
  const r = run('backup-export.js', [], db);
  assert.strictEqual(r.code, 0, r.out);
  const file = path.join(backupDir(), `defi-double-${lib.localDate()}.json.gz`);
  return { r, file };
}

test('les dates, positions, références et octets survivent à un aller-retour', () => {
  const db = createDb();
  const data = { t: new Timestamp(1790000000, 123000000), g: new GeoPoint(46.25, 6.85), r: db.doc('teams/T1'), b: Buffer.from('abc'), list: [new Timestamp(1, 2)], n: null, s: 'x', o: { deep: true } };
  const back = lib.deserialize(JSON.parse(JSON.stringify(lib.serialize(data))), { Timestamp, GeoPoint }, db);
  assert.ok(back.t instanceof Timestamp && back.t.seconds === 1790000000 && back.t.nanoseconds === 123000000);
  assert.ok(back.g instanceof GeoPoint && back.g.latitude === 46.25);
  assert.strictEqual(back.r.path, 'teams/T1');
  assert.strictEqual(back.b.toString(), 'abc');
  assert.ok(back.list[0] instanceof Timestamp);
  assert.deepStrictEqual([back.n, back.s, back.o], [null, 'x', { deep: true }]);
});

test('export : toutes les collections, fichier compressé lisible seulement par soi', () => {
  const { r, file } = exportNow();
  assert.match(r.out, /Sauvegarde écrite : .*\(9 documents/);
  const backup = lib.readBackup(file);
  assert.deepStrictEqual(Object.keys(backup.collections).sort(), Object.keys(BASE).sort());
  assert.deepStrictEqual(backup.collections, BASE, 'le contenu doit être identique à la base, PIN compris');
  assert.strictEqual(backup.projectId, 'tcm-test');
  assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
  assert.strictEqual(fs.statSync(backupDir()).mode & 0o777, 0o700);
  assert.deepStrictEqual(fs.readdirSync(backupDir()).filter((f) => f.endsWith('.tmp')), [], 'aucun fichier temporaire ne doit rester');
  // c'est bien du gzip
  assert.doesNotThrow(() => zlib.gunzipSync(fs.readFileSync(file)));
});

test('export : ne lit que la base, n\'écrit rien dedans', () => {
  const { r } = exportNow();
  assert.deepStrictEqual(r.db, BASE);
});

test('export : base vide = échec (code 1) et aucun fichier', () => {
  const dir = path.join(tmp, 'vide');
  const r = run('backup-export.js', [dir], {});
  assert.strictEqual(r.code, 1);
  assert.match(r.out, /ÉCHOUÉE/);
  assert.ok(!fs.existsSync(dir) || fs.readdirSync(dir).length === 0);
});

test('export : dossier choisi en argument', () => {
  const dir = path.join(tmp, 'ailleurs');
  const r = run('backup-export.js', [dir], BASE);
  assert.strictEqual(r.code, 0, r.out);
  assert.ok(fs.existsSync(path.join(dir, `defi-double-${lib.localDate()}.json.gz`)));
});

test('restauration sans --apply : montre le plan et n\'écrit RIEN', () => {
  const { file } = exportNow();
  const now = clone(BASE);
  delete now.matches.M1; // match supprimé par erreur
  const r = run('backup-restore.js', [file], now);
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /matches\s+1 à recréer/);
  assert.match(r.out, /Rien n'a été écrit/);
  assert.deepStrictEqual(r.db, now);
});

test('restauration --apply : recrée le disparu, ne supprime rien, ne touche pas au reste', () => {
  const { file } = exportNow();
  const now = clone(BASE);
  delete now.matches.M1;
  now.matches.M2 = { equipeA: 'Nouveau', equipeB: 'Match', date: ts(1790009999) }; // ajouté après la sauvegarde
  now.teams.T2.cote = 10; // modifié après la sauvegarde
  now.config.server.url = 'https://adresse-actuelle.trycloudflare.com';
  const before = fs.readdirSync(backupDir()).length;
  const r = run('backup-restore.js', [file, '--apply'], now);
  assert.strictEqual(r.code, 0, r.out);
  assert.deepStrictEqual(r.db.matches.M1, BASE.matches.M1, 'le match supprimé revient à l\'identique, date comprise');
  assert.deepStrictEqual(r.db.matches.M2, now.matches.M2, 'le match ajouté depuis est gardé');
  assert.strictEqual(r.db.teams.T2.cote, 10, 'mode missing : les modifications récentes sont gardées');
  assert.strictEqual(r.db.config.server.url, 'https://adresse-actuelle.trycloudflare.com');
  assert.match(r.out, /1 document\(s\) écrit/);
  // filet de sécurité : l'état d'avant est sauvegardé
  const files = fs.readdirSync(backupDir());
  assert.strictEqual(files.length, before + 1);
  const safety = files.find((f) => f.includes('avant-restauration'));
  assert.ok(safety);
  assert.deepStrictEqual(lib.readBackup(path.join(backupDir(), safety)).collections.matches, now.matches);
});

test('restauration --mode overwrite : remet les modifiés, mais jamais l\'adresse du tunnel ni le code admin', () => {
  const { file } = exportNow();
  const now = clone(BASE);
  now.teams.T2.cote = 10;
  now.config.server.url = 'https://adresse-actuelle.trycloudflare.com';
  now.secrets.admin.hash = 'adminhash-nouveau';
  now.teams.T3 = { name: 'Equipe récente', cote: 5, points: 0 };
  const r = run('backup-restore.js', [file, '--apply', '--mode', 'overwrite'], now);
  assert.strictEqual(r.code, 0, r.out);
  assert.strictEqual(r.db.teams.T2.cote, 8, 'remis à la valeur de la sauvegarde');
  assert.strictEqual(r.db.config.server.url, 'https://adresse-actuelle.trycloudflare.com', 'config/server protégé');
  assert.strictEqual(r.db.secrets.admin.hash, 'adminhash-nouveau', 'code admin protégé');
  assert.deepStrictEqual(r.db.teams.T3, now.teams.T3, 'rien n\'est supprimé');
  assert.match(r.out, /config .*1 protégés/);
  assert.match(r.out, /secrets .*1 protégés/);
  assert.match(r.out, /1 document\(s\) écrit/);
});

test('restauration --include-admin : remet aussi le code admin, toujours pas le tunnel', () => {
  const { file } = exportNow();
  const now = clone(BASE);
  now.secrets.admin.hash = 'adminhash-nouveau';
  now.config.server.url = 'https://adresse-actuelle.trycloudflare.com';
  const r = run('backup-restore.js', [file, '--apply', '--mode', 'overwrite', '--include-admin'], now);
  assert.strictEqual(r.code, 0, r.out);
  assert.strictEqual(r.db.secrets.admin.hash, 'adminhash-ancien');
  assert.strictEqual(r.db.config.server.url, 'https://adresse-actuelle.trycloudflare.com');
});

test('restauration --only : ne touche que les collections demandées', () => {
  const { file } = exportNow();
  const now = clone(BASE);
  delete now.teams.T1; delete now.secrets.T1; delete now.matches.M1;
  const r = run('backup-restore.js', [file, '--apply', '--only', 'teams,secrets'], now);
  assert.strictEqual(r.code, 0, r.out);
  assert.deepStrictEqual(r.db.teams.T1, BASE.teams.T1);
  assert.deepStrictEqual(r.db.secrets.T1, BASE.secrets.T1);
  assert.strictEqual(r.db.matches.M1, undefined, 'matches non demandé : pas recréé');
  assert.match(r.out, /PIN restaurés/);
});

test('restauration : base déjà complète = rien à faire, rien écrit, pas de fichier de sécurité', () => {
  const { file } = exportNow();
  const before = fs.readdirSync(backupDir()).length;
  const r = run('backup-restore.js', [file, '--apply'], BASE);
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /Rien à restaurer/);
  assert.deepStrictEqual(r.db, BASE);
  assert.strictEqual(fs.readdirSync(backupDir()).length, before);
});

test('restauration refusée : autre projet, mauvais fichier, option inconnue, collection inconnue', () => {
  const { file } = exportNow();
  let r = run('backup-restore.js', [file, '--apply'], {}, { FAKE_PROJECT: 'autre-projet' });
  assert.strictEqual(r.code, 1); assert.match(r.out, /vient du projet « tcm-test »/);
  assert.deepStrictEqual(r.db, {});

  const bad = path.join(tmp, 'pas-une-sauvegarde.json');
  fs.writeFileSync(bad, '{"hello":1}');
  r = run('backup-restore.js', [bad, '--apply'], {});
  assert.strictEqual(r.code, 1); assert.match(r.out, /n'est pas une sauvegarde/);

  r = run('backup-restore.js', [file, '--forcer'], BASE);
  assert.strictEqual(r.code, 1); assert.match(r.out, /Option inconnue/);

  r = run('backup-restore.js', [file, '--only', 'equipes'], BASE);
  assert.strictEqual(r.code, 1); assert.match(r.out, /absente\(s\) de la sauvegarde : equipes/);

  r = run('backup-restore.js', [], BASE);
  assert.strictEqual(r.code, 1); assert.match(r.out, /Indique le fichier/);
});

test('restauration : un document réapparu entre-temps n\'est jamais écrasé (create)', async () => {
  const db = createDb({ teams: { T1: { name: 'X' } } });
  const plan = { writes: [{ collection: 'teams', id: 'T1', data: { name: 'Ancien' }, create: true }] };
  await assert.rejects(lib.applyPlan(db, plan, { Timestamp, GeoPoint }), /ALREADY_EXISTS/);
  assert.strictEqual(db.store.get('teams').get('T1').name, 'X');
});

test('restauration : écrit par paquets (plus de 500 documents)', async () => {
  const db = createDb();
  const writes = Array.from({ length: 1001 }, (_, i) => ({ collection: 'matches', id: 'M' + i, data: { i, date: ts(i) }, create: true }));
  const n = await lib.applyPlan(db, { writes }, { Timestamp, GeoPoint });
  assert.strictEqual(n, 1001);
  assert.strictEqual(db.store.get('matches').size, 1001);
  assert.ok(db.store.get('matches').get('M7').date instanceof Timestamp);
});
