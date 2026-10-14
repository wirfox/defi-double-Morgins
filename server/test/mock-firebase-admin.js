// Préchargé (node -r) par test/backup.test.js : remplace firebase-admin et la clé du
// compte de service par la fausse base, pour lancer les vrais scripts sans Firebase.
// FAKE_DB_IN  : fichier JSON de départ (format sérialisé de backup-lib)
// FAKE_DB_OUT : fichier où la base est réécrite à la fin, pour que le test la vérifie
const fs = require('fs');
const Module = require('module');
const { createDb, Timestamp, GeoPoint } = require('./fake-firestore');
const { serialize, deserialize } = require('../scripts/backup-lib');

const initial = JSON.parse(fs.readFileSync(process.env.FAKE_DB_IN, 'utf8'));
const db = createDb({});
for (const [c, docs] of Object.entries(initial)) {
  db.store.set(c, new Map(Object.entries(docs).map(([id, d]) => [id, deserialize(d, { Timestamp, GeoPoint }, db)])));
}

const fakeAdmin = {
  initializeApp() {},
  credential: { cert: () => ({}) },
  firestore: Object.assign(() => db, { Timestamp, GeoPoint }),
};
const fakeKey = { project_id: process.env.FAKE_PROJECT || 'tcm-test' };

const load = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'firebase-admin') return fakeAdmin;
  if (request.endsWith('serviceAccountKey.json')) return fakeKey;
  return load.apply(this, arguments);
};

process.on('exit', () => {
  const out = {};
  for (const [c, docs] of db.store) out[c] = Object.fromEntries([...docs].map(([id, d]) => [id, serialize(d)]));
  fs.writeFileSync(process.env.FAKE_DB_OUT, JSON.stringify(out));
});
