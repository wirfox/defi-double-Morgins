// Fonctions communes à la sauvegarde et à la restauration de la base Firestore.
// Séparées des scripts pour pouvoir être testées sans Firebase (voir test/backup.test.js).
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const FORMAT = 'defi-double-backup';
const VERSION = 1;

// Documents jamais écrasés par une restauration en mode « overwrite » :
// - config/server contient l'adresse ACTUELLE du tunnel (une vieille adresse casserait le site) ;
// - secrets/admin est le code admin : le remettre à l'ancien surprendrait (sauf --include-admin).
const NEVER_OVERWRITE = new Set(['config/server']);
const ADMIN_DOC = 'secrets/admin';

// ---------- Conversion des valeurs Firestore <-> JSON ----------
function isTimestamp(v) {
  return v && typeof v.toDate === 'function' && typeof v.seconds === 'number' && typeof v.nanoseconds === 'number';
}
function isGeoPoint(v) {
  return v && typeof v.latitude === 'number' && typeof v.longitude === 'number' && typeof v.isEqual === 'function';
}
function isDocRef(v) {
  return v && typeof v.path === 'string' && v.firestore && typeof v.get === 'function';
}

function serialize(v) {
  if (v === null || typeof v !== 'object') return v;
  if (isTimestamp(v)) return { __type: 'timestamp', seconds: v.seconds, nanoseconds: v.nanoseconds };
  if (v instanceof Date) return { __type: 'timestamp', seconds: Math.floor(v.getTime() / 1000), nanoseconds: (v.getTime() % 1000) * 1e6 };
  if (isGeoPoint(v)) return { __type: 'geopoint', latitude: v.latitude, longitude: v.longitude };
  if (isDocRef(v)) return { __type: 'ref', path: v.path };
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return { __type: 'bytes', base64: Buffer.from(v).toString('base64') };
  if (Array.isArray(v)) return v.map(serialize);
  const out = {};
  for (const [k, x] of Object.entries(v)) out[k] = serialize(x);
  return out;
}

// types = { Timestamp, GeoPoint } de firebase-admin/firestore ; db sert à recréer les références.
function deserialize(v, types, db) {
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map((x) => deserialize(x, types, db));
  switch (v.__type) {
    case 'timestamp': return new types.Timestamp(v.seconds, v.nanoseconds);
    case 'geopoint': return new types.GeoPoint(v.latitude, v.longitude);
    case 'ref': return db.doc(v.path);
    case 'bytes': return Buffer.from(v.base64, 'base64');
    default: {
      const out = {};
      for (const [k, x] of Object.entries(v)) out[k] = deserialize(x, types, db);
      return out;
    }
  }
}

// JSON avec les clés triées : deux documents identiques donnent le même texte.
function stable(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
}

// ---------- Export ----------
async function exportAll(db) {
  const collections = {};
  const counts = {};
  const roots = await db.listCollections();
  for (const col of roots.sort((a, b) => a.id.localeCompare(b.id))) {
    const snap = await col.get();
    collections[col.id] = {};
    for (const doc of snap.docs) collections[col.id][doc.id] = serialize(doc.data());
    counts[col.id] = snap.docs.length;
  }
  return { format: FORMAT, version: VERSION, exportedAt: new Date().toISOString(), counts, collections };
}

function localDate(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function localTime(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

// Écrit la sauvegarde compressée, lisible seulement par l'utilisateur (600), dans un
// dossier fermé aux autres (700). Écriture dans un fichier temporaire puis renommage :
// une coupure en plein milieu ne laisse jamais un fichier à moitié écrit.
function writeBackup(dir, backup, name) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, name);
  const tmp = file + '.tmp';
  const data = zlib.gzipSync(JSON.stringify(backup));
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
  return { file, bytes: data.length };
}

function readBackup(file) {
  const raw = fs.readFileSync(file);
  const text = file.endsWith('.gz') ? zlib.gunzipSync(raw).toString('utf8') : raw.toString('utf8');
  const backup = JSON.parse(text);
  if (!backup || backup.format !== FORMAT || !backup.collections) {
    throw new Error(`${file} n'est pas une sauvegarde Défi Double.`);
  }
  if (backup.version > VERSION) {
    throw new Error(`Sauvegarde au format ${backup.version}, ce script ne connaît que le format ${VERSION} : mets le dépôt à jour (git pull).`);
  }
  return backup;
}

// ---------- Restauration ----------
// Compare la sauvegarde à la base actuelle, sans rien écrire.
// mode « missing » : on ne recrée que les documents qui n'existent plus.
// mode « overwrite » : on remet aussi les documents qui ont changé depuis.
// Dans les deux cas, AUCUN document n'est supprimé.
async function planRestore(db, backup, { mode = 'missing', only = null, includeAdmin = false } = {}) {
  const plan = { mode, collections: {}, writes: [] };
  const names = Object.keys(backup.collections).filter((c) => !only || only.includes(c));
  for (const name of names) {
    const wanted = backup.collections[name];
    const current = {};
    const snap = await db.collection(name).get();
    for (const doc of snap.docs) current[doc.id] = serialize(doc.data());
    const c = { missing: [], different: [], identical: 0, skipped: [], extra: 0 };
    for (const [id, data] of Object.entries(wanted)) {
      const key = `${name}/${id}`;
      if (!(id in current)) {
        c.missing.push(id);
        plan.writes.push({ collection: name, id, data, create: true });
      } else if (stable(current[id]) === stable(data)) {
        c.identical++;
      } else {
        c.different.push(id);
        if (mode !== 'overwrite') continue;
        if (NEVER_OVERWRITE.has(key) || (key === ADMIN_DOC && !includeAdmin)) c.skipped.push(id);
        else plan.writes.push({ collection: name, id, data, create: false });
      }
    }
    c.extra = Object.keys(current).filter((id) => !(id in wanted)).length;
    plan.collections[name] = c;
  }
  return plan;
}

// Applique le plan par paquets (une écriture groupée Firestore accepte 500 opérations).
// create() échoue si le document est réapparu entre-temps : on n'écrase jamais par surprise.
async function applyPlan(db, plan, types, chunk = 400) {
  let done = 0;
  for (let i = 0; i < plan.writes.length; i += chunk) {
    const batch = db.batch();
    for (const w of plan.writes.slice(i, i + chunk)) {
      const ref = db.collection(w.collection).doc(w.id);
      const data = deserialize(w.data, types, db);
      if (w.create) batch.create(ref, data); else batch.set(ref, data);
    }
    await batch.commit();
    done += Math.min(chunk, plan.writes.length - i);
  }
  return done;
}

module.exports = {
  FORMAT, VERSION, serialize, deserialize, stable, exportAll, writeBackup, readBackup,
  planRestore, applyPlan, localDate, localTime,
};
