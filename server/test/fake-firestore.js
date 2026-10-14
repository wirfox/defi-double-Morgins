// Fausse base Firestore en mémoire pour les tests de sauvegarde/restauration.
// Seulement ce que backup-lib.js utilise : listCollections, get, doc, batch.
class Timestamp {
  constructor(seconds, nanoseconds) { this.seconds = seconds; this.nanoseconds = nanoseconds; }
  toDate() { return new Date(this.seconds * 1000 + Math.floor(this.nanoseconds / 1e6)); }
}
class GeoPoint {
  constructor(latitude, longitude) { this.latitude = latitude; this.longitude = longitude; }
  isEqual(o) { return o.latitude === this.latitude && o.longitude === this.longitude; }
}

function createDb(initial = {}) {
  const store = new Map(); // collection -> Map(id -> data)
  for (const [c, docs] of Object.entries(initial)) store.set(c, new Map(Object.entries(docs)));
  const coll = (name) => { if (!store.has(name)) store.set(name, new Map()); return store.get(name); };
  const log = { reads: 0, writes: [] };

  const db = {
    store, log,
    async listCollections() {
      return [...store.keys()].filter((c) => store.get(c).size).map((c) => db.collection(c));
    },
    collection(name) {
      return {
        id: name,
        async get() {
          log.reads++;
          return { docs: [...coll(name).entries()].map(([id, d]) => ({ id, data: () => ({ ...d }) })) };
        },
        doc(id) { return db.doc(`${name}/${id}`); },
      };
    },
    doc(p) {
      const [name, id] = p.split('/');
      return { path: p, id, collectionName: name, firestore: db, async get() { return null; } };
    },
    batch() {
      const ops = [];
      return {
        create(ref, data) { ops.push(['create', ref, data]); },
        set(ref, data) { ops.push(['set', ref, data]); },
        async commit() {
          for (const [op, ref] of ops) {
            if (op === 'create' && coll(ref.collectionName).has(ref.id)) {
              const e = new Error('ALREADY_EXISTS'); e.code = 6; throw e;
            }
          }
          for (const [op, ref, data] of ops) { coll(ref.collectionName).set(ref.id, data); log.writes.push([op, ref.path]); }
        },
      };
    },
  };
  return db;
}

module.exports = { createDb, Timestamp, GeoPoint };
