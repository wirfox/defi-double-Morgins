#!/usr/bin/env node
// Convertit les empreintes de PIN de l'ancien format (SHA-256 sans poivre,
// champ `hash`) vers le nouveau (HMAC-SHA256 avec le poivre du Pi, champ `hmac`).
// Les PIN des joueurs ne changent PAS : pour chaque ancienne empreinte, le
// script retrouve le PIN (10 000 essais, c'est justement la faiblesse corrigée),
// calcule la nouvelle empreinte, puis remplace l'ancienne.
//
//   npm run pepper-migrate               -> montre ce qui serait converti, n'écrit rien
//   npm run pepper-migrate -- --apply    -> convertit pour de vrai
//
// Avec --apply, l'état actuel de la base est d'abord sauvegardé dans
// ~/backups/defi-double (…-avant-poivre-HHMMSS.json.gz). Aucun PIN n'est
// jamais affiché. Rejouable sans risque : ce qui est déjà converti est ignoré.
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { loadPepper, pinHmac } = require('../pin-pepper');
const { exportAll, writeBackup, localDate, localTime } = require('./backup-lib');

const sha256 = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

// Table des 10 000 empreintes SHA-256 possibles : empreinte -> PIN.
function legacyTable() {
  const t = new Map();
  for (let i = 0; i < 10000; i++) { const pin = String(i).padStart(4, '0'); t.set(sha256(pin), pin); }
  return t;
}

// Ce qu'il faut écrire pour chaque document de `secrets` (sauf le code admin).
function planMigration(docs, pepper) {
  const table = legacyTable();
  const plan = { writes: [], done: 0, unknown: [], conflicts: [] };
  for (const { id, data } of docs) {
    if (id === 'admin' || !data || typeof data !== 'object') continue;
    if (!data.hash) { if (data.hmac) plan.done++; continue; }
    const pin = table.get(String(data.hash).toLowerCase());
    if (!pin) { plan.unknown.push(id); continue; }
    const hmac = pinHmac(pepper, pin);
    // Déjà une nouvelle empreinte, mais pour un autre PIN : on ne choisit pas à
    // la place de l'admin, on signale.
    if (data.hmac && data.hmac !== hmac) { plan.conflicts.push(id); continue; }
    const { hash, ...rest } = data;
    plan.writes.push({ id, data: { ...rest, hmac } });
  }
  return plan;
}

async function main() {
  const apply = process.argv.includes('--apply');
  const unknownOpt = process.argv.slice(2).find((a) => a !== '--apply');
  if (unknownOpt) throw new Error(`Option inconnue : ${unknownOpt}`);
  const pepper = loadPepper();

  let firebaseApp, firestore, serviceAccount;
  try {
    firebaseApp = require('firebase-admin/app');
    firestore = require('firebase-admin/firestore');
    serviceAccount = require('../serviceAccountKey.json');
  } catch (e) {
    throw new Error('Clé serviceAccountKey.json introuvable dans le dossier server : ce script tourne seulement sur le Pi.');
  }
  firebaseApp.initializeApp({ credential: firebaseApp.cert(serviceAccount) });
  const db = firestore.getFirestore();

  const read = async () => (await db.collection('secrets').get()).docs.map((d) => ({ id: d.id, data: d.data() }));
  const plan = planMigration(await read(), pepper);
  console.log(`PIN à convertir : ${plan.writes.length} · déjà convertis : ${plan.done}`);
  if (plan.unknown.length) console.log(`Empreinte illisible (laissée telle quelle, redéfinis ce PIN dans l'admin) : ${plan.unknown.join(', ')}`);
  if (plan.conflicts.length) console.log(`Ancienne et nouvelle empreinte différentes (laissées telles quelles, redéfinis ce PIN dans l'admin) : ${plan.conflicts.join(', ')}`);

  if (!apply) {
    console.log(plan.writes.length ? '\nRien n\'a été écrit. Pour convertir, relance avec --apply.' : '\nRien à convertir.');
    return;
  }
  if (!plan.writes.length) { console.log('\nRien à convertir.'); return; }

  // Filet de sécurité : l'état actuel, avant d'y toucher.
  const now = new Date();
  const current = await exportAll(db);
  current.projectId = serviceAccount.project_id;
  const dir = path.join(os.homedir(), 'backups', 'defi-double');
  const { file } = writeBackup(dir, current, `defi-double-${localDate(now)}-avant-poivre-${localTime(now)}.json.gz`);
  console.log(`\nÉtat actuel sauvegardé avant conversion : ${file}`);

  // Chaque document est réécrit en une fois (nouvelle empreinte + ancienne
  // retirée) : il n'existe jamais d'instant où un PIN n'aurait plus d'empreinte.
  for (let i = 0; i < plan.writes.length; i += 400) {
    const batch = db.batch();
    for (const w of plan.writes.slice(i, i + 400)) batch.set(db.collection('secrets').doc(w.id), w.data);
    await batch.commit();
  }

  // Vérification : on relit et on contrôle chaque document converti.
  const after = new Map((await read()).map((d) => [d.id, d.data]));
  const bad = plan.writes.filter((w) => { const d = after.get(w.id); return !d || d.hash !== undefined || d.hmac !== w.data.hmac; });
  if (bad.length) throw new Error(`conversion incomplète pour : ${bad.map((w) => w.id).join(', ')}. Relance la commande ; la sauvegarde ci-dessus contient l'état d'avant.`);
  console.log(`Conversion terminée et vérifiée : ${plan.writes.length} PIN. Les joueurs gardent les mêmes PIN.`);
}

if (require.main === module) {
  main().then(() => process.exit(0), (e) => {
    console.error('Conversion ANNULÉE : ' + e.message);
    process.exit(1);
  });
}

module.exports = { planMigration };
