#!/usr/bin/env node
// Sauvegarde complète de la base Firestore dans un fichier daté et compressé.
//   cd ~/defi-double-Morgins/server && node scripts/backup-export.js [dossier]
// Dossier par défaut : ~/backups/defi-double. Le fichier contient TOUT, PIN compris
// (empreintes et PIN chiffrés) : il est créé lisible seulement par ton utilisateur.
// Ne fait que LIRE la base. Code de sortie 0 = sauvegarde réussie, sinon 1.
const os = require('os');
const path = require('path');
const { exportAll, writeBackup, localDate } = require('./backup-lib');

async function main() {
  const dir = path.resolve(process.argv[2] || path.join(os.homedir(), 'backups', 'defi-double'));
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

  const backup = await exportAll(db);
  backup.projectId = serviceAccount.project_id;
  const total = Object.values(backup.counts).reduce((a, b) => a + b, 0);
  if (total === 0) throw new Error('La base est vide ou illisible : sauvegarde annulée pour ne pas garder un fichier vide.');

  const { file, bytes } = writeBackup(dir, backup, `defi-double-${localDate()}.json.gz`);
  const detail = Object.entries(backup.counts).map(([c, n]) => `${c} ${n}`).join(', ');
  console.log(`Sauvegarde écrite : ${file} (${total} documents, ${Math.ceil(bytes / 1024)} Ko)`);
  console.log(`Détail : ${detail}`);
}

main().then(() => process.exit(0), (e) => {
  console.error('Sauvegarde ÉCHOUÉE : ' + e.message);
  process.exit(1);
});
