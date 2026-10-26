#!/usr/bin/env node
// Restauration d'une sauvegarde faite par backup-export.js. Ne SUPPRIME jamais rien.
//
//   node scripts/backup-restore.js <fichier.json.gz>               -> montre ce qui changerait, n'écrit rien
//   node scripts/backup-restore.js <fichier.json.gz> --apply       -> recrée les documents disparus
//
// Options :
//   --mode overwrite   remet aussi les documents modifiés depuis la sauvegarde
//                      (jamais config/server, ni le code admin sans --include-admin)
//   --only a,b         seulement ces collections (ex. --only matches ou --only teams,secrets)
//   --details          liste les documents concernés
//   --apply            écrit vraiment ; avant d'écrire, l'état actuel est sauvegardé à côté
const os = require('os');
const path = require('path');
const { exportAll, writeBackup, readBackup, planRestore, applyPlan, localDate, localTime } = require('./backup-lib');

function parseArgs(argv) {
  const opts = { file: null, apply: false, mode: 'missing', only: null, includeAdmin: false, details: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--apply') opts.apply = true;
    else if (a === '--details') opts.details = true;
    else if (a === '--include-admin') opts.includeAdmin = true;
    else if (a === '--mode') opts.mode = argv[++i];
    else if (a === '--only') opts.only = String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a.startsWith('--')) throw new Error(`Option inconnue : ${a}`);
    else if (!opts.file) opts.file = a;
    else throw new Error(`Argument en trop : ${a}`);
  }
  if (!opts.file) throw new Error('Indique le fichier de sauvegarde à restaurer. Exemple : node scripts/backup-restore.js ~/backups/defi-double/defi-double-2026-10-14.json.gz');
  if (!['missing', 'overwrite'].includes(opts.mode)) throw new Error('--mode doit valoir missing ou overwrite.');
  return opts;
}

function printPlan(plan, details) {
  let creates = 0, overwrites = 0;
  for (const w of plan.writes) (w.create ? creates++ : overwrites++);
  console.log(`Mode : ${plan.mode === 'overwrite' ? 'overwrite (recrée les disparus ET remet les modifiés)' : 'missing (recrée seulement les disparus)'}`);
  for (const [name, c] of Object.entries(plan.collections)) {
    const parts = [`${c.missing.length} à recréer`, `${c.identical} identiques`];
    if (c.different.length) parts.push(`${c.different.length} modifiés depuis${plan.mode === 'overwrite' ? '' : ' (laissés tels quels)'}`);
    if (c.skipped.length) parts.push(`${c.skipped.length} protégés (non touchés)`);
    if (c.extra) parts.push(`${c.extra} nouveaux depuis (gardés)`);
    console.log(`  ${name.padEnd(16)} ${parts.join(' · ')}`);
    if (details) {
      if (c.missing.length) console.log(`      à recréer : ${c.missing.join(', ')}`);
      if (c.different.length) console.log(`      modifiés : ${c.different.join(', ')}`);
      if (c.skipped.length) console.log(`      protégés : ${c.skipped.join(', ')}`);
    }
  }
  console.log(`Total : ${creates} document(s) à recréer, ${overwrites} à remettre. Aucune suppression.`);
  return creates + overwrites;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const backup = readBackup(path.resolve(opts.file));
  if (opts.only) {
    const unknown = opts.only.filter((c) => !(c in backup.collections));
    if (unknown.length) throw new Error(`Collection(s) absente(s) de la sauvegarde : ${unknown.join(', ')}`);
  }

  let firebaseApp, firestore, serviceAccount;
  try {
    firebaseApp = require('firebase-admin/app');
    firestore = require('firebase-admin/firestore');
    serviceAccount = require('../serviceAccountKey.json');
  } catch (e) {
    throw new Error('Clé serviceAccountKey.json introuvable dans le dossier server : ce script tourne seulement sur le Pi.');
  }
  if (backup.projectId && backup.projectId !== serviceAccount.project_id) {
    throw new Error(`Cette sauvegarde vient du projet « ${backup.projectId} », pas de « ${serviceAccount.project_id} » : restauration refusée.`);
  }
  firebaseApp.initializeApp({ credential: firebaseApp.cert(serviceAccount) });
  const db = firestore.getFirestore();

  console.log(`Sauvegarde du ${new Date(backup.exportedAt).toLocaleString('fr-CH')} (projet ${serviceAccount.project_id})`);
  const plan = await planRestore(db, backup, opts);
  const n = printPlan(plan, opts.details);

  if (!opts.apply) {
    console.log(n ? '\nRien n\'a été écrit. Pour appliquer, relance la même commande avec --apply.' : '\nRien à restaurer : la base contient déjà tout ce qu\'il y a dans la sauvegarde.');
    return;
  }
  if (!n) { console.log('\nRien à restaurer.'); return; }

  // Filet de sécurité : on garde l'état actuel avant d'y toucher.
  const now = new Date();
  const current = await exportAll(db);
  current.projectId = serviceAccount.project_id;
  const dir = path.join(os.homedir(), 'backups', 'defi-double');
  const { file } = writeBackup(dir, current, `defi-double-${localDate(now)}-avant-restauration-${localTime(now)}.json.gz`);
  console.log(`\nÉtat actuel sauvegardé avant restauration : ${file}`);

  const written = await applyPlan(db, plan, { Timestamp: firestore.Timestamp, GeoPoint: firestore.GeoPoint });
  console.log(`Restauration terminée : ${written} document(s) écrit(s).`);
  if (plan.writes.some((w) => w.collection === 'secrets')) {
    console.log('Note : si le code admin a changé depuis cette sauvegarde, les PIN restaurés ne s\'afficheront plus dans l\'admin.\nIls marchent quand même pour saisir les matchs ; sinon, redéfinis-les avec « Modifier ».');
    console.log('Si cette sauvegarde date d\'avant le poivre des PIN, relance ensuite : npm run pepper-migrate -- --apply');
  }
}

main().then(() => process.exit(0), (e) => {
  console.error('Restauration ANNULÉE : ' + e.message);
  process.exit(1);
});
