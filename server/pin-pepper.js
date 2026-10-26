// « Poivre » des PIN : une clé secrète de 32 octets qui n'existe QUE sur le Pi
// (fichier pinPepper.key, à côté de serviceAccountKey.json, + une copie dans
// Proton Pass). L'empreinte rangée dans Firestore est HMAC-SHA256(poivre, PIN) :
// sans le poivre, quelqu'un qui récupère la base (règles mal écrites, export,
// sauvegarde en clair) ne peut tester AUCUN des 10 000 PIN possibles.
//
// Le poivre n'est jamais dans Firestore ni dans les sauvegardes : s'il est
// perdu, plus aucun PIN ne peut être vérifié (il faudrait en redonner de
// nouveaux à toutes les équipes). D'où la copie obligatoire dans Proton Pass.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PEPPER_FILE = process.env.PIN_PEPPER_FILE || path.join(__dirname, 'pinPepper.key');

const MISSING_HELP =
  `Clé « poivre » des PIN introuvable (${PEPPER_FILE}).\n` +
  'Sur le Pi, crée-la puis protège-la :\n' +
  '  cd ~/defi-double-Morgins/server && (umask 077 && openssl rand -hex 32 > pinPepper.key)\n' +
  'Copie ensuite son contenu dans Proton Pass (cat pinPepper.key). Si le Pi est reconstruit,\n' +
  'remets CE MÊME fichier : avec une autre clé, plus aucun PIN ne serait reconnu.';

function loadPepper() {
  let hex = process.env.PIN_PEPPER;
  if (!hex) {
    try {
      hex = fs.readFileSync(PEPPER_FILE, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT') throw new Error(MISSING_HELP);
      throw e;
    }
    try {
      if (fs.statSync(PEPPER_FILE).mode & 0o077) {
        console.warn(`Attention : ${PEPPER_FILE} est lisible par d'autres comptes. Corrige avec : chmod 600 ${PEPPER_FILE}`);
      }
    } catch (e) { /* vérification de confort seulement */ }
  }
  hex = String(hex).trim();
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error(`Clé « poivre » invalide (${PEPPER_FILE}) : il faut 64 caractères hexadécimaux, comme ceux produits par « openssl rand -hex 32 ».`);
  }
  return Buffer.from(hex, 'hex');
}

const pinHmac = (pepper, pin) => crypto.createHmac('sha256', pepper).update(String(pin), 'utf8').digest('hex');

module.exports = { loadPepper, pinHmac, PEPPER_FILE };
