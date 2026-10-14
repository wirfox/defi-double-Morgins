#!/usr/bin/env node
// Crée le tout premier code admin, depuis le Raspberry Pi lui-même.
//   cd ~/defi-double-Morgins/server && npm run admin-setup
// Le code est demandé deux fois sans s'afficher : il ne reste ni à l'écran ni
// dans l'historique du terminal, et peut contenir n'importe quel caractère.
const http = require('http');
const readline = require('readline');
const { execSync } = require('child_process');

const PORT = Number(process.env.PORT) || 8080;
const tty = process.stdin.isTTY;

function setEcho(on) {
  if (!tty) return;
  try { execSync(on ? 'stty echo' : 'stty -echo', { stdio: 'inherit' }); } catch (e) {}
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function main() {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const lines = rl[Symbol.asyncIterator]();
  const read = async (question) => {
    process.stdout.write(question);
    const { value } = await lines.next();
    if (tty) process.stdout.write('\n');
    return (value || '').replace(/\r$/, '');
  };

  let code, confirm;
  setEcho(false);
  try {
    code = await read('Nouveau code admin (8 à 64 caractères) : ');
    confirm = await read('Confirme le code : ');
  } finally {
    setEcho(true);
    rl.close();
  }
  if (code !== confirm) fail('Les deux codes ne correspondent pas. Rien n\'a été changé.');
  if (code.length < 8 || code.length > 64) fail('Le code doit faire entre 8 et 64 caractères. Rien n\'a été changé.');

  const body = JSON.stringify({ code });
  const req = http.request({
    host: '127.0.0.1', port: PORT, path: '/admin/setup', method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  }, (res) => {
    let data = '';
    res.on('data', (c) => { data += c; });
    res.on('end', () => {
      let reply = {};
      try { reply = JSON.parse(data); } catch (e) {}
      if (reply.ok) {
        console.log('✓ Code admin créé. Connecte-toi maintenant dans l\'admin du site.');
        process.exit(0);
      }
      fail('Refusé : ' + (reply.error || 'réponse ' + res.statusCode));
    });
  });
  req.on('error', () => fail(`Serveur injoignable sur le port ${PORT}. Est-il lancé ? (pm2 list)`));
  req.end(body);
}

main();
