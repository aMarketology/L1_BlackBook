const { Client } = require('ssh2');
const fs = require('fs');
const path = require('path');

const conn = new Client();
const pubKey = fs.readFileSync(path.join(process.env.USERPROFILE, '.ssh', 'id_ed25519.pub'), 'utf8').trim();

console.log('Connecting to server with password...');

conn.on('ready', () => {
  console.log('Client :: ready. Configuring SSH keys...');
  conn.exec(`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "${pubKey}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`, (err, stream) => {
    if (err) throw err;
    stream.on('close', (code, signal) => {
      console.log('SSH keys added! Return code:', code);
      conn.end();
      process.exit(code === 0 ? 0 : 1);
    }).on('data', (data) => {
      console.log('STDOUT: ' + data);
    }).stderr.on('data', (data) => {
      console.log('STDERR: ' + data);
    });
  });
}).connect({
  host: '74.50.74.126',
  port: 22,
  username: 'root',
  password: 'M$s4gq4R',
  readyTimeout: 15000
});
