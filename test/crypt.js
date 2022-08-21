const assert = require('node:assert/strict');
const crypt = require('../build/Release/crypt.node');

const str = 'Hello World!';
const input = new TextEncoder().encode(str).buffer;
const output = crypt.CryptProtectData(input);
const verity = crypt.CryptUnprotectData(output);
const out = new TextDecoder('utf-8').decode(verity);

assert.strictEqual(str, out, 'CryptProtectData -> CryptUnprotectData errors');
