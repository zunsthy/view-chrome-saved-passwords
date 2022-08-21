const assert = require('node:assert/strict');
const { base64ToUint8Array } = require('../lib/utils');

const input = 'SGVsbG8gV29ybGQh';
const output = base64ToUint8Array(input);
const verify = new TextDecoder('utf-8').decode(output);

assert.strictEqual(verify, 'Hello World!', 'base64 string decode error');
