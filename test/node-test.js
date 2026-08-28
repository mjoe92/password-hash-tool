/* Node test harness for PhtCore — validates every algorithm's hash/verify,
 * the AES-GCM roundtrip, HMAC known-answer vectors, and cross-library
 * interoperability (Node crypto / native argon2 as independent references). */
'use strict';

const assert = require('assert');
const nodeCrypto = require('crypto');

// --- Load app.js core and wire up the same globals the browser CDN scripts provide ---
global.self = global;
require('../app.js');
const Pht = global.PhtCore;
assert(Pht, 'PhtCore export missing');

const scryptJs = require('scrypt-js');
global.scrypt = scryptJs; // browser global shape: { scrypt, syncScrypt }

const bcryptjs = require('bcryptjs');
global.dcodeIO = { bcrypt: bcryptjs };

let argon2Native = null;
try {
  argon2Native = require('argon2');
  const typeMap = { 0: argon2Native.argon2d, 1: argon2Native.argon2i, 2: argon2Native.argon2id };
  global.argon2 = {
    ArgonType: { Argon2d: 0, Argon2i: 1, Argon2id: 2 },
    async hash(o) {
      const encoded = await argon2Native.hash(o.pass, {
        type: typeMap[o.type],
        memoryCost: o.mem,
        timeCost: o.time,
        parallelism: o.parallelism,
        salt: Buffer.from(o.salt),
        hashLength: o.hashLen,
      });
      return { encoded };
    },
    async verify(o) {
      // argon2 >= 0.41 resolves with a boolean instead of throwing.
      const ok = await argon2Native.verify(o.encoded, o.pass);
      if (!ok) throw new Error('Password mismatch');
    },
  };
} catch (e) {
  console.log('NOTE: native argon2 unavailable, argon2 tests will be skipped:', e.message);
}

const blakejs = require('blakejs');
Pht._setBlake2b(blakejs.blake2b);

const PASSWORD = 'correct horse battery staple';
const WRONG = 'incorrect horse battery staple';

const results = [];
function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { results.push({ name, ok: true }); })
    .catch((e) => { results.push({ name, ok: false, error: e.message }); });
}

function defaultParams(algorithm) {
  const params = {};
  for (const p of algorithm.params) params[p.id] = p.value;
  return params;
}

(async () => {
  for (const algorithm of Pht.ALGORITHMS) {
    await record(`${algorithm.id}: hash + verify(correct) === true`, async () => {
      const encoded = await algorithm.hash(PASSWORD, defaultParams(algorithm));
      assert(typeof encoded === 'string' && encoded.length > 10, 'no encoded output');
      assert.strictEqual(await algorithm.verify(PASSWORD, encoded), true, 'correct password must verify');
    });
    await record(`${algorithm.id}: verify(wrong) === false`, async () => {
      const encoded = await algorithm.hash(PASSWORD, defaultParams(algorithm));
      assert.strictEqual(await algorithm.verify(WRONG, encoded), false, 'wrong password must fail');
    });
    await record(`${algorithm.id}: detectAlgorithm() recognizes its output`, async () => {
      const encoded = await algorithm.hash(PASSWORD, defaultParams(algorithm));
      const detected = Pht.detectAlgorithm(encoded);
      assert.strictEqual(detected && detected.id, algorithm.id, 'auto-detection failed');
    });
  }

  // --- cross-library interop: PBKDF2 (Node crypto as reference) ---
  await record('pbkdf2-sha256: verifies Node crypto-produced hash', async () => {
    const salt = Buffer.from('salt', 'utf8');
    const dk = nodeCrypto.pbkdf2Sync('password', salt, 1, 32, 'sha256');
    const b64 = (buf) => Buffer.from(buf).toString('base64').replace(/=+$/, '');
    const encoded = `$pbkdf2-sha256$1$${b64(salt)}$${b64(dk)}`;
    const algo = Pht.detectAlgorithm(encoded);
    assert(algo && algo.id === 'pbkdf2-sha256', 'detection failed');
    assert.strictEqual(await algo.verify('password', encoded), true);
    assert.strictEqual(await algo.verify('wrong', encoded), false);
  });
  await record('pbkdf2-sha512: verifies Node crypto-produced hash', async () => {
    const salt = Buffer.from('salt', 'utf8');
    const dk = nodeCrypto.pbkdf2Sync('password', salt, 1, 64, 'sha512');
    const b64 = (buf) => Buffer.from(buf).toString('base64').replace(/=+$/, '');
    const encoded = `$pbkdf2-sha512$1$${b64(salt)}$${b64(dk)}`;
    const algo = Pht.detectAlgorithm(encoded);
    assert(algo && algo.id === 'pbkdf2-sha512', 'detection failed');
    assert.strictEqual(await algo.verify('password', encoded), true);
  });

  // --- cross-library interop: scrypt (Node crypto as reference) ---
  await record('scrypt: verifies Node crypto-produced hash', async () => {
    const salt = Buffer.from('SodiumChloride', 'utf8');
    const N = 16384, r = 8, p = 1;
    const dk = nodeCrypto.scryptSync('pleaseletmein', salt, 64, { N, r, p });
    const b64 = (buf) => Buffer.from(buf).toString('base64').replace(/=+$/, '');
    const encoded = `$scrypt$ln=14,r=${r},p=${p}$${b64(salt)}$${b64(dk)}`;
    const algo = Pht.detectAlgorithm(encoded);
    assert(algo && algo.id === 'scrypt', 'detection failed');
    assert.strictEqual(await algo.verify('pleaseletmein', encoded), true);
    assert.strictEqual(await algo.verify('wrong', encoded), false);
  });

  // --- known-answer: RFC 6070-style scrypt vector (libsodium test vector) ---
  await record('scrypt: known-answer vector N=16 r=1 p=1', async () => {
    // RFC 7914 test vector: scrypt(P="", S="", N=16, r=1, p=1, dkLen=64) starts 77 d6 57 62 38 65 7b 20
    const dk = nodeCrypto.scryptSync('', Buffer.from(''), 64, { N: 16, r: 1, p: 1 });
    assert.strictEqual(Buffer.from(dk).toString('hex').slice(0, 8), '77d65762', 'node scrypt sanity failed');
    const viaLib = await scryptJs.scrypt(new TextEncoder().encode(''), new Uint8Array(0), 16, 1, 1, 64);
    assert(Buffer.from(viaLib).equals(dk), 'scrypt-js disagrees with Node crypto');
  });

  // --- encryption roundtrip ---
  await record('encryptText/decryptText: roundtrip', async () => {
    const encoded = await Pht.encryptText(PASSWORD, 'Meet at the castle at 3pm. 🏰', 100000);
    assert(encoded.startsWith('enc-v1$pbkdf2-sha256$i=100000$'), 'unexpected prefix: ' + encoded.slice(0, 40));
    assert.strictEqual(await Pht.decryptText(PASSWORD, encoded), 'Meet at the castle at 3pm. 🏰');
  });
  await record('encryptText/decryptText: wrong password fails', async () => {
    const encoded = await Pht.encryptText(PASSWORD, 'secret message', 100000);
    await assert.rejects(() => Pht.decryptText(WRONG, encoded), /OperationError|decrypt/i);
  });

  // --- HMAC known-answer vectors ---
  await record('hmac-sha256: RFC vector', async () => {
    const tag = await Pht.computeHmac('key', 'The quick brown fox jumps over the lazy dog', 'SHA-256');
    assert.strictEqual(tag, 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
  });
  await record('hmac-sha512: RFC vector', async () => {
    const tag = await Pht.computeHmac('key', 'The quick brown fox jumps over the lazy dog', 'SHA-512');
    assert.strictEqual(tag, 'b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a');
  });

  // --- utils ---
  await record('utils: base64 roundtrip (padding-free)', async () => {
    for (const len of [1, 2, 3, 15, 16, 17, 32]) {
      const bytes = Pht.utils.randomBytes(len);
      const b64 = Pht.utils.toB64(bytes);
      assert(!b64.includes('='), 'padding present');
      assert(Buffer.from(Pht.utils.fromB64(b64)).equals(Buffer.from(bytes)), 'roundtrip failed for len ' + len);
    }
  });

  let failed = 0;
  for (const r of results) {
    if (r.ok) console.log('PASS  ' + r.name);
    else { failed++; console.log('FAIL  ' + r.name + '  ->  ' + r.error); }
  }
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
})();
