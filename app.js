/* Password Hash Tool — browser-only hashing, verification, and encryption.
 *
 * Structure:
 *  - PhtCore: environment-agnostic crypto (works in browsers and Node for testing).
 *  - UI wiring: guarded so the core can be unit-tested outside the browser.
 *
 * Encoded hash formats are self-describing: verification parses algorithm,
 * parameters, and salt from the encoded string — it never reuses UI values.
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Utilities
  // ---------------------------------------------------------------------------

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function toHex(buffer) {
    return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function toB64(bytes) {
    let binary = '';
    for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
    // padding-free base64, as used by passlib-encoded PHC strings
    return btoa(binary).replace(/=+$/, '');
  }

  function fromB64(text) {
    const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function constantTimeEqual(a, b) {
    const aa = new Uint8Array(a);
    const bb = new Uint8Array(b);
    if (aa.length !== bb.length) return false;
    let diff = 0;
    for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
    return diff === 0;
  }

  function subtle() {
    if (!global.crypto || !global.crypto.subtle) {
      throw new Error('Web Crypto is not available in this context.');
    }
    return global.crypto.subtle;
  }

  async function sha(algorithm, data) {
    return new Uint8Array(await subtle().digest(algorithm, data));
  }

  // ---------------------------------------------------------------------------
  // Password hashing primitives
  // ---------------------------------------------------------------------------

  async function hashPbkdf2(password, hashName, iterations, dkLen, salt) {
    const key = await subtle().importKey(
      'raw', textEncoder.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await subtle().deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: hashName }, key, dkLen * 8
    );
    return new Uint8Array(bits);
  }

  async function hashScryptRaw(password, salt, N, r, p, dkLen) {
    // scrypt-js v3 exposes an object with .scrypt(password, salt, N, r, p, dkLen) -> Promise
    const lib = global.scrypt && global.scrypt.scrypt ? global.scrypt.scrypt : global.scrypt;
    if (typeof lib !== 'function') throw new Error('The scrypt library is not loaded.');
    return lib(textEncoder.encode(password), salt, N, r, p, dkLen);
  }

  function bcryptLib() {
    const lib = global.dcodeIO && global.dcodeIO.bcrypt ? global.dcodeIO.bcrypt : global.bcrypt;
    if (!lib) throw new Error('The bcrypt library is not loaded.');
    return lib;
  }

  function argon2Lib() {
    if (!global.argon2) throw new Error('The Argon2 library is not loaded.');
    return global.argon2;
  }

  // argon2-browser rejects with library-specific messages on mismatch, so the
  // encoded string is validated first: a well-formed hash that fails verify is
  // a mismatch (false), anything else is a real error. Parameter order inside
  // the PHC string varies between libraries (m,t,p vs m,p,t), so only the
  // overall shape is checked here — the library does the strict parse.
  function assertArgon2Encoded(encoded, variant) {
    const ok = new RegExp(`^\\$argon2${variant}\\$v=\\d+\\$m=\\d+,(?:t=\\d+,p=\\d+|p=\\d+,t=\\d+)\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+$`).test(encoded);
    if (!ok) throw new Error(`Not a recognized Argon2${variant} hash string.`);
  }

  async function verifyArgon2Typed(password, encoded, type, variant) {
    assertArgon2Encoded(encoded, variant);
    try {
      await argon2Lib().verify({ pass: password, encoded, type });
      return true;
    } catch {
      return false;
    }
  }

  let blake2bFn = null;
  async function blake2b(input, outLen) {
    if (!blake2bFn) {
      // Lazy-load blakejs only when Blake2b-KDF is used.
      const mod = await import('https://cdn.jsdelivr.net/npm/blakejs@1.2.1/+esm');
      blake2bFn = mod.blake2b;
    }
    return blake2bFn(input, outLen);
  }

  // Educational Balloon-style construction (NOT the standardized Balloon hash).
  async function balloonDigest(password, salt, space, time) {
    const blocks = new Array(space);
    blocks[0] = await sha('SHA-256', concat(textEncoder.encode(password), salt));
    for (let i = 1; i < space; i++) {
      blocks[i] = await sha('SHA-256', concat(u32le(i), blocks[i - 1]));
    }
    for (let t = 0; t < time; t++) {
      for (let i = 0; i < space; i++) {
        const prev = blocks[(i - 1 + space) % space];
        const other = blocks[(i + 1) % space];
        blocks[i] = await sha('SHA-256', concat(prev, other));
      }
    }
    return sha('SHA-256', concat(u32le(time), blocks[space - 1]));
  }

  // Experimental AE-based construction: PBKDF2-SHA512 key -> AES-GCM over a
  // fixed plaintext with a salt-derived IV -> SHA-512(salt || ciphertext).
  async function aehashDigest(password, salt, ops) {
    const iterations = 100000 * ops;
    const keyMaterial = await hashPbkdf2(password, 'SHA-512', iterations, 64, salt);
    const key = await subtle().importKey('raw', keyMaterial.slice(0, 32), 'AES-GCM', false, ['encrypt']);
    const iv = (await sha('SHA-256', salt)).slice(0, 12);
    const ciphertext = new Uint8Array(await subtle().encrypt(
      { name: 'AES-GCM', iv }, key, textEncoder.encode('aehash-v1')
    ));
    return sha('SHA-512', concat(salt, ciphertext));
  }

  async function blake2bKdfDigest(password, salt, iterations) {
    let state = await blake2b(concat(textEncoder.encode(password), salt), 32);
    for (let i = 0; i < iterations; i++) {
      state = await blake2b(concat(state, u32le(i)), 32);
    }
    return state;
  }

  function concat(...parts) {
    const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const p of parts) { bytes.set(p, offset); offset += p.length; }
    return bytes;
  }

  function u32le(value) {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
  }

  // ---------------------------------------------------------------------------
  // Algorithm registry
  // ---------------------------------------------------------------------------

  const ALGORITHMS = [
    {
      id: 'argon2id', label: 'Argon2id', group: 'Recommended',
      note: 'First choice for new password storage (OWASP).',
      params: [
        { id: 'time', label: 'Iterations (t)', type: 'number', min: 1, max: 10, step: 1, value: 3 },
        { id: 'mem', label: 'Memory (KiB)', type: 'number', min: 8192, max: 1048576, step: 1024, value: 65536 },
        { id: 'parallelism', label: 'Parallelism (p)', type: 'number', min: 1, max: 8, step: 1, value: 1 },
      ],
      async hash(password, p) {
        const result = await argon2Lib().hash({
          pass: password,
          salt: randomBytes(16),
          time: p.time, mem: p.mem, parallelism: p.parallelism,
          hashLen: 32,
          type: argon2Lib().ArgonType.Argon2id,
        });
        return result.encoded;
      },
      async verify(password, encoded) {
        return verifyArgon2Typed(password, encoded, argon2Lib().ArgonType.Argon2id, 'id');
      },
      detect: (h) => h.startsWith('$argon2id$'),
    },
    {
      id: 'scrypt', label: 'scrypt', group: 'Recommended',
      note: 'Memory-hard KDF; strong alternative to Argon2.',
      params: [
        { id: 'logN', label: 'N (2^)', type: 'select', options: ['14', '15', '16', '17', '18'], value: '15' },
        { id: 'r', label: 'Block size (r)', type: 'number', min: 1, max: 32, step: 1, value: 8 },
        { id: 'p', label: 'Parallelism (p)', type: 'number', min: 1, max: 16, step: 1, value: 1 },
      ],
      async hash(password, p) {
        const N = 2 ** Number(p.logN);
        const salt = randomBytes(16);
        const key = await hashScryptRaw(password, salt, N, p.r, p.p, 32);
        return `$scrypt$ln=${p.logN},r=${p.r},p=${p.p}$${toB64(salt)}$${toB64(key)}`;
      },
      async verify(password, encoded) {
        const m = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(encoded);
        if (!m) throw new Error('Not a recognized scrypt hash string.');
        const key = await hashScryptRaw(password, fromB64(m[4]), 2 ** Number(m[1]), Number(m[2]), Number(m[3]), m[5].length * 6 / 8 | 0);
        return constantTimeEqual(key, fromB64(m[5]));
      },
      detect: (h) => h.startsWith('$scrypt$'),
    },
    {
      id: 'bcrypt', label: 'bcrypt', group: 'Recommended',
      note: 'Widely supported legacy-compatible choice.',
      params: [
        { id: 'rounds', label: 'Cost (salt rounds)', type: 'number', min: 4, max: 15, step: 1, value: 12 },
      ],
      async hash(password, p) {
        return bcryptLib().hashSync(password, bcryptLib().genSaltSync(Number(p.rounds)));
      },
      async verify(password, encoded) {
        return bcryptLib().compareSync(password, encoded);
      },
      detect: (h) => /^\$2[aby]\$/.test(h),
    },
    {
      id: 'pbkdf2-sha256', label: 'PBKDF2-HMAC-SHA256', group: 'Recommended',
      note: 'FIPS-friendly default when PBKDF2 is required.',
      params: [
        { id: 'iterations', label: 'Iterations', type: 'number', min: 100000, max: 5000000, step: 50000, value: 600000 },
      ],
      async hash(password, p) {
        const salt = randomBytes(16);
        const key = await hashPbkdf2(password, 'SHA-256', p.iterations, 32, salt);
        return `$pbkdf2-sha256$${p.iterations}$${toB64(salt)}$${toB64(key)}`;
      },
      async verify(password, encoded) { return verifyPbkdf2Generic(password, encoded, 'SHA-256'); },
      detect: (h) => h.startsWith('$pbkdf2-sha256$'),
    },
    {
      id: 'argon2d', label: 'Argon2d', group: 'More Argon2 variants',
      note: 'Faster, but data-dependent memory access (side-channel sensitive).',
      params: [
        { id: 'time', label: 'Iterations (t)', type: 'number', min: 1, max: 10, step: 1, value: 3 },
        { id: 'mem', label: 'Memory (KiB)', type: 'number', min: 8192, max: 1048576, step: 1024, value: 65536 },
        { id: 'parallelism', label: 'Parallelism (p)', type: 'number', min: 1, max: 8, step: 1, value: 1 },
      ],
      async hash(password, p) {
        const result = await argon2Lib().hash({
          pass: password, salt: randomBytes(16),
          time: p.time, mem: p.mem, parallelism: p.parallelism, hashLen: 32,
          type: argon2Lib().ArgonType.Argon2d,
        });
        return result.encoded;
      },
      async verify(password, encoded) {
        return verifyArgon2Typed(password, encoded, argon2Lib().ArgonType.Argon2d, 'd');
      },
      detect: (h) => h.startsWith('$argon2d$'),
    },
    {
      id: 'argon2i', label: 'Argon2i', group: 'More Argon2 variants',
      note: 'Data-independent access; preferred where side-channel resistance matters.',
      params: [
        { id: 'time', label: 'Iterations (t)', type: 'number', min: 1, max: 10, step: 1, value: 3 },
        { id: 'mem', label: 'Memory (KiB)', type: 'number', min: 8192, max: 1048576, step: 1024, value: 65536 },
        { id: 'parallelism', label: 'Parallelism (p)', type: 'number', min: 1, max: 8, step: 1, value: 1 },
      ],
      async hash(password, p) {
        const result = await argon2Lib().hash({
          pass: password, salt: randomBytes(16),
          time: p.time, mem: p.mem, parallelism: p.parallelism, hashLen: 32,
          type: argon2Lib().ArgonType.Argon2i,
        });
        return result.encoded;
      },
      async verify(password, encoded) {
        return verifyArgon2Typed(password, encoded, argon2Lib().ArgonType.Argon2i, 'i');
      },
      detect: (h) => h.startsWith('$argon2i$'),
    },
    {
      id: 'pbkdf2-sha384', label: 'PBKDF2-HMAC-SHA384', group: 'More KDF variants',
      note: 'Intermediate digest size, sometimes required by policy.',
      params: [
        { id: 'iterations', label: 'Iterations', type: 'number', min: 100000, max: 5000000, step: 50000, value: 600000 },
      ],
      async hash(password, p) {
        const salt = randomBytes(16);
        const key = await hashPbkdf2(password, 'SHA-384', p.iterations, 48, salt);
        return `$pbkdf2-sha384$${p.iterations}$${toB64(salt)}$${toB64(key)}`;
      },
      async verify(password, encoded) { return verifyPbkdf2Generic(password, encoded, 'SHA-384'); },
      detect: (h) => h.startsWith('$pbkdf2-sha384$'),
    },
    {
      id: 'pbkdf2-sha512', label: 'PBKDF2-HMAC-SHA512', group: 'More KDF variants',
      note: 'Largest digest size of the standard PBKDF2 family.',
      params: [
        { id: 'iterations', label: 'Iterations', type: 'number', min: 100000, max: 5000000, step: 50000, value: 600000 },
      ],
      async hash(password, p) {
        const salt = randomBytes(16);
        const key = await hashPbkdf2(password, 'SHA-512', p.iterations, 64, salt);
        return `$pbkdf2-sha512$${p.iterations}$${toB64(salt)}$${toB64(key)}`;
      },
      async verify(password, encoded) { return verifyPbkdf2Generic(password, encoded, 'SHA-512'); },
      detect: (h) => h.startsWith('$pbkdf2-sha512$'),
    },
    {
      id: 'balloon', label: 'Balloon-style (educational)', group: 'Educational / experimental',
      note: 'Teaching aid only — NOT the standardized Balloon hash and not reviewed. Do not use in production.',
      params: [
        { id: 'space', label: 'Space (blocks)', type: 'number', min: 64, max: 2048, step: 64, value: 1024 },
        { id: 'time', label: 'Time (passes)', type: 'number', min: 1, max: 10, step: 1, value: 3 },
      ],
      async hash(password, p) {
        const salt = randomBytes(16);
        const digest = await balloonDigest(password, salt, p.space, p.time);
        return `$balloon$s=${p.space},t=${p.time}$${toB64(salt)}$${toB64(digest)}`;
      },
      async verify(password, encoded) {
        const m = /^\$balloon\$s=(\d+),t=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(encoded);
        if (!m) throw new Error('Not a recognized balloon-style hash string.');
        const digest = await balloonDigest(password, fromB64(m[3]), Number(m[1]), Number(m[2]));
        return constantTimeEqual(digest, fromB64(m[4]));
      },
      detect: (h) => h.startsWith('$balloon$'),
    },
    {
      id: 'aehash', label: 'aehash (experimental)', group: 'Educational / experimental',
      note: 'Experimental AE-based construction. Not a standard; do not use in production.',
      params: [
        { id: 'ops', label: 'Operations (passes)', type: 'number', min: 1, max: 10, step: 1, value: 3 },
      ],
      async hash(password, p) {
        const salt = randomBytes(16);
        const digest = await aehashDigest(password, salt, p.ops);
        return `$aehash$o=${p.ops}$${toB64(salt)}$${toB64(digest)}`;
      },
      async verify(password, encoded) {
        const m = /^\$aehash\$o=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(encoded);
        if (!m) throw new Error('Not a recognized aehash hash string.');
        const digest = await aehashDigest(password, fromB64(m[2]), Number(m[1]));
        return constantTimeEqual(digest, fromB64(m[3]));
      },
      detect: (h) => h.startsWith('$aehash$'),
    },
    {
      id: 'blake2b-kdf', label: 'Blake2b-KDF (educational)', group: 'Educational / experimental',
      note: 'Simple iterated Blake2b KDF via blakejs. Not a standard password hash; do not use in production.',
      params: [
        { id: 'iterations', label: 'Iterations', type: 'number', min: 1, max: 20, step: 1, value: 4 },
      ],
      async hash(password, p) {
        const salt = randomBytes(16);
        const digest = await blake2bKdfDigest(password, salt, p.iterations);
        return `$blake2b-kdf$i=${p.iterations}$${toB64(salt)}$${toB64(digest)}`;
      },
      async verify(password, encoded) {
        const m = /^\$blake2b-kdf\$i=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(encoded);
        if (!m) throw new Error('Not a recognized blake2b-kdf hash string.');
        const digest = await blake2bKdfDigest(password, fromB64(m[2]), Number(m[1]));
        return constantTimeEqual(digest, fromB64(m[3]));
      },
      detect: (h) => h.startsWith('$blake2b-kdf$'),
    },
  ];

  async function verifyPbkdf2Generic(password, encoded, hashName) {
    const shortName = hashName.toLowerCase().replace('-', ''); // 'SHA-256' -> 'sha256' (passlib naming)
    const m = new RegExp(`^\\$pbkdf2-${shortName}\\$(\\d+)\\$([A-Za-z0-9+/]+)\\$([A-Za-z0-9+/]+)$`).exec(encoded);
    if (!m) throw new Error(`Not a recognized PBKDF2-${shortName} hash string.`);
    const salt = fromB64(m[2]);
    const expected = fromB64(m[3]);
    const derived = await hashPbkdf2(password, hashName, Number(m[1]), expected.length, salt);
    return constantTimeEqual(derived, expected);
  }

  function detectAlgorithm(encoded) {
    return ALGORITHMS.find((a) => a.detect(encoded.trim())) || null;
  }

  // ---------------------------------------------------------------------------
  // Text encryption (AES-256-GCM, PBKDF2-SHA256 key derivation)
  // ---------------------------------------------------------------------------

  async function deriveAesKey(password, salt, iterations) {
    const material = await hashPbkdf2(password, 'SHA-256', iterations, 32, salt);
    return subtle().importKey('raw', material, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async function encryptText(password, plaintext, iterations) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveAesKey(password, salt, iterations);
    const ciphertext = new Uint8Array(await subtle().encrypt(
      { name: 'AES-GCM', iv }, key, textEncoder.encode(plaintext)
    ));
    return `enc-v1$pbkdf2-sha256$i=${iterations}$${toB64(salt)}$${toB64(iv)}$${toB64(ciphertext)}`;
  }

  async function decryptText(password, encoded) {
    const m = /^enc-v1\$pbkdf2-sha256\$i=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(encoded.trim());
    if (!m) throw new Error('Not a recognized encrypted string (expected enc-v1 format).');
    const key = await deriveAesKey(password, fromB64(m[2]), Number(m[1]));
    const plaintext = await subtle().decrypt(
      { name: 'AES-GCM', iv: fromB64(m[3]) }, key, fromB64(m[4])
    );
    return textDecoder.decode(plaintext);
  }

  // ---------------------------------------------------------------------------
  // HMAC (message authentication, NOT password storage)
  // ---------------------------------------------------------------------------

  async function computeHmac(secret, message, hashName) {
    const key = await subtle().importKey(
      'raw', textEncoder.encode(secret), { name: 'HMAC', hash: hashName }, false, ['sign']
    );
    const mac = await subtle().sign('HMAC', key, textEncoder.encode(message));
    return toHex(mac);
  }

  // ---------------------------------------------------------------------------
  // Exports (for Node-based tests)
  // ---------------------------------------------------------------------------

  global.PhtCore = {
    ALGORITHMS, detectAlgorithm, encryptText, decryptText, computeHmac,
    utils: { toHex, toB64, fromB64, constantTimeEqual, randomBytes },
    // Test hook: lets Node tests inject a local blake2b (browsers lazy-load the ESM bundle).
    _setBlake2b(fn) { blake2bFn = fn; },
  };

  // ---------------------------------------------------------------------------
  // UI wiring (browser only)
  // ---------------------------------------------------------------------------

  if (typeof document === 'undefined') return;

  const $ = (id) => document.getElementById(id);

  const form = $('tool-form');
  const operationSelect = $('operation');
  const operationNote = $('operation-note');
  const parametersField = $('parameters');
  const parametersLegend = $('parameters-legend');
  const passwordField = $('field-password');
  const passwordInput = $('password');
  const togglePasswordButton = $('toggle-password');
  const secretField = $('field-secret');
  const hmacSecret = $('hmac-secret');
  const textField = $('field-text');
  const textLabel = $('text-label');
  const textInput = $('text-input');
  const message = $('message');
  const actionButton = $('action');
  const resultSection = $('result-section');
  const resultTitle = $('result-title');
  const output = $('output');
  const copyButton = $('copy');
  const verifyForm = $('verify-form');
  const verifyHashInput = $('verify-hash');
  const verifyDetected = $('verify-detected');
  const verifyPasswordInput = $('verify-password');
  const verifyMessage = $('verify-message');
  const verifyButton = $('verify');
  const verifyResult = $('verify-result');
  const themeToggle = $('theme-toggle');
  const themeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

  const ACTION_LABELS = {
    hash: 'Generate hash',
    encrypt: 'Encrypt text',
    decrypt: 'Decrypt text',
    hmac: 'Compute HMAC',
  };

  const RESULT_TITLES = {
    hash: 'Password hash',
    hmac: 'HMAC tag',
  };

  // --- operation registry: one combobox drives the whole card ----------------

  const UTILITY_OPERATIONS = [
    {
      kind: 'encrypt', id: 'encrypt', label: 'Encrypt text (AES-256-GCM)', group: 'Password utilities',
      note: 'AES-256-GCM with a PBKDF2-SHA256-derived key. Reversible with the same password.',
      params: [
        { id: 'iterations', label: 'PBKDF2 iterations', type: 'number', min: 100000, max: 5000000, step: 50000, value: 600000 },
      ],
    },
    {
      kind: 'decrypt', id: 'decrypt', label: 'Decrypt text (AES-256-GCM)', group: 'Password utilities',
      note: 'Paste an enc-v1 string and enter the password it was encrypted with.',
    },
    {
      kind: 'hmac', id: 'hmac', label: 'Compute HMAC', group: 'Message authentication',
      note: 'Keyed message authentication — not a password storage method.',
      params: [
        { id: 'hash', label: 'Hash function', type: 'select', options: ['SHA-256', 'SHA-384', 'SHA-512'], value: 'SHA-256' },
      ],
    },
  ];

  const OPERATIONS = [
    ...ALGORITHMS.map((a) => ({ kind: 'hash', id: a.id, label: a.label, group: a.group, note: a.note, params: a.params })),
    ...UTILITY_OPERATIONS,
  ];

  function currentOperation() {
    return OPERATIONS.find((o) => o.id === operationSelect.value);
  }

  // --- theme -----------------------------------------------------------------

  function resolveTheme(preference) {
    return preference === 'system' ? (themeMediaQuery.matches ? 'dark' : 'light') : preference;
  }

  function applyTheme(preference, persist = false) {
    const theme = resolveTheme(preference);
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.themePreference = preference;
    const isDark = theme === 'dark';
    themeToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    themeToggle.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    if (persist) localStorage.setItem('theme-preference', preference);
  }

  applyTheme(localStorage.getItem('theme-preference') || 'system');
  themeToggle.addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark', true));
  themeMediaQuery.addEventListener('change', () => {
    if ((localStorage.getItem('theme-preference') || 'system') === 'system') applyTheme('system');
  });

  // --- shared helpers ----------------------------------------------------------

  function setMessage(element, text, isError = false) {
    element.textContent = text;
    element.classList.toggle('error', isError);
  }

  async function copyToClipboard(button, textarea) {
    try {
      await navigator.clipboard.writeText(textarea.value);
      button.textContent = 'Copied';
      window.setTimeout(() => { button.textContent = 'Copy'; }, 1800);
    } catch {
      textarea.focus();
      textarea.select();
    }
  }

  // --- combobox + dynamic form ---------------------------------------------------

  for (const group of [...new Set(OPERATIONS.map((o) => o.group))]) {
    const optgroup = document.createElement('optgroup');
    optgroup.label = group;
    for (const operation of OPERATIONS.filter((o) => o.group === group)) {
      const option = document.createElement('option');
      option.value = operation.id;
      option.textContent = operation.label;
      optgroup.appendChild(option);
    }
    operationSelect.appendChild(optgroup);
  }

  function renderParameters(operation) {
    const grid = $('parameter-grid');
    grid.replaceChildren();
    if (!operation.params) {
      parametersField.hidden = true;
      return;
    }
    parametersField.hidden = false;
    parametersLegend.textContent = `${operation.label} parameters`;
    for (const param of operation.params) {
      const label = document.createElement('label');
      label.textContent = param.label + ' ';
      let input;
      if (param.type === 'select') {
        input = document.createElement('select');
        for (const value of param.options) {
          const option = document.createElement('option');
          option.value = value;
          option.textContent = value;
          input.appendChild(option);
        }
        input.value = param.value;
      } else {
        input = document.createElement('input');
        input.type = 'number';
        input.min = param.min;
        input.max = param.max;
        input.step = param.step;
        input.value = param.value;
      }
      input.id = `param-${param.id}`;
      input.required = true;
      label.appendChild(input);
      grid.appendChild(label);
    }
  }

  function renderOperation(operation) {
    renderParameters(operation);
    operationNote.textContent = operation.note || '';

    passwordField.hidden = operation.kind === 'hmac';
    secretField.hidden = operation.kind !== 'hmac';

    const usesText = operation.kind === 'encrypt' || operation.kind === 'decrypt' || operation.kind === 'hmac';
    textField.hidden = !usesText;
    textLabel.textContent = operation.kind === 'encrypt'
      ? 'Text to encrypt'
      : operation.kind === 'decrypt' ? 'Encrypted string (enc-v1)' : 'Message';

    actionButton.textContent = ACTION_LABELS[operation.kind];
    resultTitle.textContent = RESULT_TITLES[operation.kind] || 'Result';

    resultSection.hidden = true;
    output.value = '';
    setMessage(message, 'Ready. Everything runs locally in your browser.');
  }

  operationSelect.addEventListener('change', () => renderOperation(currentOperation()));
  renderOperation(currentOperation());

  function readParameters(operation) {
    const values = {};
    for (const param of operation.params) {
      const input = $(`param-${param.id}`);
      const raw = param.type === 'select' ? input.value : Number(input.value);
      if (param.type !== 'select' && (!Number.isFinite(raw) || raw < param.min || raw > param.max)) {
        throw new Error(`${param.label} must be between ${param.min} and ${param.max}.`);
      }
      values[param.id] = raw;
    }
    return values;
  }

  // --- field helpers -------------------------------------------------------------

  togglePasswordButton.addEventListener('click', () => {
    const showing = passwordInput.type === 'text';
    passwordInput.type = showing ? 'password' : 'text';
    togglePasswordButton.textContent = showing ? 'Show' : 'Hide';
    togglePasswordButton.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  });

  verifyHashInput.addEventListener('input', () => {
    const algorithm = detectAlgorithm(verifyHashInput.value);
    verifyDetected.textContent = algorithm ? `Detected: ${algorithm.label}` : '';
  });
  // --- submit --------------------------------------------------------------------

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    resultSection.hidden = true;
    output.value = '';

    const operation = currentOperation();
    const password = passwordInput.value;

    const start = (busyLabel) => {
      actionButton.disabled = true;
      actionButton.textContent = busyLabel;
      setMessage(message, 'Working locally in your browser…');
    };

    try {
      if (operation.kind === 'hash') {
        if (password.length < 12) {
          setMessage(message, 'Use a password with at least 12 characters.', true);
          return;
        }
        const algorithm = ALGORITHMS.find((a) => a.id === operation.id);
        const params = readParameters(operation);
        start('Hashing…');
        output.value = await algorithm.hash(password, params);
        resultSection.hidden = false;
        setMessage(message, 'Hash generated.');
      } else if (operation.kind === 'encrypt') {
        if (!password || !textInput.value) {
          setMessage(message, 'Enter a password and some text.', true);
          return;
        }
        const params = readParameters(operation);
        start('Encrypting…');
        output.value = await encryptText(password, textInput.value, params.iterations);
        resultSection.hidden = false;
        setMessage(message, 'Text encrypted.');
      } else if (operation.kind === 'decrypt') {
        if (!password || !textInput.value) {
          setMessage(message, 'Enter a password and an encrypted string.', true);
          return;
        }
        start('Decrypting…');
        output.value = await decryptText(password, textInput.value);
        resultSection.hidden = false;
        setMessage(message, 'Text decrypted.');
      } else if (operation.kind === 'hmac') {
        if (!hmacSecret.value || !textInput.value) {
          setMessage(message, 'Enter both a secret key and a message.', true);
          return;
        }
        const params = readParameters(operation);
        start('Computing…');
        output.value = await computeHmac(hmacSecret.value, textInput.value, params.hash);
        resultSection.hidden = false;
        setMessage(message, 'HMAC computed.');
      }
    } catch (error) {
      if (error && error.name === 'OperationError') {
        setMessage(message, 'Decryption failed — wrong password or corrupted string.', true);
      } else {
        console.error(error);
        setMessage(message, `Operation failed: ${error.message}`, true);
      }
    } finally {
      passwordInput.value = '';
      hmacSecret.value = '';
      actionButton.disabled = false;
      actionButton.textContent = ACTION_LABELS[operation.kind];
    }
  });

  // --- verify section (always visible) ------------------------------------------

  verifyForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    verifyResult.hidden = true;
    verifyResult.className = 'verify-outcome';

    const encoded = verifyHashInput.value.trim();
    const password = verifyPasswordInput.value;
    if (!encoded || !password) {
      setMessage(verifyMessage, 'Enter both a hash and a password.', true);
      return;
    }
    const algorithm = detectAlgorithm(encoded);
    if (!algorithm) {
      setMessage(verifyMessage, 'Unrecognized hash format. Supported: Argon2, bcrypt, scrypt, PBKDF2, and this tool\'s educational formats.', true);
      return;
    }

    verifyButton.disabled = true;
    verifyButton.textContent = 'Verifying…';
    setMessage(verifyMessage, `Verifying with ${algorithm.label}…`);

    try {
      const valid = await algorithm.verify(password, encoded);
      verifyResult.hidden = false;
      verifyResult.classList.add(valid ? 'valid' : 'invalid');
      verifyResult.textContent = valid ? 'Valid — the password matches the hash.' : 'Invalid — the password does not match.';
      setMessage(verifyMessage, valid ? 'Verification succeeded.' : 'Verification finished: no match.');
    } catch (error) {
      console.error(error);
      setMessage(verifyMessage, `Verification failed: ${error.message}`, true);
    } finally {
      verifyPasswordInput.value = '';
      verifyButton.disabled = false;
      verifyButton.textContent = 'Verify password';
    }
  });

  copyButton.addEventListener('click', () => copyToClipboard(copyButton, output));
})(typeof self !== 'undefined' ? self : globalThis);
