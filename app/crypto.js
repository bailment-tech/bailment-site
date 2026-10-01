// Bailment / Bailee — shared browser crypto.  ->  Bailee.crypto
// Classic script on purpose: ES modules are blocked over file:// by CORS.
// Load first: <script src="app/crypto.js"></script>. No dependencies, WebCrypto only.
(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};

  // Bailment / Bailee — shared browser crypto.
  // No dependencies. WebCrypto (SubtleCrypto) only. Works in a browser and in node >= 20.
  //
  // Everything here runs on the client. Nothing in this file talks to a network.

  const subtle = globalThis.crypto.subtle;
  const utf8 = new TextEncoder();
  const utf8d = new TextDecoder();

  /* ------------------------------------------------------------------ bytes */

  function bytes(x) {
    if (x instanceof Uint8Array) return x;
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
    if (typeof x === 'string') return utf8.encode(x);
    throw new TypeError('expected bytes or string');
  }

  function concat(...parts) {
    const arrs = parts.map(bytes);
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }

  function hex(b) {
    return Array.from(bytes(b), (v) => v.toString(16).padStart(2, '0')).join('');
  }

  function unhex(s) {
    const t = String(s).replace(/[^0-9a-fA-F]/g, '');
    if (t.length % 2) throw new Error('odd-length hex');
    const out = new Uint8Array(t.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
    return out;
  }

  function b64url(b) {
    const a = bytes(b);
    let s = '';
    for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function unb64url(s) {
    const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
    const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
    const raw = atob(t + pad);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function utf8Decode(b) { return utf8d.decode(bytes(b)); }

  function equalBytes(a, b) {
    const x = bytes(a), y = bytes(b);
    if (x.length !== y.length) return false;
    let d = 0;
    for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
    return d === 0;
  }

  /* --------------------------------------------------------------- hashing */

  async function sha256(b) {
    return new Uint8Array(await subtle.digest('SHA-256', bytes(b)));
  }

  function randomNonce(len = 32) {
    return globalThis.crypto.getRandomValues(new Uint8Array(len));
  }

  // Deterministic JSON: object keys sorted, no whitespace. This is what gets signed,
  // so both sides must serialise the same way.
  //
  // Strict on purpose (C-13). This function decides which bytes get signed, so a value
  // it cannot represent exactly throws instead of silently encoding as `{}`, `null` or a
  // hole. Representable: null, boolean, finite number, string, array, plain object.
  // Not representable: Date, Map, Set, typed array, class instance, function, symbol,
  // bigint, NaN, Infinity, undefined (top level or inside an array).
  // An object property whose value is `undefined` is dropped, exactly as JSON.stringify
  // drops it, so the key is simply absent on both sides.
  function canonical(value, path = '$') {
    const t = typeof value;
    if (value === null || t === 'boolean' || t === 'string') return JSON.stringify(value);
    if (t === 'number') {
      if (!Number.isFinite(value)) throw new TypeError('canonical: ' + String(value) + ' is not representable at ' + path);
      return JSON.stringify(value);
    }
    if (t !== 'object') throw new TypeError('canonical: ' + (t === 'undefined' ? 'undefined' : t) + ' is not representable at ' + path);
    if (Array.isArray(value)) {
      const parts = [];
      for (let i = 0; i < value.length; i++) {
        if (!(i in value)) throw new TypeError('canonical: array hole is not representable at ' + path + '[' + i + ']');
        parts.push(canonical(value[i], path + '[' + i + ']'));
      }
      return '[' + parts.join(',') + ']';
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      const name = (value.constructor && value.constructor.name) || 'non-plain object';
      throw new TypeError('canonical: ' + name + ' is not representable at ' + path);
    }
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k], path + '.' + k)).join(',') + '}';
  }

  async function digestJSON(value) { return sha256(canonical(value)); }

  /* ------------------------------------------------------------ commitment */

  // Domain separator. Mirrors persistentCommit() in the Compact contracts: the nonce is
  // a salt, so a low-entropy document (a one-page form, a known template) cannot be
  // brute-forced back out of the published commitment.
  //
  // v2 (C-02). v1 was SHA-256( domain || nonce || content ) over two variable-length
  // fields, so commit(prefix || body, N) === commit(body, N || prefix): the party that
  // chose the nonce could open one commitment to two different documents (add or drop a
  // leading "VOID - DO NOT FILE." caption and both readings verified). v2 makes every
  // field after the fixed literal domain fixed width, which is self-delimiting, and
  // commits to the document digest exactly as document_record.compact does. The domain
  // string carries the version so a v1 and a v2 commitment can never be confused.
  const COMMIT_DOMAIN = 'bailment.tech:persistentCommit:v2';
  const COMMIT_NONCE_BYTES = 32;

  // commit(content, nonce) = SHA-256( domain || ':' || nonce[32] || SHA-256(content)[32] )
  async function commit(content, nonce) {
    const n = bytes(nonce);
    if (n.length !== COMMIT_NONCE_BYTES) {
      throw new Error('nonce must be exactly ' + COMMIT_NONCE_BYTES + ' bytes, got ' + n.length);
    }
    return sha256(concat(utf8.encode(COMMIT_DOMAIN + ':'), n, await sha256(bytes(content))));
  }

  // Anyone given (content, nonce) can re-derive the commitment and check it. Symmetric
  // with commit(): a nonce that is not exactly 32 bytes cannot have produced any v2
  // commitment, so it verifies false rather than throwing into a verifier's UI. Creating
  // a commitment is where a bad nonce is loud; checking one is a verdict, not a mistake.
  async function verifyCommit(content, nonce, expected) {
    try { return equalBytes(await commit(content, nonce), bytes(expected)); }
    catch { return false; }
  }

  /* --------------------------------------------------------------- merkle */

  // Domain-separated leaf / node hashing (0x00 / 0x01) so a node hash can never be
  // replayed as a leaf. Odd nodes are promoted to the next level, never duplicated.
  const LEAF = new Uint8Array([0x00]);
  const NODE = new Uint8Array([0x01]);

  async function merkleLeaf(leaf) { return sha256(concat(LEAF, leaf)); }
  async function merkleNode(l, r) { return sha256(concat(NODE, l, r)); }

  async function levels(leaves) {
    if (!leaves.length) throw new Error('merkle: no leaves');
    let level = [];
    for (const l of leaves) level.push(await merkleLeaf(l));
    const all = [level];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(i + 1 < level.length ? await merkleNode(level[i], level[i + 1]) : level[i]);
      }
      level = next;
      all.push(level);
    }
    return all;
  }

  async function merkleRoot(leaves) {
    const all = await levels(leaves);
    return all[all.length - 1][0];
  }

  // Read one sibling path out of an already-built level structure. No hashing.
  function proofFromLevels(all, index) {
    const proof = [];
    let i = index;
    for (let d = 0; d < all.length - 1; d++) {
      const level = all[d];
      const sib = i ^ 1;
      if (sib < level.length) {
        proof.push({ side: sib < i ? 'left' : 'right', hash: level[sib] });
      }
      i = Math.floor(i / 2);
    }
    return proof;
  }

  // Returns [{ side: 'left' | 'right', hash: Uint8Array }] — `side` is where the
  // sibling sits relative to the node being carried up.
  //
  // Note (C-06): the number of steps varies with the batch size and with the leaf
  // index, because an odd node is promoted rather than duplicated. A proof therefore
  // tells its holder roughly how many leaves the tree had. The published root does not.
  async function merkleProof(leaves, index) {
    if (index < 0 || index >= leaves.length) throw new Error('merkle: index out of range');
    return proofFromLevels(await levels(leaves), index);
  }

  // Every proof, from ONE pass over the tree: merkleProofs(leaves)[i] === merkleProof(leaves, i).
  // merkleProof() rebuilds all levels per call, so calling it inside a per-leaf loop is
  // O(n^2) hashes (APPSEC-02: 13.4 s at 400 claims, auto-run from a URL fragment).
  async function merkleProofs(leaves) {
    const all = await levels(leaves);
    return leaves.map((_, i) => proofFromLevels(all, i));
  }

  async function verifyProof(leaf, proof, root) {
    let h = await merkleLeaf(leaf);
    for (const step of proof) {
      const sib = bytes(step.hash);
      h = step.side === 'left' ? await merkleNode(sib, h) : await merkleNode(h, sib);
    }
    return equalBytes(h, bytes(root));
  }

  /* -------------------------------------------------- ECDSA P-256 (signing) */

  const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
  const ECDSA_SHA = { name: 'ECDSA', hash: 'SHA-256' };

  async function generateSigningKey() {
    return subtle.generateKey(ECDSA, true, ['sign', 'verify']);
  }

  async function sign(privateKey, message) {
    return new Uint8Array(await subtle.sign(ECDSA_SHA, privateKey, bytes(message)));
  }

  async function verify(publicKey, signature, message) {
    return subtle.verify(ECDSA_SHA, publicKey, bytes(signature), bytes(message));
  }

  // Public keys travel as base64url SPKI. Private keys never travel, but export
  // exists so a demo can round-trip one inside the same browser.
  async function exportPublicKey(key) {
    return b64url(new Uint8Array(await subtle.exportKey('spki', key)));
  }

  async function importPublicKey(s) {
    return subtle.importKey('spki', unb64url(s), ECDSA, true, ['verify']);
  }

  async function exportPrivateKey(key) {
    return b64url(new Uint8Array(await subtle.exportKey('pkcs8', key)));
  }

  async function importPrivateKey(s) {
    return subtle.importKey('pkcs8', unb64url(s), ECDSA, true, ['sign']);
  }

  // Sign / verify a JSON value using the canonical form.
  async function signJSON(privateKey, value) {
    return b64url(await sign(privateKey, canonical(value)));
  }

  async function verifyJSON(publicKey, signatureB64, value) {
    try { return await verify(publicKey, unb64url(signatureB64), canonical(value)); }
    catch { return false; }
  }

  // Short, human-readable fingerprint of a public key, for reading out or printing.
  async function keyFingerprint(spkiB64) {
    const h = await sha256(unb64url(spkiB64));
    return hex(h.slice(0, 8)).replace(/(.{4})(?=.)/g, '$1 ').toUpperCase();
  }

  /* ------------------------------------- P-256 point compression (32+1 byte) */

  const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

  function modPow(base, exp, m) {
    let r = 1n, b = base % m, e = exp;
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }

  function bigToBytes(v, len = 32) {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }

  function bytesToBig(b) {
    let v = 0n;
    for (const x of bytes(b)) v = (v << 8n) | BigInt(x);
    return v;
  }

  // raw uncompressed point (65 bytes, 0x04 || X || Y) -> 33 bytes (0x02/0x03 || X)
  function compressPoint(raw) {
    const r = bytes(raw);
    if (r.length !== 65 || r[0] !== 0x04) throw new Error('expected 65-byte uncompressed point');
    const y = bytesToBig(r.slice(33));
    return concat(new Uint8Array([(y & 1n) === 1n ? 0x03 : 0x02]), r.slice(1, 33));
  }

  // 33 bytes -> 65 bytes. y = sqrt(x^3 - 3x + b) mod p; p = 3 mod 4 so the square
  // root is a single exponentiation. A mistyped code almost always fails here.
  function decompressPoint(comp) {
    const c = bytes(comp);
    if (c.length !== 33 || (c[0] !== 0x02 && c[0] !== 0x03)) throw new Error('bad compressed point');
    const x = bytesToBig(c.slice(1));
    if (x >= P) throw new Error('bad compressed point: x out of range');
    const y2 = (((x * x % P) * x % P) - 3n * x + B) % P;
    const yy = (y2 + P) % P;
    let y = modPow(yy, (P + 1n) / 4n, P);
    if (y * y % P !== yy) throw new Error('bad compressed point: not on curve');
    if ((y & 1n) !== BigInt(c[0] & 1)) y = P - y;
    return concat(new Uint8Array([0x04]), bigToBytes(x), bigToBytes(y));
  }

  /* ------------------------------------------------- short read-aloud codes */

  // Crockford base32: no I, L, O, U. Safe to read over a phone line.
  const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  // Crockford's five extra check symbols, so a check character can hold 0..36.
  const B32_CHECK = B32 + '*~$=U';

  function base32(b) {
    const a = bytes(b);
    let out = '', buf = 0, bits = 0;
    for (const v of a) {
      buf = (buf << 8) | v; bits += 8;
      while (bits >= 5) { out += B32[(buf >> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits) out += B32[(buf << (5 - bits)) & 31];
    return out;
  }

  // Strict decode (C-12). base32() pads the final character with zero bits, so a decode
  // that finds a non-zero leftover was given a character the encoder could not have
  // produced. Accepting it made the last character malleable: 33 bytes encode to 53
  // characters = 265 bits, one bit more than the key needs, so two codes decoded to the
  // same public key. Rejecting non-canonical padding makes the encoding injective.
  function unbase32(s) {
    const t = String(s).toUpperCase().replace(/[^0-9A-Z]/g, '')
      .replace(/O/g, '0').replace(/[IL]/g, '1');
    const out = [];
    let buf = 0, bits = 0;
    for (const ch of t) {
      const v = B32.indexOf(ch);
      if (v < 0) throw new Error('bad character in code: ' + ch);
      buf = (buf << 5) | v; bits += 5;
      if (bits >= 8) { out.push((buf >> (bits - 8)) & 0xff); bits -= 8; }
    }
    if (bits && (buf & ((1 << bits) - 1)) !== 0) throw new Error('bad code: non-canonical trailing bits');
    return new Uint8Array(out);
  }

  // Crockford check symbol: the encoded value mod 37, as one extra character.
  function checkSymbol(b) {
    let m = 0n;
    for (const v of bytes(b)) m = ((m << 8n) + BigInt(v)) % 37n;
    return B32_CHECK[Number(m)];
  }

  // Codes are read aloud, so accept any spacing or case; map the characters Crockford
  // says are confusable. Punctuation other than the grouping dash is left alone, so a
  // check symbol (* ~ $ = U) survives.
  function normalizeCode(s) {
    return String(s).toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  }

  function groupCode(s, size = 5) {
    return s.replace(new RegExp(`(.{${size}})(?=.)`, 'g'), '$1-');
  }

  /* ------------------------------------ ECDH P-256 + AES-GCM (sealed tier 2) */

  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };

  // The reader runs this in their own browser. The private half never leaves.
  async function generateReaderKey() {
    return subtle.generateKey(ECDH, true, ['deriveBits']);
  }

  // The short public code the reader reads out.
  // 33 bytes -> 53 base32 characters + 1 Crockford check character = 54.
  const READER_CODE_CHARS = 54;

  async function readerCode(publicKey) {
    const raw = new Uint8Array(await subtle.exportKey('raw', publicKey));
    const comp = compressPoint(raw);
    return groupCode(base32(comp) + checkSymbol(comp));
  }

  // Rejects a wrong length before decoding and a single misheard character on the check
  // symbol (C-12), so a bad code says so instead of sealing the attestation to a point
  // nobody holds the private key for.
  async function importReaderCode(code) {
    const t = normalizeCode(code);
    if (t.length !== READER_CODE_CHARS) {
      throw new Error('reader code must be ' + READER_CODE_CHARS + ' characters (53 + 1 check), got ' + t.length);
    }
    const comp = unbase32(t.slice(0, -1));
    if (checkSymbol(comp) !== t.slice(-1)) {
      throw new Error('reader code failed its check character: at least one character is wrong');
    }
    return subtle.importKey('raw', decompressPoint(comp), ECDH, true, []);
  }

  async function aesKeyFrom(privateKey, publicKey, info) {
    const sharedBits = await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
    const ikm = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8.encode(info) },
      ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  const SEAL_INFO = 'bailment.tech:sealed-attestation:v1';

  // Encrypt to the reader's public code. Returns a plain JSON envelope.
  async function seal(plaintext, readerPublicKey) {
    const eph = await subtle.generateKey(ECDH, true, ['deriveBits']);
    const key = await aesKeyFrom(eph.privateKey, readerPublicKey, SEAL_INFO);
    const iv = randomNonce(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes(plaintext)));
    const rawEph = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
    return {
      v: 1,
      alg: 'ECDH-P256+HKDF-SHA256+AES-256-GCM',
      epk: b64url(compressPoint(rawEph)),
      iv: b64url(iv),
      ct: b64url(ct),
    };
  }

  async function unseal(envelope, readerPrivateKey) {
    const eph = await subtle.importKey('raw', decompressPoint(unb64url(envelope.epk)), ECDH, true, []);
    const key = await aesKeyFrom(readerPrivateKey, eph, SEAL_INFO);
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: unb64url(envelope.iv) }, key, unb64url(envelope.ct));
    return new Uint8Array(pt);
  }

  root.Bailee.crypto = { bytes, concat, hex, unhex, b64url, unb64url, utf8Decode, equalBytes, sha256, randomNonce, canonical, digestJSON, COMMIT_DOMAIN, COMMIT_NONCE_BYTES, commit, verifyCommit, merkleLeaf, merkleRoot, merkleProof, merkleProofs, verifyProof, generateSigningKey, sign, verify, exportPublicKey, importPublicKey, exportPrivateKey, importPrivateKey, signJSON, verifyJSON, keyFingerprint, compressPoint, decompressPoint, base32, unbase32, checkSymbol, groupCode, generateReaderKey, READER_CODE_CHARS, readerCode, importReaderCode, SEAL_INFO, seal, unseal };
  // Back-compat aliases for the earlier product names (Baliff, then Bailiff).
  // Safe to delete once nothing uses them.
  root.Bailiff = root.Bailee;
  root.Baliff = root.Bailee;
})(typeof globalThis !== 'undefined' ? globalThis : this);
