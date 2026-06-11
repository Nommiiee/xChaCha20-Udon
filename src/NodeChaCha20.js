/**
 * xchacha20.js  —  Node.js / Browser-compatible
 * ─────────────────────────────────────────────────────────────────────────────
 * XChaCha20 encrypt & decrypt, bit-for-bit compatible with XChaCha20Udon.cs
 *
 * Wire format:  Base64( [24-byte nonce] ∥ [N-byte ciphertext] )
 *
 * Usage:
 *   const { encrypt, decrypt } = require('./xchacha20');
 *   const blob  = encrypt('Hello VRChat!', 'VRChatSecretKey!');
 *   const plain = decrypt(blob, 'VRChatSecretKey!');
 *
 * Requires Node.js ≥ 14  (for crypto.randomBytes)
 * ─────────────────────────────────────────────────────────────────────────────
 */

"use strict";

// ─── Node crypto for nonce only (you may swap for webcrypto if needed) ────────
const nodeCrypto = typeof require !== "undefined" ? require("crypto") : null;

// ═══════════════════════════════════════════════════════════════════════════════
//  PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encrypts a plaintext string using XChaCha20.
 * @param {string} plaintext  - UTF-8 string to encrypt
 * @param {string} password   - password string (matched to UdonSharp DeriveKey)
 * @returns {string}          - Base64-encoded  [24-byte nonce ∥ ciphertext]
 */
function encrypt(plaintext, password) {
  const key = deriveKey(password); // Uint8Array(32)
  const nonce = generateNonce(); // Uint8Array(24)
  const ptBytes = textEncode(plaintext);
  const ctBytes = xchacha20Process(ptBytes, key, nonce, 1);

  const output = new Uint8Array(24 + ctBytes.length);
  output.set(nonce, 0);
  output.set(ctBytes, 24);
  return base64Encode(output);
}

/**
 * Decrypts a Base64 blob produced by encrypt() or XChaCha20Udon.cs Encrypt().
 * @param {string} cipherBase64 - Base64-encoded [24-byte nonce ∥ ciphertext]
 * @param {string} password     - same password used to encrypt
 * @returns {string}            - original plaintext, or '' on bad input
 */
function decrypt(cipherBase64, password) {
  const raw = base64Decode(cipherBase64);
  if (!raw || raw.length < 24) return "";

  const key = deriveKey(password);
  const nonce = raw.slice(0, 24);
  const ctBytes = raw.slice(24);

  const ptBytes = xchacha20Process(ctBytes, key, nonce, 1);
  return textDecode(ptBytes);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  XCHACHA20  —  draft-irtf-cfrg-xchacha §2.3
// ═══════════════════════════════════════════════════════════════════════════════

function xchacha20Process(data, key, nonce24, initialCounter) {
  // Step 1 – HChaCha20 subkey from key + nonce[0..15]
  const subKey = hchacha20(key, nonce24.slice(0, 16));

  // Step 2 – 12-byte sub-nonce: 4 zero bytes ∥ nonce[16..23]
  const subNonce = new Uint8Array(12);
  subNonce.set(nonce24.slice(16), 4);

  // Step 3 – standard ChaCha20
  return chacha20Process(data, subKey, subNonce, initialCounter);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HCHACHA20  —  draft-irtf-cfrg-xchacha §2.2
// ═══════════════════════════════════════════════════════════════════════════════

function hchacha20(key, nonce16) {
  const state = buildInitialState(key, nonce16, 0);
  // Replace counter words [12] with nonce[0..3], [13] with nonce[4..7]
  // already done by buildInitialState when counter=0 and nonce is only 16 bytes:
  // positions 12-15 hold LE32s of nonce16[0..15]
  // Note: buildInitialState(key, nonce16, counter) sets positions 12=counter,13-15=nonce[0..7]
  // For HChaCha20 we need positions 12-15 = nonce16[0..15], so override:
  state[12] = le32(nonce16, 0);
  state[13] = le32(nonce16, 4);
  state[14] = le32(nonce16, 8);
  state[15] = le32(nonce16, 12);

  const working = chacha20Core20Rounds(new Uint32Array(state));

  // Return words [0..3] ∥ [12..15] — NO add-back
  const out = new Uint8Array(32);
  putLE32(working[0], out, 0);
  putLE32(working[1], out, 4);
  putLE32(working[2], out, 8);
  putLE32(working[3], out, 12);
  putLE32(working[12], out, 16);
  putLE32(working[13], out, 20);
  putLE32(working[14], out, 24);
  putLE32(working[15], out, 28);
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CHACHA20 STREAM CIPHER  —  RFC 8439 §2.4
// ═══════════════════════════════════════════════════════════════════════════════

function chacha20Process(data, key, nonce12, counter) {
  const output = new Uint8Array(data.length);
  let pos = 0;
  // counter is a JS number; use >>> 0 to keep it as uint32
  counter = counter >>> 0;

  while (pos < data.length) {
    const keyStream = chacha20KeystreamBlock(key, nonce12, counter);
    counter = (counter + 1) >>> 0;

    const blockLen = Math.min(64, data.length - pos);
    for (let i = 0; i < blockLen; i++)
      output[pos + i] = data[pos + i] ^ keyStream[i];

    pos += 64;
  }
  return output;
}

function chacha20KeystreamBlock(key, nonce12, counter) {
  const state = new Uint32Array(16);

  // Constants ("expand 32-byte k")
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  // Key (8 × LE32)
  for (let i = 0; i < 8; i++) state[4 + i] = le32(key, i * 4);

  // Counter
  state[12] = counter >>> 0;

  // Nonce (3 × LE32)
  state[13] = le32(nonce12, 0);
  state[14] = le32(nonce12, 4);
  state[15] = le32(nonce12, 8);

  const working = chacha20Core20Rounds(new Uint32Array(state));

  // Add original state back (RFC 8439 §2.3)
  for (let i = 0; i < 16; i++) working[i] = (working[i] + state[i]) >>> 0;

  // Serialise → 64 bytes
  const block = new Uint8Array(64);
  for (let i = 0; i < 16; i++) putLE32(working[i], block, i * 4);
  return block;
}

// ─── 20-round core (in-place on a Uint32Array copy) ──────────────────────────

function chacha20Core20Rounds(s) {
  for (let i = 0; i < 10; i++) {
    qr(s, 0, 4, 8, 12);
    qr(s, 1, 5, 9, 13);
    qr(s, 2, 6, 10, 14);
    qr(s, 3, 7, 11, 15);
    qr(s, 0, 5, 10, 15);
    qr(s, 1, 6, 11, 12);
    qr(s, 2, 7, 8, 13);
    qr(s, 3, 4, 9, 14);
  }
  return s;
}

// ─── Quarter-round (RFC 8439 §2.1) ───────────────────────────────────────────

function qr(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] ^= s[a];
  s[d] = rotl(s[d], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] ^= s[c];
  s[b] = rotl(s[b], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] ^= s[a];
  s[d] = rotl(s[d], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] ^= s[c];
  s[b] = rotl(s[b], 7);
}

function rotl(v, n) {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KEY DERIVATION  —  must exactly mirror XChaCha20Udon.cs DeriveKey()
// ═══════════════════════════════════════════════════════════════════════════════
//

function deriveKey(password) {
  // FNV-1a 64-bit constants
  const FNV_PRIME = BigInt("0x00000100000001B3");
  const FNV_BASIS = BigInt("0xcbf29ce484222325");
  const MASK64 = BigInt("0xFFFFFFFFFFFFFFFF");

  let hash = FNV_BASIS;

  // Pass 1 — forward
  for (let i = 0; i < password.length; i++) {
    const ch = password.charCodeAt(i);
    hash = BigInt.asUintN(64, (hash ^ BigInt(ch & 0xff)) * FNV_PRIME);
    hash = BigInt.asUintN(64, (hash ^ BigInt((ch >> 8) & 0xff)) * FNV_PRIME);
  }

  // Pass 2 — reverse
  for (let i = password.length - 1; i >= 0; i--) {
    const ch = password.charCodeAt(i);
    hash = BigInt.asUintN(64, (hash ^ BigInt(ch & 0xff)) * FNV_PRIME);
    hash = BigInt.asUintN(64, (hash ^ BigInt((ch >> 8) & 0xff)) * FNV_PRIME);
  }

  // Split hash into (hi, lo) uint32 pair matching C# state
  let xhi = Number((hash >> 32n) & 0xffffffffn) >>> 0;
  let xlo = Number(hash & 0xffffffffn) >>> 0;

  const key = new Uint8Array(32);

  for (let chunk = 0; chunk < 4; chunk++) {
    // 128 rounds of Xorshift64
    for (let r = 0; r < 128; r++) {
      [xhi, xlo] = xorshift64(xhi, xlo);
    }

    // Write 8 bytes (matches C# byte layout)
    const off = chunk * 8;
    key[off + 0] = xlo & 0xff;
    key[off + 1] = (xlo >>> 8) & 0xff;
    key[off + 2] = (xlo >>> 16) & 0xff;
    key[off + 3] = (xlo >>> 24) & 0xff;
    key[off + 4] = xhi & 0xff;
    key[off + 5] = (xhi >>> 8) & 0xff;
    key[off + 6] = (xhi >>> 16) & 0xff;
    key[off + 7] = (xhi >>> 24) & 0xff;
  }
  return key;
}

// ─── Xorshift64 (mirrors C# Xorshift64 step-by-step) ────────────────────────

function xorshift64(hi, lo) {
  // << 13
  let newHi = ((hi << 13) | (lo >>> 19)) >>> 0;
  let newLo = (lo << 13) >>> 0;
  hi = (hi ^ newHi) >>> 0;
  lo = (lo ^ newLo) >>> 0;

  // >> 7
  newLo = ((hi << 25) | (lo >>> 7)) >>> 0;
  newHi = (hi >>> 7) >>> 0;
  hi = (hi ^ newHi) >>> 0;
  lo = (lo ^ newLo) >>> 0;

  // << 17
  newHi = ((hi << 17) | (lo >>> 15)) >>> 0;
  newLo = (lo << 17) >>> 0;
  hi = (hi ^ newHi) >>> 0;
  lo = (lo ^ newLo) >>> 0;

  return [hi, lo];
}

// ═══════════════════════════════════════════════════════════════════════════════
//  NONCE GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

function generateNonce() {
  if (nodeCrypto) return nodeCrypto.randomBytes(24);
  // Browser fallback
  const nonce = new Uint8Array(24);
  crypto.getRandomValues(nonce);
  return nonce;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BASE64  (RFC 4648 §4 — matches UdonSharp Base64Encode/Base64Decode)
// ═══════════════════════════════════════════════════════════════════════════════

const B64_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64Encode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i],
      b1 = bytes[i + 1] ?? 0,
      b2 = bytes[i + 2] ?? 0;
    out += B64_CHARS[b0 >> 2];
    out += B64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += B64_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)];
    out += B64_CHARS[b2 & 0x3f];
  }
  const pad = (3 - (bytes.length % 3)) % 3;
  return out.slice(0, out.length - pad) + "=".repeat(pad);
}

function base64Decode(s) {
  s = s.trim().replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let idx = 0;

  for (let i = 0; i < s.length - 1; i += 4) {
    const rem = s.length - i;
    const c0 = B64_CHARS.indexOf(s[i]);
    const c1 = rem > 1 ? B64_CHARS.indexOf(s[i + 1]) : 0;
    const c2 = rem > 2 ? B64_CHARS.indexOf(s[i + 2]) : 0;
    const c3 = rem > 3 ? B64_CHARS.indexOf(s[i + 3]) : 0;
    if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) return null;

    if (idx < out.length) out[idx++] = (c0 << 2) | (c1 >> 4);
    if (idx < out.length) out[idx++] = ((c1 & 0x0f) << 4) | (c2 >> 2);
    if (idx < out.length) out[idx++] = ((c2 & 0x03) << 6) | c3;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STRING ↔ BYTES (UTF-8, mirrors UdonSharp StringToBytes / BytesToString)
// ═══════════════════════════════════════════════════════════════════════════════

function textEncode(str) {
  // TextEncoder is available in Node ≥ 11 and all modern browsers
  return new TextEncoder().encode(str);
}

function textDecode(bytes) {
  return new TextDecoder("utf-8").decode(bytes);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LITTLE-ENDIAN HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function le32(buf, offset) {
  return (
    (buf[offset] |
      (buf[offset + 1] << 8) |
      (buf[offset + 2] << 16) |
      (buf[offset + 3] << 24)) >>>
    0
  );
}

function putLE32(v, buf, offset) {
  buf[offset] = v & 0xff;
  buf[offset + 1] = (v >>> 8) & 0xff;
  buf[offset + 2] = (v >>> 16) & 0xff;
  buf[offset + 3] = (v >>> 24) & 0xff;
}

// ─── (unused directly, kept for buildInitialState reference symmetry) ─────────
function buildInitialState(key, nonce12, counter) {
  const s = new Uint32Array(16);
  s[0] = 0x61707865;
  s[1] = 0x3320646e;
  s[2] = 0x79622d32;
  s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = le32(key, i * 4);
  s[12] = counter >>> 0;
  if (nonce12.length >= 12) {
    s[13] = le32(nonce12, 0);
    s[14] = le32(nonce12, 4);
    s[15] = le32(nonce12, 8);
  }
  return s;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = { encrypt, decrypt };
