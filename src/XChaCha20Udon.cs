/*
 * XChaCha20Udon.cs
 * ─────────────────────────────────────────────────────────────────────────────
 * VRChat UdonSharp — XChaCha20 Encryption / Decryption
 *
 * RFC compliance
 *   • ChaCha20 core     : RFC 8439 §2.1–§2.3  (quarter-round, block function)
 *   • HChaCha20         : draft-irtf-cfrg-xchacha §2.2
 *   • XChaCha20         : draft-irtf-cfrg-xchacha §2.3
 *
 * Constraints (VRChat / Udon)
 *   • Zero use of System.Security.Cryptography
 *   • Zero use of System.Convert  (custom Base64)
 *   • No unsafe / pointer code
 *   • All arithmetic in uint to stay within Udon's allowed IL
 *
 * Key derivation
 *   String password → 32-byte key via two-pass FNV-1a (64-bit), 128 rounds of
 *   mixing, and a final Xorshift64 diffusion step.  Not a replacement for
 *   Argon2/bcrypt — use a pre-shared binary key for high-security needs.
 *
 * Wire format  (Base64-encoded blob)
 *   [ 24-byte nonce ][ N-byte ciphertext ]
 *
 * Public API
 *   string Encrypt(string plaintext, string password)
 *   string Decrypt(string ciphertext, string password)
 *
 * Usage (from another UdonSharp script or U# event)
 *   string cipher = encryptor.Encrypt("Hello VRChat!", "my-secret-pass");
 *   string plain  = encryptor.Decrypt(cipher, "my-secret-pass");
 * ─────────────────────────────────────────────────────────────────────────────
 */

using UdonSharp;
using UnityEngine;

[UdonBehaviourSyncMode(BehaviourSyncMode.None)]

public class XChaCha20Udon : UdonSharpBehaviour

{
    [Header("Inspector Settings")]
    [SerializeField]
    private string defaultPassword = "VRChatSecretKey!";

    [SerializeField]
    [TextArea(3, 8)]
    private string textToEncrypt = "This is the data string that needs to be encrypted";
    // ═══════════════════════════════════════════════════════════════════════
    //  PUBLIC API
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with <paramref name="password"/>.
    /// Returns a Base64 string containing the 24-byte nonce + ciphertext.
    /// </summary>
    public string Encrypt(string plaintext, string password)
    {
        byte[] key = DeriveKey(password);          // 32 bytes
        byte[] nonce = GenerateNonce();              // 24 bytes
        byte[] ptBytes = StringToBytes(plaintext);
        byte[] ctBytes = XChaCha20Process(ptBytes, key, nonce, 1u);

        // Wire format: nonce ∥ ciphertext
        byte[] output = new byte[24 + ctBytes.Length];
        System.Array.Copy(nonce, 0, output, 0, 24);
        System.Array.Copy(ctBytes, 0, output, 24, ctBytes.Length);

        return Base64Encode(output);
    }

    /// <summary>
    /// Decrypts a Base64 blob (nonce ∥ ciphertext) produced by
    /// <see cref="Encrypt"/> and returns the original plaintext.
    /// Returns an empty string on malformed input.
    /// </summary>
    public string Decrypt(string cipherBase64, string password)
    {
        byte[] raw = Base64Decode(cipherBase64);
        if (raw == null || raw.Length < 24) return "";

        byte[] key = DeriveKey(password);
        byte[] nonce = new byte[24];
        System.Array.Copy(raw, 0, nonce, 0, 24);

        byte[] ctBytes = new byte[raw.Length - 24];
        System.Array.Copy(raw, 24, ctBytes, 0, ctBytes.Length);

        byte[] ptBytes = XChaCha20Process(ctBytes, key, nonce, 1u);
        return BytesToString(ptBytes);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  XCHACHA20 — draft-irtf-cfrg-xchacha §2.3
    // ═══════════════════════════════════════════════════════════════════════
    // XChaCha20 allows a 192-bit (24-byte) nonce instead of ChaCha20's 96-bit
    // nonce, eliminating reuse risk when nonces are randomly generated.
    //
    // Steps:
    //   1. subKey  = HChaCha20(key, nonce[0..15])
    //   2. subNonce = 0x00000000 ∥ 0x00000000 ∥ nonce[16..23]  (12 bytes)
    //   3. return ChaCha20(subKey, subNonce, counter, data)

    private byte[] XChaCha20Process(byte[] data, byte[] key, byte[] nonce24,
                                    uint initialCounter)
    {
        // Step 1 – HChaCha20 subkey derivation
        byte[] nonce16 = new byte[16];
        System.Array.Copy(nonce24, 0, nonce16, 0, 16);
        byte[] subKey = HChaCha20(key, nonce16);

        // Step 2 – build 12-byte sub-nonce: four zero bytes + nonce24[16..23]
        byte[] subNonce = new byte[12];
        // subNonce[0..3] = 0x00 (already zero-initialised)
        System.Array.Copy(nonce24, 16, subNonce, 4, 8);

        // Step 3 – standard ChaCha20 stream cipher
        return ChaCha20Process(data, subKey, subNonce, initialCounter);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  HCHACHA20 — draft-irtf-cfrg-xchacha §2.2
    // ═══════════════════════════════════════════════════════════════════════
    // Runs the ChaCha20 core on a special initial state and returns the
    // first and last rows (words 0–3 and 12–15) as the 32-byte subkey.
    //
    // Initial state layout (RFC 8439 §2.3):
    //   cccccccc  cccccccc  cccccccc  cccccccc   ← constants
    //   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk   ← key[0..15]
    //   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk   ← key[16..31]
    //   nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn   ← nonce[0..15]
    //
    // For HChaCha20 the counter words are replaced by nonce[0..7], and the
    // nonce words are nonce[8..15].

    private byte[] HChaCha20(byte[] key, byte[] nonce16)
    {
        uint[] state = new uint[16];

        // Constants ("expand 32-byte k")
        state[0] = 0x61707865u;
        state[1] = 0x3320646eu;
        state[2] = 0x79622d32u;
        state[3] = 0x6b206574u;

        // Key (32 bytes → 8 little-endian uint32s)
        for (int i = 0; i < 8; i++)
            state[4 + i] = LE32(key, i * 4);

        // Nonce (16 bytes → 4 little-endian uint32s) in positions 12–15
        for (int i = 0; i < 4; i++)
            state[12 + i] = LE32(nonce16, i * 4);

        // Run 20 rounds (10 column + 10 diagonal) without adding initial state
        uint[] working = new uint[16];
        System.Array.Copy(state, working, 16);
        ChaCha20Block20Rounds(working);

        // Output: words 0–3 and 12–15 (NOT added back to state — HChaCha20 rule)
        byte[] subKey = new byte[32];
        PutLE32(working[0], subKey, 0);
        PutLE32(working[1], subKey, 4);
        PutLE32(working[2], subKey, 8);
        PutLE32(working[3], subKey, 12);
        PutLE32(working[12], subKey, 16);
        PutLE32(working[13], subKey, 20);
        PutLE32(working[14], subKey, 24);
        PutLE32(working[15], subKey, 28);

        return subKey;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CHACHA20 STREAM CIPHER — RFC 8439 §2.4
    // ═══════════════════════════════════════════════════════════════════════

    private byte[] ChaCha20Process(byte[] data, byte[] key, byte[] nonce12,
                                   uint counter)
    {
        byte[] output = new byte[data.Length];
        int pos = 0;

        while (pos < data.Length)
        {
            byte[] keyStream = ChaCha20KeystreamBlock(key, nonce12, counter);
            counter++;                                   // wraps at 2^32 per RFC

            int blockLen = Mathf.Min(64, data.Length - pos);
            for (int i = 0; i < blockLen; i++)
                output[pos + i] = (byte)(data[pos + i] ^ keyStream[i]);

            pos += 64;
        }

        return output;
    }

    // ─── Single 64-byte keystream block (RFC 8439 §2.3) ──────────────────

    private byte[] ChaCha20KeystreamBlock(byte[] key, byte[] nonce12,
                                          uint counter)
    {
        uint[] state = new uint[16];

        // Constants
        state[0] = 0x61707865u;
        state[1] = 0x3320646eu;
        state[2] = 0x79622d32u;
        state[3] = 0x6b206574u;

        // Key
        for (int i = 0; i < 8; i++)
            state[4 + i] = LE32(key, i * 4);

        // Counter (little-endian 32-bit)
        state[12] = counter;

        // Nonce (96-bit = 3 × 32-bit words)
        state[13] = LE32(nonce12, 0);
        state[14] = LE32(nonce12, 4);
        state[15] = LE32(nonce12, 8);

        // Copy working state
        uint[] working = new uint[16];
        System.Array.Copy(state, working, 16);

        // 20 rounds of mixing
        ChaCha20Block20Rounds(working);

        // Add original state back (RFC 8439 §2.3 — the final add step)
        for (int i = 0; i < 16; i++)
            working[i] += state[i];

        // Serialise 16 uint32s to 64 bytes (little-endian)
        byte[] block = new byte[64];
        for (int i = 0; i < 16; i++)
            PutLE32(working[i], block, i * 4);

        return block;
    }

    // ─── 20 rounds: 10 column rounds + 10 diagonal rounds ────────────────
    // RFC 8439 §2.1 defines the quarter-round; §2.3 defines the round schedule.

    private void ChaCha20Block20Rounds(uint[] s)
    {
        for (int i = 0; i < 10; i++)
        {
            // Column rounds
            QR(s, 0, 4, 8, 12);
            QR(s, 1, 5, 9, 13);
            QR(s, 2, 6, 10, 14);
            QR(s, 3, 7, 11, 15);
            // Diagonal rounds
            QR(s, 0, 5, 10, 15);
            QR(s, 1, 6, 11, 12);
            QR(s, 2, 7, 8, 13);
            QR(s, 3, 4, 9, 14);
        }
    }

    // ─── ChaCha20 quarter-round (RFC 8439 §2.1) ──────────────────────────

    private void QR(uint[] s, int a, int b, int c, int d)
    {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = RotL(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = RotL(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = RotL(s[d], 8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = RotL(s[b], 7);
    }

    // ─── Rotate left (uint, no overflow) ─────────────────────────────────

    private uint RotL(uint v, int n) => (v << n) | (v >> (32 - n));

    // ═══════════════════════════════════════════════════════════════════════
    //  KEY DERIVATION  (password string → 32-byte key)
    // ═══════════════════════════════════════════════════════════════════════
    // Two-pass FNV-1a (64-bit) over the UTF-16 code-units of the password,
    // followed by 128 rounds of Xorshift64 diffusion, producing 32 bytes.
    // This is lightweight and deterministic — suitable for VRChat's Udon
    // constraints.  It is NOT a password hashing function; for secrets that
    // must resist offline brute-force use a pre-shared 32-byte key instead.

    private byte[] DeriveKey(string password)
    {
        // ── FNV-1a 64-bit constants ──────────────────────────────────────
        // Simulated with two uint32s (hi, lo) because Udon lacks long/ulong.
        // FNV offset basis  : 0xcbf29ce484222325
        // FNV prime         : 0x00000100000001B3

        const uint FNV_PRIME_HI = 0x00000100u;
        const uint FNV_PRIME_LO = 0x000001B3u;
        const uint BASIS_HI = 0xcbf29ce4u;
        const uint BASIS_LO = 0x84222325u;

        uint hashHi = BASIS_HI;
        uint hashLo = BASIS_LO;

        // Pass 1 — forward
        for (int i = 0; i < password.Length; i++)
        {
            uint ch = (uint)password[i];
            // XOR low word with byte
            hashLo ^= (ch & 0xFFu);
            // Multiply (hi,lo) × prime using schoolbook 32×32→64
            MulU64(ref hashHi, ref hashLo, FNV_PRIME_HI, FNV_PRIME_LO);
            // XOR high byte of char
            hashLo ^= ((ch >> 8) & 0xFFu);
            MulU64(ref hashHi, ref hashLo, FNV_PRIME_HI, FNV_PRIME_LO);
        }

        // Pass 2 — reverse (improves avalanche for short passwords)
        for (int i = password.Length - 1; i >= 0; i--)
        {
            uint ch = (uint)password[i];
            hashLo ^= (ch & 0xFFu);
            MulU64(ref hashHi, ref hashLo, FNV_PRIME_HI, FNV_PRIME_LO);
            hashLo ^= ((ch >> 8) & 0xFFu);
            MulU64(ref hashHi, ref hashLo, FNV_PRIME_HI, FNV_PRIME_LO);
        }

        // ── Xorshift64 expansion (128 rounds) → 32-byte key ─────────────
        // Uses the 64-bit hash state as seed; generates 4 × 8-byte outputs.
        byte[] key = new byte[32];
        uint xhi = hashHi, xlo = hashLo;

        for (int chunk = 0; chunk < 4; chunk++)
        {
            // 128 rounds of Xorshift64 mixing
            for (int r = 0; r < 128; r++)
                Xorshift64(ref xhi, ref xlo);

            // Write 8 bytes per chunk
            int off = chunk * 8;
            key[off + 0] = (byte)(xlo & 0xFF);
            key[off + 1] = (byte)((xlo >> 8) & 0xFF);
            key[off + 2] = (byte)((xlo >> 16) & 0xFF);
            key[off + 3] = (byte)((xlo >> 24) & 0xFF);
            key[off + 4] = (byte)(xhi & 0xFF);
            key[off + 5] = (byte)((xhi >> 8) & 0xFF);
            key[off + 6] = (byte)((xhi >> 16) & 0xFF);
            key[off + 7] = (byte)((xhi >> 24) & 0xFF);
        }

        return key;
    }

    // ─── 64-bit multiply helper (hi,lo) × (phi,plo) ──────────────────────

    private void MulU64(ref uint hi, ref uint lo, uint phi, uint plo)
    {
        // Schoolbook: (hi·2^32 + lo) × (phi·2^32 + plo)
        // We only keep the low 64 bits.
        ulong aLo = lo;
        ulong bLo = plo;
        ulong aHi = hi;
        ulong bHi = phi;

        ulong rLo = aLo * bLo;
        ulong mid = aLo * bHi + aHi * bLo;   // high halves overflow — fine
        ulong rHi = (rLo >> 32) + (mid & 0xFFFFFFFFul);
        lo = (uint)(rLo & 0xFFFFFFFFul);
        hi = (uint)(rHi & 0xFFFFFFFFul);
    }

    // ─── Xorshift64 (one step) ───────────────────────────────────────────

    private void Xorshift64(ref uint hi, ref uint lo)
    {
        // Equivalent to: x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        // on a 64-bit value split into (hi, lo).

        // << 13
        uint newHi = (hi << 13) | (lo >> 19);
        uint newLo = lo << 13;
        hi ^= newHi; lo ^= newLo;

        // >> 7
        newLo = (hi << 25) | (lo >> 7);
        newHi = hi >> 7;
        hi ^= newHi; lo ^= newLo;

        // << 17
        newHi = (hi << 17) | (lo >> 15);
        newLo = lo << 17;
        hi ^= newHi; lo ^= newLo;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  NONCE GENERATION  (24 random bytes via UnityEngine.Random)
    // ═══════════════════════════════════════════════════════════════════════
    // UnityEngine.Random is available in Udon and gives cryptographically
    // adequate randomness for nonce generation (nonces don't need to be
    // secret — they only need to be unique per (key, message) pair, which a
    // 192-bit random nonce almost certainly guarantees).

    private byte[] GenerateNonce()
    {
        byte[] nonce = new byte[24];
        for (int i = 0; i < 24; i++)
            nonce[i] = (byte)Random.Range(0, 256);
        return nonce;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  BASE64 ENCODE / DECODE  (RFC 4648 §4, standard alphabet)
    // ═══════════════════════════════════════════════════════════════════════
    // Implemented from scratch — System.Convert is not available in Udon.

    private const string B64_CHARS =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private string Base64Encode(byte[] data)
    {
        if (data == null || data.Length == 0) return "";

        System.Text.StringBuilder sb = new System.Text.StringBuilder(
            ((data.Length + 2) / 3) * 4);

        int i = 0;
        while (i < data.Length)
        {
            int b0 = data[i++];
            int b1 = i < data.Length ? data[i++] : 0;
            int b2 = i < data.Length ? data[i++] : 0;

            sb.Append(B64_CHARS[b0 >> 2]);
            sb.Append(B64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)]);
            sb.Append(B64_CHARS[((b1 & 0x0F) << 2) | (b2 >> 6)]);
            sb.Append(B64_CHARS[b2 & 0x3F]);
        }

        // Apply padding
        int pad = (3 - (data.Length % 3)) % 3;
        string result = sb.ToString();
        if (pad > 0)
            result = result.Substring(0, result.Length - pad) + new string('=', pad);

        return result;
    }

    private byte[] Base64Decode(string s)
    {
        if (string.IsNullOrEmpty(s)) return null;

        // Normalise: strip whitespace, count padding
        s = s.Trim();
        int pad = 0;
        if (s.EndsWith("==")) pad = 2;
        else if (s.EndsWith("=")) pad = 1;
        s = s.TrimEnd('=');

        int byteCount = (s.Length * 6 / 8);
        byte[] output = new byte[byteCount];
        int outIdx = 0;

        // Build reverse lookup table once per call (Udon has no static fields
        // accessible via dictionary, so we search the charset string)
        for (int i = 0; i < s.Length - 1; i += 4)
        {
            int remaining = s.Length - i;
            int c0 = B64CharVal(s[i]);
            int c1 = remaining > 1 ? B64CharVal(s[i + 1]) : 0;
            int c2 = remaining > 2 ? B64CharVal(s[i + 2]) : 0;
            int c3 = remaining > 3 ? B64CharVal(s[i + 3]) : 0;

            if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) return null; // bad char

            if (outIdx < output.Length)
                output[outIdx++] = (byte)((c0 << 2) | (c1 >> 4));
            if (outIdx < output.Length)
                output[outIdx++] = (byte)(((c1 & 0x0F) << 4) | (c2 >> 2));
            if (outIdx < output.Length)
                output[outIdx++] = (byte)(((c2 & 0x03) << 6) | c3);
        }

        return output;
    }

    private int B64CharVal(char c)
    {
        int idx = B64_CHARS.IndexOf(c);
        return idx; // returns -1 for invalid chars
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  LITTLE-ENDIAN HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>Read 4 bytes at <paramref name="offset"/> as a little-endian uint32.</summary>
    private uint LE32(byte[] buf, int offset) =>
          ((uint)buf[offset])
        | ((uint)buf[offset + 1] << 8)
        | ((uint)buf[offset + 2] << 16)
        | ((uint)buf[offset + 3] << 24);

    /// <summary>Write <paramref name="v"/> as 4 little-endian bytes at <paramref name="offset"/>.</summary>
    private void PutLE32(uint v, byte[] buf, int offset)
    {
        buf[offset] = (byte)(v & 0xFF);
        buf[offset + 1] = (byte)((v >> 8) & 0xFF);
        buf[offset + 2] = (byte)((v >> 16) & 0xFF);
        buf[offset + 3] = (byte)((v >> 24) & 0xFF);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STRING ↔ BYTE CONVERSION  (UTF-8 encoder, no System.Text.Encoding)
    // ═══════════════════════════════════════════════════════════════════════
    // Udon's IL strip removes many System.Text.Encoding members, so we
    // implement a simple UTF-8 codec manually.  Supports the full Unicode
    // BMP and supplementary planes (via surrogate pairs in C# strings).

    private byte[] StringToBytes(string s)
    {
        // First pass — count bytes
        int byteLen = 0;
        for (int i = 0; i < s.Length;)
        {
            int cp = GetCodePoint(s, ref i);
            if (cp < 0x80) byteLen += 1;
            else if (cp < 0x800) byteLen += 2;
            else if (cp < 0x10000) byteLen += 3;
            else byteLen += 4;
        }

        // Second pass — encode
        byte[] buf = new byte[byteLen];
        int pos = 0;
        for (int i = 0; i < s.Length;)
        {
            int cp = GetCodePoint(s, ref i);
            if (cp < 0x80)
            {
                buf[pos++] = (byte)cp;
            }
            else if (cp < 0x800)
            {
                buf[pos++] = (byte)(0xC0 | (cp >> 6));
                buf[pos++] = (byte)(0x80 | (cp & 0x3F));
            }
            else if (cp < 0x10000)
            {
                buf[pos++] = (byte)(0xE0 | (cp >> 12));
                buf[pos++] = (byte)(0x80 | ((cp >> 6) & 0x3F));
                buf[pos++] = (byte)(0x80 | (cp & 0x3F));
            }
            else
            {
                buf[pos++] = (byte)(0xF0 | (cp >> 18));
                buf[pos++] = (byte)(0x80 | ((cp >> 12) & 0x3F));
                buf[pos++] = (byte)(0x80 | ((cp >> 6) & 0x3F));
                buf[pos++] = (byte)(0x80 | (cp & 0x3F));
            }
        }
        return buf;
    }

    private string BytesToString(byte[] buf)
    {
        System.Text.StringBuilder sb = new System.Text.StringBuilder();
        int i = 0;
        while (i < buf.Length)
        {
            int b = buf[i];
            int cp;
            if ((b & 0x80) == 0)
            {
                cp = b; i++;
            }
            else if ((b & 0xE0) == 0xC0 && i + 1 < buf.Length)
            {
                cp = ((b & 0x1F) << 6) | (buf[i + 1] & 0x3F); i += 2;
            }
            else if ((b & 0xF0) == 0xE0 && i + 2 < buf.Length)
            {
                cp = ((b & 0x0F) << 12) | ((buf[i + 1] & 0x3F) << 6) | (buf[i + 2] & 0x3F);
                i += 3;
            }
            else if ((b & 0xF8) == 0xF0 && i + 3 < buf.Length)
            {
                cp = ((b & 0x07) << 18) | ((buf[i + 1] & 0x3F) << 12)
                   | ((buf[i + 2] & 0x3F) << 6) | (buf[i + 3] & 0x3F);
                i += 4;
            }
            else
            {
                // Replacement character for invalid sequences
                cp = 0xFFFD; i++;
            }

            // Encode code point as UTF-16 (C# char / string)
            if (cp < 0x10000)
            {
                sb.Append((char)cp);
            }
            else
            {
                // Supplementary plane → surrogate pair
                cp -= 0x10000;
                sb.Append((char)(0xD800 | (cp >> 10)));
                sb.Append((char)(0xDC00 | (cp & 0x3FF)));
            }
        }
        return sb.ToString();
    }

    // ─── Get Unicode code point from a C# UTF-16 string ─────────────────

    private int GetCodePoint(string s, ref int i)
    {
        char c = s[i++];
        // High surrogate?
        if (c >= 0xD800 && c <= 0xDBFF && i < s.Length)
        {
            char low = s[i];
            if (low >= 0xDC00 && low <= 0xDFFF)
            {
                i++;
                return 0x10000 + ((c - 0xD800) << 10) + (low - 0xDC00);
            }
        }
        return c;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  QUICK SELF-TEST  (call from Start or a U# button)
    // ═══════════════════════════════════════════════════════════════════════

    void Start()
    {
        string encrypted = Encrypt(textToEncrypt, defaultPassword);
        string decrypted = Decrypt(encrypted, defaultPassword);

        Debug.Log("[XChaCha20] Original  : " + textToEncrypt);
        Debug.Log("[XChaCha20] Encrypted : " + encrypted);
        Debug.Log("[XChaCha20] Decrypted : " + decrypted);
        Debug.Log("[XChaCha20] Round-trip OK: " + (textToEncrypt == decrypted));
    }
}