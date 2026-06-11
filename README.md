# XChaCha20 for UdonSharp & Node.js

A cross-platform implementation of **XChaCha20** for **VRChat UdonSharp** and **Node.js**.

This project enables encryption and decryption of data between VRChat worlds and backend services using a compatible implementation on both platforms.

## Features

- XChaCha20 stream cipher
- HChaCha20 subkey derivation
- Cross-platform compatibility
- VRChat UdonSharp support
- Node.js support
- Automatic 24-byte nonce generation
- UTF-8 string support
- Base64 wire format
- No external dependencies required for UdonSharp

## Supported Platforms

| Platform           | Status |
| ------------------ | ------ |
| VRChat UdonSharp   | ✅     |
| Unity              | ✅     |
| Node.js            | ✅     |
| Browser JavaScript | ✅     |

---

## Repository Contents

```text
.
├── src/XChaCha20Udon.cs
├── src/NodeChaCha20.js
├── LICENSE
└── README.md
```

## Prerequisites

This project is intended for developers who have a **basic working knowledge** of:

- Unity
- VRChat SDK
- UdonSharp
- JavaScript / Node.js

The library is designed to be integrated into existing projects and therefore does **not** provide a beginner tutorial on Unity, UdonSharp, or JavaScript development.

It is expected that users are comfortable with:

- Importing scripts into a Unity project
- Working with UdonSharp behaviours
- Writing and running JavaScript/Node.js code
- Managing strings, byte arrays, and Base64 data
- Understanding basic cryptographic concepts such as keys and nonces

If you are new to Unity or UdonSharp, it is recommended that you become familiar with those technologies before using this library.
This project is a library, not a complete networking solution. It provides compatible encryption/decryption primitives for UdonSharp and Node.js and assumes the user can integrate them into their own application architecture.

---

## Installation

### UdonSharp

Import `XChaCha20Udon.cs` into your Unity project by directly downloading or copying the file.

### Node.js

Import `NodeChaCha20` into your Javascript project by directly downloading or copying the file to whatever location you like.

```javascript
const { encrypt, decrypt } = require("./NodeChaCha20"); // Path to the location of the file you store it at
```

---

## Quick Start

### Encrypt

```javascript
const encrypted = encrypt("Hello VRChat!", "VRChatSecretKey!");
```

### Decrypt

```javascript
const decrypted = decrypt(encrypted, "VRChatSecretKey!");
```

---

## UdonSharp Example

```csharp
string password = "VRChatSecretKey!";

string encrypted =
    Encrypt(
        "Hello VRChat!",
        password
    );

string decrypted =
    Decrypt(
        encrypted,
        password
    );
```

---

## Wire Format

Encrypted payloads are encoded as:

```text
Base64(
    [24-byte nonce] ||
    [ciphertext]
)
```

The nonce is prepended to the ciphertext and transmitted together.

---

## Interoperability

Data encrypted in Node.js can be decrypted in UdonSharp.

```text
Node.js
   Encrypt
      ↓
Base64 Payload
      ↓
UdonSharp
   Decrypt
```

Data encrypted in UdonSharp can be decrypted in Node.js.

```text
UdonSharp
   Encrypt
      ↓
Base64 Payload
      ↓
Node.js
   Decrypt
```

---

## Test Suite

### Node.js Round-Trip Test

```javascript
const { encrypt, decrypt } = require("./NodeChaCha20"); // Path to file wherever you have stored it in your project.

const password = "VRChatSecretKey!";
const original = "Hello XChaCha20!";

const encrypted = encrypt(original, password);
const decrypted = decrypt(encrypted, password);

console.log("Original :", original);
console.log("Encrypted:", encrypted);
console.log("Decrypted:", decrypted);

if (original !== decrypted) {
  throw new Error("Round-trip test failed");
}

console.log("PASS");
```

You can also run the following command from the root of your github directory as well.

```
npm run test
```

Expected:

```text
PASS
```

---

### UdonSharp Round-Trip Test

The included Start() method performs a built-in validation test.

Expected Unity Console output:

```text
[XChaCha20] Original  : ...
[XChaCha20] Encrypted : ...
[XChaCha20] Decrypted : ...
[XChaCha20] Round-trip OK: True
```

---

## Cross-Platform Compatibility Test

### Encrypt in Node.js

```javascript
const encrypted = encrypt("Cross Platform Test", "SharedPassword");

console.log(encrypted);
```

Copy the output.

### Decrypt in UdonSharp

```csharp
string decrypted =
    Decrypt(
        encryptedString,
        "SharedPassword"
    );
```

Expected result:

```text
Cross Platform Test
```

Repeat the process in reverse to verify bidirectional compatibility.

---

## Security Notes

This implementation follows:

- RFC 8439 (ChaCha20)
- draft-irtf-cfrg-xchacha (XChaCha20)

The included password-to-key derivation function exists primarily to provide deterministic compatibility between UdonSharp and Node.js.

For applications requiring stronger resistance against offline password attacks, use a high-entropy pre-shared 32-byte secret rather than a user-generated password.

### Important

This project implements:

```text
XChaCha20
```

It does **not** provide authenticated encryption.

This means ciphertext integrity is not verified.

If message authentication is required, consider extending the implementation with:

```text
XChaCha20-Poly1305
```

or another authenticated encryption scheme.

---

## License

Licensed under the GNU General Public License v2.0.

See the LICENSE file for details.

---

## Contributing

Issues and pull requests are welcome.

Bug reports, interoperability tests, performance improvements, and security reviews are especially appreciated.
