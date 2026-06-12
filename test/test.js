// ═══════════════════════════════════════════════════════════════════════════════
//  QUICK SELF-TEST  (run with:  node xchacha20.js)
// ═══════════════════════════════════════════════════════════════════════════════
const { encrypt, decrypt } = require("../src/NodeChaCha20");

if (typeof require !== "undefined" && require.main === module) {
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
  console.log(
    decrypt(
      "KlAS6qYkYMwFw9bLuTTCbjeu8+5lmIxQuXUNLM/h921awbZbnK4YkYS/b4eaNpXIOkxjeu8Z/vVdBUBGmOXXfkw2dwphBkCe74Y=",
      password,
    ),
  );
}
