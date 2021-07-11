const EC = require("elliptic").ec;
const ec = new EC("secp256k1");

// Generating a new key pair in hex-strings:
const key = ec.genKeyPair();

// Public Key:
const publicKey = key.getPublic("hex");
const privateKey = key.getPrivate("hex");

// Generated Keys Info:
console.log();
console.log("Generated Key Summary:");
console.log();

console.log(
  "==============================================================================================================================================="
);
console.log(`Public Key: ${publicKey}`);
console.log();
console.log(`Private Key (secret): ${privateKey}`);
console.log(
  "==============================================================================================================================================="
);
