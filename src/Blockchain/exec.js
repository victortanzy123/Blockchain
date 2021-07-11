const { Blockchain, Transaction, Block } = require("./Blockchain");

// Elliptic Curve:
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");
