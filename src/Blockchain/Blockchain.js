// Cryptography from SHA256
const SHA256 = require("crypto-js/sha256");
const crypto = require("crypto");

// Elliptic Curve Function:
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");

class Transaction {
  constructor(addressFrom, addressTo, amount) {
    this.addressFrom = addressFrom;
    this.addressTo = addressTo;
    this.amount = amount;
    this.timestamp = Date.now(); // in unix.
    this.transactionHash = this.calculateTxHash();
  }

  // Creating a SHA256 hash of the transaction:
  calculateTxHash() {
    return crypto
      .createHash("sha256")
      .update(this.addressFrom + this.addressTo + this.amount + this.timestamp)
      .digest("hex");
  }

  //   To only allow wallets with private keys linked to permit Txs
  //   Check if addressFrom matches the public key
  signTransaction(signingKey) {
    if (signingKey.getPublic("hex") !== this.addressFrom) {
      // Public key dont match addressFrom:
      throw new Error("Not your wallet, cannot sign transaction");
    }

    // Calculate hash of this Tx and sign it with key:
    const hashTx = this.calculateTxHash();
    const sig = signingKey.sign(hashTx, "base64");

    this.signature = sig.toDER("hex");
  }

  isTxValid() {
    // If the Tx dont have a from Address - mining reward
    if (this.addressFrom === null) return true;

    if (!this.signature || this.signature.length === 0) {
      throw new Error("No signature in this transaction");
    }

    const publicKey = ec.keyFromPublic(this.fromAddress, "hex");
    return publicKey.verify(this.calculateTxHash(), this.signature);
  }

  hasValidTxs() {
    for (const tx of this.transactions) {
      if (!tx.isTxValid()) {
        return false;
      }
    }

    return true;
  }
}

class Block {
  constructor(index, timestamp, transactions, previousHash = "") {
    this.index = index;
    this.previousHash = previousHash;
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.hash = this.calculateHash();
    this.nonce = 0;
  }

  calculateHash() {
    return SHA256(
      this.index +
        this.previousHash +
        this.timestamp +
        JSON.stringify(this.transactions + this.nonce).toString()
    );
  }

  // difficulty in terms of quantity of 0s at the start of the hash:
  mineBlock(difficulty) {
    while (
      this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0")
    ) {
      this.nonce++;
      this.hash = this.calculateHash();
    }
  }
}

class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()]; // First block in the array
    this.difficulty = 2;
    this.pendingTransactions = [];
    this.miningReward = 100;
  }

  createGenesisBlock() {
    return new Block(0, "07/07/1999", "Genesis Block", "0");
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  minePendingTransactions(miningRewardAddress) {
    const rewardTx = new Transaction(
      null,
      miningRewardAddress,
      this.miningReward
    );
    this.pendingTransactions.push(rewardTx);

    const block = new Block(
      Date.now(),
      this.pendingTransactions,
      this.getLatestBlock().hash
    );
    // Mine with the current difficulty:
    block.mineBlock(this.difficulty);

    // Once successful:
    console.log(`Block successfully mined!`);
    this.chain.push(block);
    this.pendingTransactions = []; // reset  pendingTx Array
  }

  //   addBlock(newBlock) {
  //     newBlock.previousHash = this.getLatestBlock().hash;
  //     newBlock.mineBlock(this.difficulty);
  //     this.chain.push(newBlock);
  //   }

  // Checks before adding it to the 'mempool' for mining:
  addTransaction(transaction) {
    if (!transaction.isValid()) {
      throw new Error("Invalid Transaction, revert");
    } else if (!transaction.addressFrom || !transaction.addressTo) {
      throw new Error("Invalid transaction, revert");
    } else if (transaction.amount <= 0) {
      throw new Error("Invalid Transaction amount");
    } else if (
      this.getBalanceOfAddress(transaction.addressFrom) < transaction.amount
    ) {
      throw new Error("Insufficient Balance");
    } else {
      this.pendingTransactions.push(transaction);
      console.log(`Transaction Added: ${transaction}`);
    }
  }

  getBalanceOfAddress(address) {
    let balance = 0;

    for (const block of this.chain) {
      for (const thisTx of block.transactions) {
        if (thisTx.addressFrom === address) {
          balance -= thisTx.amount;
        }
        if (thisTx.addressTo === address) {
          balance += thisTx.amount;
        }
      }
    }
    console.log(`getBalanceOfAddress: ${balance}`);
    return balance;
  }

  getAllTransactionsForWallet(address) {
    const addressTxArray = [];

    for (const block of this.chain) {
      for (const tx of block.transactions) {
        if (tx.addressFrom === address || tx.addressTo === address) {
          addressTxArray.push(tx);
        }
      }
    }

    console.log(`Transaction count for wallet: ${addressTxArray.length}`);
    return addressTxArray;
  }

  isChainValid() {
    // Check if the Genesis Block has NOT been tampered by comparing output of createGenesis block with the first block on our chain:
    const realGenesis = JSON.stringify(this.createGenesisBlock());
    if (realGenesis !== JSON.stringify(this.chain[0])) {
      return false;
    }
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      if (currentBlock.hash !== currentBlock.calculateHash()) {
        return false;
      }

      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }
    }
    return true;
  }
}

module.exports.Blockchain = Blockchain;
module.exports.Block = Block;
module.exports.Transaction = Transaction;

console.log("Hello there");
