"use strict";

/********* External Imports ********/

const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
} = require("./lib");
const { subtle } = require("crypto").webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {

  constructor() {
    this.data = {
      kvs: {},
    };
    this.secrets = {};
  }

  
  static async init(password) {
    const keychain = new Keychain();
    const salt = getRandomBytes(16);
    const iv = getRandomBytes(12);
    keychain.secrets.key = await Keychain.deriveKey(password, salt);

    const testValue = await subtle.encrypt(
      { name: "AES-GCM", iv },
      keychain.secrets.key,
      stringToBuffer("keychain-test")
    );
    keychain.data.salt = encodeBuffer(salt);
    keychain.data.iv = encodeBuffer(iv);
    keychain.data.testValue = encodeBuffer(testValue);

    return keychain;
  }

  
  static async deriveKey(password, salt) {
    const keyMaterial = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return await subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  
  static async load(password, repr, trustedDataCheck) {
    const data = JSON.parse(repr);
    const salt = decodeBuffer(data.salt);
    const derivedKey = await Keychain.deriveKey(password, salt);

    try {
      const iv = decodeBuffer(data.iv);
      const encryptedTestValue = decodeBuffer(data.testValue);
      const decryptedTestValue = await subtle.decrypt(
        { name: "AES-GCM", iv },
        derivedKey,
        encryptedTestValue
      );

      if (bufferToString(decryptedTestValue) !== "keychain-test") {
        throw new Error("Incorrect password");
      }
    } catch (e) {
      throw new Error("Incorrect password");
    }

    if (trustedDataCheck) {
      const computedChecksum = await Keychain.computeChecksum(repr);
      if (trustedDataCheck !== computedChecksum) {
        throw new Error("Checksum validation failed!");
      }
    }

    const keychain = new Keychain();
    keychain.secrets.key = derivedKey;
    keychain.data = data;
    return keychain;
  }

  
  async dump() {
    const jsonString = JSON.stringify(this.data);
    const checksum = await Keychain.computeChecksum(jsonString);
    return [jsonString, checksum];
  }

  static async computeChecksum(data) {
    const buffer = stringToBuffer(data);
    const hash = await subtle.digest("SHA-256", buffer);
    return encodeBuffer(hash);
  }

  
  async get(name) {
    const encryptedKeys = Object.keys(this.data.kvs);
    for (let encryptedKey of encryptedKeys) {
      const decodedEntry = JSON.parse(decodeBuffer(encryptedKey));
      const decodedKey = decodeBuffer(decodedEntry.encryptedKey);
      const iv = decodeBuffer(decodedEntry.iv);
      try {
        const decryptedKey = await subtle.decrypt(
          { name: "AES-GCM", iv },
          this.secrets.key,
          decodedKey
        );
        const decryptedKeyString = bufferToString(decryptedKey);
        if (decryptedKeyString === name) {
          const encryptedValue = decodeBuffer(this.data.kvs[encryptedKey]);
          const decryptedValue = await subtle.decrypt(
            { name: "AES-GCM", iv },
            this.secrets.key,
            encryptedValue
          );
          return bufferToString(decryptedValue);
        }
      } catch (e) {
        
      }
    }
    return null;
  }

 
  async set(name, value) {
    const iv = getRandomBytes(12);
    const encryptedName = await subtle.encrypt(
      { name: "AES-GCM", iv },
      this.secrets.key,
      stringToBuffer(name)
    );
    const encryptedValue = await subtle.encrypt(
      { name: "AES-GCM", iv },
      this.secrets.key,
      stringToBuffer(value)
    );

    this.data.kvs[
      encodeBuffer(
        JSON.stringify({
          encryptedKey: encodeBuffer(encryptedName),
          iv: encodeBuffer(iv),
        })
      )
    ] = encodeBuffer(encryptedValue);
  }


  async remove(name) {
    const encryptedKeys = Object.keys(this.data.kvs);
    for (let encryptedKey of encryptedKeys) {
      const decodedEntry = JSON.parse(decodeBuffer(encryptedKey));
      const decodedKey = decodeBuffer(decodedEntry.encryptedKey);
      const iv = decodeBuffer(decodedEntry.iv);
      try {
        const decryptedKey = await subtle.decrypt(
          { name: "AES-GCM", iv },
          this.secrets.key,
          decodedKey
        );
        const decryptedKeyString = bufferToString(decryptedKey);
        if (decryptedKeyString === name) {
          delete this.data.kvs[encryptedKey];
          return true;
        }
      } catch (e) {
        throw new Error("Incorrect password");
      }
    }
    return false;
  }
}

module.exports = { Keychain };
