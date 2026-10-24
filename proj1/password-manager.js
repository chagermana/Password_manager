"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  // only values are stored in the constructor. 
  // it is  called by init (new keychain) and load (exisitng keychain)
  //hmacKey and aesKey live in memory only. they are never saved to disk
  //salt, kvs and check are saved in the dump, since they dont help an attacker
  // salt isnt a secret, kvs and check are encrypted
  constructor(hmacKey, aesKey, salt, kvs, check) { 

         this.hmacKey = hmacKey; // key for hiding domain names (HMAC)
         this.aesKey = aesKey; // key for encrypting password (AES-GCM)
         this.salt = salt; // (random value, saved as a Base64 string)
         this.kvs = kvs; //(the key-value store: HMAC(domain-> encrypted password)
         this.check = check; //({iv,ct} : lets load() detect a wrong master password)
  };
//the master password is changed into the 2 keys needed. both init and load call the function therefore same password&salt = same keys

  static async deriveKeys(password, salt) {
    //turning of password string into a key object that pbkdf2 can use 
    const rawKey = await subtle.importKey(
      "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]
    );
    
    //run pbkdff2 once. 
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2", salt: salt,iterations:PBKDF2_ITERATIONS, hash: "SHA-256"
      },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]
    );
    
// use hmac as a prf
      const hmacBytes = await subtle.sign("HMAC", masterKey, stringToBuffer("domain-key"));
      const aesBytes = await subtle.sign("HMAC", masterKey, stringToBuffer("aes-key"));
// each value is changed to a key object for its own job
      const hmacKey = await subtle.importKey(
      "raw", hmacBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    const aesKey = await subtle.importKey(
      "raw", aesBytes, "AES-GCM", false, ["encrypt", "decrypt"]);

      return { hmacKey, aesKey };
  }
  //a new, empty keychain is created
    static async init(password) {
    const salt = getRandomBytes(16);
    const { hmacKey, aesKey } = await Keychain.deriveKeys(password, salt);

    // The check value lets load() notice a wrong password
    const iv = getRandomBytes(12);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      stringToBuffer("keychain")
    );
    // buffers cant be saved in json so they are converted to base 64 strings
    const check = { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
    // return a new keychain instance with the derived keys, encoded salt, empty kvs, and check value
    return new Keychain(hmacKey, aesKey, encodeBuffer(salt), {}, check);
  }
 
  static async load(password, repr, trustedDataCheck) {
    throw "Not Implemented!";
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    throw "Not Implemented!";
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    throw "Not Implemented!";
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    throw "Not Implemented!";
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    throw "Not Implemented!";
  };
};

module.exports = { Keychain }
