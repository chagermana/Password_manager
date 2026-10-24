**SECURE PASSWORD MANAGER**

**Object Fields**
- in the dump (saved) : kvs. salt(Base64),check
- in memory only: hmacKey(for domain names) and aesKey(for passwords)
DO NOT put the master pasword or any key in the dump
                                                       
**Key derivation**
1. generate a salt: getRandomBytes(16)
2. import the master password as a PKHDF2 key, then call PBKDF2 once (SHA-256, about 100,000 iterations) to get a master HMAC key.
3. Sign two different fixed strings with the master key.
- "domain-key" gives the bytes for hmacKey(import as HMAC, usages sign, verify)
- "aes-key" gives the bytes for aesKey (import as AES-GCM, usages encrypt, decrypt)
4. load repeats the same steps using the stored result

**Padding**
- pad every password to exactly 64 characters with "\0": value.padEnd(64, "\0").
- after decrypting, remove the trailing "\0" characters
- if a password is longer than 64 characters, throw an error

**Entry format in kvs**
kvs[ base64(HMAC(hmacKey, domain)) ] = { iv: <base64>, ct: <base64> }
- iv: fresh random 12 bytes for every encryption (also when updating an existing entry)
- ct: AES-GCM ciphertext of the padded password

**Swap attack defense**
- Use the entry's kvs key (the Base64 HMAC of the domain) as the AES-GCM additional data, in both set and get.
- If an adversary swaps two entries, the additional data no longer matches, the GCM check fails, and we throw.
- This works without the trusted hash.
**
Dump format**
- dump() builds JSON.stringify({ kvs, salt, check }).
- The hash is SHA-256 of that exact string, Base64 encoded.
- dump() returns [jsonString, hash].
- load(): if trustedDataCheck !== undefined, hash the repr string we received (not a re-stringified copy) and compare. Throw on a mismatch.

**Wrong password detection**
- In init, encrypt the fixed string "keychain" with aesKey and a random IV. Store {iv, ct} as check.
- In load, try to decrypt check. If it fails, or the result is not "keychain", throw "invalid password".
**
Function summary**
1. init(password)	                            new salt, derive keys, create check, return a new Keychain
2. load(password, repr, trustedDataCheck)	    verify hash if given, parse JSON, derive keys, verify check, return Keychain
3. dump()	                                    return [json, hash]
4. set(name, value)	                          pad, compute domain HMAC, encrypt with the HMAC as additional data, store
5.  get(name)	                                  compute domain HMAC, return null if missing, else decrypt and strip padding
6.  remove(name)	                              delete the entry, return true if it existed, else false
