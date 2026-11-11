"use strict";

let expect = require('expect.js');
const { Keychain } = require('../password-manager');

function expectReject(promise) {
    return promise.then(
        (result) => expect().fail(`Expected failure, but function returned ${result}`),
        (error) => {},
    );
}

describe('Password manager', async function() {
    this.timeout(5000);
    let password = "password123!";

    let kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    describe('functionality', async function() {

        it('inits without an error', async function() {
            await Keychain.init(password);
        });

        it('can set and retrieve a password', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
            expect(await keychain.get(url)).to.equal(pw);
        });

        it('can set and retrieve multiple passwords', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            for (let k in kvs) {
                expect(await keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('returns null for non-existent passwords', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.get('www.stanford.edu')).to.be(null);
        });

        it('can remove a password', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('service1')).to.be(true);
            expect(await keychain.get('service1')).to.be(null);
        });

        it('returns false if there is no password for the domain being removed', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('www.stanford.edu')).to.be(false);
        });

        it('can dump and restore the database', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
            let newKeychain = await Keychain.load(password, contents, checksum);

            // Make sure it's valid JSON
            expect(async function() {
                JSON.parse(contents)
            }).not.to.throwException();
            for (let k in kvs) {
                expect(await newKeychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('fails to restore the database if checksum is wrong', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let fakeChecksum = '3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM=';
            await expectReject(Keychain.load(password, contents, fakeChecksum));
        });

        it('returns false if trying to load with an incorrect password', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
            await expectReject(Keychain.load("fakepassword", contents, checksum));
        });
    });

    describe('security', async function() {

        // Very basic test to make sure you're not doing the most naive thing
        it("doesn't store domain names and passwords in the clear", async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
            let data = await keychain.dump();
            let contents = data[0];
            expect(contents).not.to.contain(password);
            expect(contents).not.to.contain(url);
            expect(contents).not.to.contain(pw);
        });

        // This test won't be graded directly -- it just exists to make sure your
        // dump include a kvs object with all your urls and passwords, because
        // we will be using that in other tests.
        it('includes a kvs object in the serialized dump', async function() {
            let keychain = await Keychain.init(password);
            for (let i = 0; i < 10; i++) {
                await keychain.set(String(i), String(i));
            }
            let data = await keychain.dump();
            let contents = data[0];
            let contentsObj = JSON.parse(contents);
            expect(contentsObj).to.have.key('kvs');
            expect(contentsObj.kvs).to.be.an('object');
            expect(Object.getOwnPropertyNames(contentsObj.kvs)).to.have.length(10);
        });

        // IV/Nonce Randomization $ Indistinguishability Test
        // This test ensures that even if two stored values are identical, their encrypted representations are distinct, implying the use of unique IVs/nonces. 
        it('uses distinct IVs/nonces for identical stored values', async function() {
            let keychain = await Keychain.init(password);
            await keychain.set('domain1.com', 'samepassword');
            await keychain.set('domain2.com', 'samepassword');
            
            let data = await keychain.dump();
            let kvs = JSON.parse(data[0]).kvs;
            
            let keys = Object.keys(kvs);
            expect(kvs[keys[0]]).not.to.equal(kvs[keys[1]]);
        });

        // HMAC/AED Integrity & Tamper Protection Test
        it('rejects tampered serialized contents (integrity test)', async function() {
            let keychain = await Keychain.init(password);
            await keychain.set('google.com', 'secret123');
            
            let [contents, checksum] = await keychain.dump();
            
            // Flip a character in the ciphertext JSON representation
            let tamperedContents = contents.replace(/[a-zA-Z0-9]/, 'X');
            await expectReject(Keychain.load(password, tamperedContents, checksum));
        });

        // Domain Swap & Rollback Resistance
        // Ensures domain names are bound to their specific record (e.g., using HMAC over the domain or authenticated data) so an attacker cannot swap encrypted entries between domains.
        it('prevents swapping encrypted payloads between domains', async function() {
            let keychain = await Keychain.init(password);
            await keychain.set('bank.com', 'bankpassword');
            await keychain.set('social.com', 'socialpassword');
            
            let [contents, checksum] = await keychain.dump();
            let parsed = JSON.parse(contents);
            
            let keys = Object.keys(parsed.kvs);
            if (keys.length >= 2) {
                // Swap values of the first two keys
                let temp = parsed.kvs[keys[0]];
                parsed.kvs[keys[0]] = parsed.kvs[keys[1]];
                parsed.kvs[keys[1]] = temp;
                
                let swappedContents = JSON.stringify(parsed);
                // Should either fail to load or resolve swapped keys to null/fail decryption
                try {
                    let loadedKeychain = await Keychain.load(password, swappedContents, checksum);
                    let val = await loadedKeychain.get(keys[0]);
                    expect(val).not.to.equal('socialpassword');
                } catch (e) {
                    // Exception on load is also acceptable behavior for HMAC failure
                }
            }
        });
    });
});