// This file is for shared application wide for cryptographic methods


const hex2ab = function(hex){
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) {return parseInt(h, 16)}));
}

const b64_to_ab = function(base64_string){
    return Uint8Array.from(atob(base64_string), c => c.charCodeAt(0));
}

const ab_to_b64 = function(arrayBuffer){
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}

const generateClientKeys = async () => {
    try {

        const keys = await window.crypto.subtle.generateKey(
            {
              name: "ECDH",
              namedCurve: "P-256",
            },
            false,
            ["deriveKey", "deriveBits"],
        );

        return keys;
    } catch (err) {
        console.error("Error in generating keys: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const loadKeypairFromJSON = async (unencryptedKeyStoreJSON) => {
    try {
        // Parse the JSON string into an object
        const unencryptedKeyStore = JSON.parse(unencryptedKeyStoreJSON);
        
        // Convert the base64 encoded strings back to ArrayBuffers for key generation
        const privateKeyArrayBuffer = Uint8Array.from(atob(unencryptedKeyStore.privateKey), c => c.charCodeAt(0));
        const publicKeyArrayBuffer = Uint8Array.from(atob(unencryptedKeyStore.publicKey), c => c.charCodeAt(0));
        
        // Convert the ArrayBuffers to CryptoKeys for key generation
        const privateKey = await window.crypto.subtle.importKey('raw', privateKeyArrayBuffer, {name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveKey', 'deriveBits']);
        const publicKey = await window.crypto.subtle.importKey('raw', publicKeyArrayBuffer, {name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveKey', 'deriveBits']);
        
        return { privateKey, publicKey };
    } catch (err) {
        console.error("Error in generating keys: ", err);
        throw err;   // Re-throw the error so it can be caught where this function is called.
    }
};

const hashKey = function(key){
    return window.crypto.subtle.digest('SHA-256', key).then(hash => {
        let result = Array.from(new Uint8Array(hash)).map(b => ('00' + b.toString(16)).slice(-2)).join('');
        return result;
    });
};

const generateEncryptedClientKeyStoreJSON = async (keys, password) => {
    try {
        const exportedPrivateKey = await window.crypto.subtle.exportKey('raw', keys.privateKey);
        const exportedPublicKey = await window.crypto.subtle.exportKey('raw', keys.publicKey);

        // Convert the ArrayBuffers to base64 strings for JSON
        const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));

        // Generate a key using the password
        const encoder = new TextEncoder();
        const passwordUint8Array = encoder.encode(password);
        const salt = crypto.getRandomValues(new Uint8Array(16));  // generate random salt
        const importedKey = await window.crypto.subtle.importKey('raw', passwordUint8Array, {name: 'PBKDF2'}, false, ['encrypt']);
        
        // Encrypt the keys with the generated key and the salt
        const encryptedPrivateKey = btoa(String.fromCharCode(...new Uint8Array(await window.crypto.subtle.encrypt({name: 'PBKDF2', salt}, importedKey, encoder.encode(privateKeyBase64)))));
        const encryptedPublicKey = btoa(String.fromCharCode(...new Uint8Array(await window.crypto.subtle.encrypt({name: 'PBKDF2', salt}, importedKey, encoder.encode(publicKeyBase64)))));
        
        // Create the keystore in JSON format with encrypted keys
        const keyStoreJSON = {
            privateKey: encryptedPrivateKey,
            publicKey: encryptedPublicKey,
            salt: btoa(String.fromCharCode(...salt)),  // store the salt for decryption
        };

        return keyStoreJSON;
    } catch (err) {
        console.error("Error in generating keys: ", err);
        throw err;   // Re-throw the error so it can be caught where this function is called.
    }
};

const decryptClientKeys = async (password, encryptedKeyStoreJSON) => {
    try {
        // Parse the JSON string into an object
        const encryptedKeyStore = JSON.parse(encryptedKeyStoreJSON);
        
        // Convert the base64 encoded strings back to ArrayBuffers for decryption
        const encryptedPrivateKeyBase64 = atob(encryptedKeyStore.privateKey);
        const encryptedPublicKeyBase64 = atob(encryptedKeyStore.publicKey);
        const saltBase64 = atob(encryptedKeyStore.salt);
        
        // Convert the base64 strings to ArrayBuffers for decryption
        const encryptedPrivateKeyArrayBuffer = Uint8Array.from(atob(encryptedPrivateKeyBase64), c => c.charCodeAt(0));
        const encryptedPublicKeyArrayBuffer = Uint8Array.from(atob(encryptedPublicKeyBase64), c => c.charCodeAt(0));
        const saltArrayBuffer = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
        
        // Generate a key using the password and the stored salt
        const encoder = new TextEncoder();
        const passwordUint8Array = encoder.encode(password);
        const importedKey = await window.crypto.subtle.importKey('raw', passwordUint8Array, {name: 'PBKDF2'}, false, ['decrypt']);
        
        // Decrypt the keys with the generated key and the salt
        const decryptedPrivateKeyArrayBuffer = new Uint8Array(await window.crypto.subtle.decrypt({name: 'PBKDF2', salt: saltArrayBuffer}, importedKey, encryptedPrivateKeyArrayBuffer));
        const decryptedPublicKeyArrayBuffer = new Uint8Array(await window.crypto.subtle.decrypt({name: 'PBKDF2', salt: saltArrayBuffer}, importedKey, encryptedPublicKeyArrayBuffer));
        
        // Convert the ArrayBuffers to base64 strings for JSON formatting and return an unencrypted keystore
        const decryptedPrivateKeyBase64 = btoa(String.fromCharCode(...decryptedPrivateKeyArrayBuffer));
        const decryptedPublicKeyBase64 = btoa(String.fromCharCode(...decryptedPublicKeyArrayBuffer));
        
        return {
            privateKey: decryptedPrivateKeyBase64,
            publicKey: decryptedPublicKeyBase64,
        };
    } catch (err) {
        console.error("Error in generating keys: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
}

const exportKey = async (key) => {
    try {
        const exported = await window.crypto.subtle.exportKey('spki', key);
        return btoa(String.fromCharCode(...new Uint8Array(exported)));  // Convert ArrayBuffer to base64 string.
    } catch (err) {
        console.error("Error in exporting public key: ", err);
        throw err;    // Re-throw the error so it can be caught where this function is called.
    }
};

const importServerPub = async (base64PEM) => {
    try {
        const bin = b64_to_ab(base64PEM.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', ''));

        const key = window.crypto.subtle.importKey(
            "spki", 
            bin,
            { name: "ECDH", namedCurve: "P-256" },
            true, 
            [] 
        );

        return key;
    } catch (err) {
        console.error("Error in importing key: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const generateSharedBits = async (serverPub, clientPriv) => {
    try {

        const bits = await window.crypto.subtle.deriveBits(
            { name: "ECDH", namedCurve: "P-256", public: serverPub },
            clientPriv, 
            256 
        );

        return bits;
    } catch (err) {
        console.error("Error in generating shared bits: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const generateSharedSecret = async (serverPub, clientPriv) => {
    try {

        const bits = await generateSharedBits(serverPub, clientPriv)
        
        return ab_to_b64(bits);
    } catch (err) {
        console.error("Error in generating shared secret: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const generateSharedKey = async (serverPub, clientPriv) => {
    try {

        const bits = await generateSharedBits(serverPub, clientPriv);

        const key = await window.crypto.subtle.importKey(
            "raw", 
            bits, 
            { name: "HKDF" }, 
            false, 
            ["deriveKey", "deriveBits"]
        );

        return key;
    } catch (err) {
        console.error("Error in generating shared secret: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const generateSessionToken = async (serverPub, clientPriv) => {
    try {

        let location = window.location.href;
        let secretKey = await generateSharedSecret(serverPub, clientPriv);
        let identifier = "AXIEL_SESSION";
        let token = window.MacaroonsBuilder.create(location, secretKey, identifier);

        return token;
    } catch (err) {
        console.error("Error in generating session token: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const generateToken = async (location, secret, identifier, firstPartCaveats, thirdPartyCaveat=undefined, caveatKey=undefined) => {
    try {

      let token;

      if(thirdPartyCaveat!=undefined){
        token = new MacaroonsBuilder(location, secret, identifier)
        .add_first_party_caveat(firstPartCaveats.map(caveat => `${caveat}`)).join()
        .add_third_party_caveat(thirdPartyCaveat, caveatKey, identifier).join()
        .getMacaroon();
      }else{
        token = new MacaroonsBuilder(location, secret, identifier)
        .add_first_party_caveat(firstPartCaveats.map(caveat => `${caveat}`)).join()
        .getMacaroon();
      };
      
        return token;
    } catch (err) {
        console.error("Error in generating session token: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};