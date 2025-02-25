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

function ab2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
};

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

async function getCryptoKey(password) {
    const encoder = new TextEncoder();
    const keyMaterial = encoder.encode(password);
    return crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
}

async function deriveKey(password, salt) {
    const keyMaterial = await getCryptoKey(password);
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
};


async function generateEncryptedText(text, password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encoder.encode(text)
    );

    return {
        cipherText: ab2hex(encrypted),
        iv: ab2hex(iv),
        salt: ab2hex(salt)
    };
};

async function generateDecryptedText(encryptedData, password) {
    const { cipherText, iv, salt } = encryptedData;
    const key = await deriveKey(password, hex2ab(salt));

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hex2ab(iv) },
        key,
        hex2ab(cipherText)
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}

const generateSharedEncryptedText = async (txt, serverPub, clientPriv) => {
    const secret = await generateSharedSecret(serverPub, clientPriv);
    const cipherTxt = await generateEncryptedText(txt, secret);

    return cipherTxt
};

const generateEncryptedClientKeyStoreJSON = async (keys, password) => {
    try {
        const exportedPrivateKey = await window.crypto.subtle.exportKey('raw', keys.privateKey);
        const exportedPublicKey = await window.crypto.subtle.exportKey('raw', keys.publicKey);

        // Convert the ArrayBuffers to base64 strings for JSON
        const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
        
        // Encrypt the keys with the generated key and the salt
        const encryptedPrivateKey = generateEncryptedText(password, privateKeyBase64);
        const encryptedPublicKey = generateEncryptedText(password, publicKeyBase64);
        
        // Create the keystore in JSON format with encrypted keys
        const keyStoreJSON = {
            privateKey: encryptedPrivateKey,
            publicKey: encryptedPublicKey
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
        
        return {
            privateKey: generateDecryptedText(encryptedKeyStore.privateKey, password),
            publicKey: generateDecryptedText(encryptedKeyStore.publicKey, password),
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

const generateLaunchToken = async (launchKey) => {
    try {

        let location = window.location.href;
        let identifier = "AXIEL_LAUNCH";
        let token = window.MacaroonsBuilder.create(location, hashKey(launchKey), identifier);

        return token;
    } catch (err) {
        console.error("Error in generating launch token: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const generateSessionToken = async (serverPub, clientPriv) => {
    try {

        let token = window.MacaroonsBuilder.create(window.location.href, await generateSharedSecret(serverPub, clientPriv), "AXIEL_SESSION");

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