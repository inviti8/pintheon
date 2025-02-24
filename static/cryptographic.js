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

const generateClientKeyStore = async () => {
    try {
        const keys = await generateClientKeys();
        
        const exportedPrivateKey = await window.crypto.subtle.exportKey('raw', keys.privateKey);
        const exportedPublicKey = await window.crypto.subtle.exportKey('raw', keys.publicKey);

        // Convert the ArrayBuffers to base64 strings for JSON
        const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));

        // Create the keystore in JSON format
        const keyStoreJSON = {
            privateKey: privateKeyBase64,
            publicKey: publicKeyBase64,
        };

        return keyStoreJSON;
    } catch (err) {
        console.error("Error in generating keys: ", err);
        throw err;   // Re-throw the error so it can be caught where this function is called.
    }
};

const exportPublicKey = async (keyPair) => {
    try {
        const exported = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
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