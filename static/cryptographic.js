// This file is for shared application wide for cryptographic methods


const hex2ab = function(hex){
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) {return parseInt(h, 16)}));
};

const b64_to_ab = function(base64_string){
    return Uint8Array.from(atob(base64_string), c => c.charCodeAt(0));
};

const ab_to_b64 = function(arrayBuffer){
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
};

function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
};

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
};

function ab2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
};

function b2ab(b64) {
    const str = atob(b64);  // Convert from Base64 back to original string
    let ab = new Uint8Array(str.length);
    for (let i = 0; i < str.length; ++i) {
        ab[i] = str.charCodeAt(i);
    }
    return ab;
};

const removeNullBytes = function(str){
    return str.split("").filter(char => char.codePointAt(0)).join("")
};

const generateClientKeys = async (extractable=true) => {
    try {

        const keys = await window.crypto.subtle.generateKey(
            {
              name: "ECDH",
              namedCurve: "P-256",
            },
            extractable,
            ["deriveKey", "deriveBits"],
        );

        return keys;
    } catch (err) {
        console.error("Error in generating keys: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

function padKey(key) {
    const textEncoder = new TextEncoder();
    let keyBytes = textEncoder.encode(key);
    if (keyBytes.length > 32){
        keyBytes = keyBytes.slice(0, 32)

    }else if (keyBytes.length < 32) {
         let padding = new Uint8Array(32 - keyBytes.length);
         keyBytes = new Uint8Array([...keyBytes, ...padding]);
     }
    return keyBytes;
};

const encryptAES = async function(data, key) {
    const textEncoder = new TextEncoder();
    let keyBytes = textEncoder.encode(key);

    if (keyBytes.length > 32){
        keyBytes = keyBytes.slice(0, 32)

    }else if (keyBytes.length < 32) {
         let padding = new Uint8Array(32 - keyBytes.length);
         keyBytes = new Uint8Array([...keyBytes, ...padding]);
    };

    // Generate a random IV (16 bytes)
    const iv = crypto.getRandomValues(new Uint8Array(16));

    // Convert the JSON data to bytes and apply PKCS7 padding (similar to Python's pad)
    let dataBytes = textEncoder.encode(JSON.stringify(data));

    const paddedData = new Uint8Array(16 - dataBytes.length % 16); // Create an array of padding bytes

    dataBytes = new Uint8Array([...dataBytes, ...paddedData]); // Combine the original and padding arrays

    let encryptedData;
    try {
        const keyObj = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['encrypt']);
        encryptedData = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, keyObj, dataBytes);

        // Return the base64 encoded IV concatenated with the encrypted data
    return btoa(String.fromCharCode(...new Uint8Array([...iv, ...new Uint8Array(encryptedData)])));

    } catch(e) { console.error("Failed to import key"); throw e; }


};

const decryptAES = async function(data, key) {
    const byteArray = Uint8Array.from(atob(data), c => c.charCodeAt(0)); 
     
    let paddedKey = await padKey(key);
             
    const iv = byteArray.slice(0,16); // This should be equal to block size
    const encrypted_data = byteArray.slice(16);
              
    const algorithmIdentifier = { name: "AES-CBC", iv: iv }; 
    
    let cryptoKey =  await window.crypto.subtle.importKey("raw", paddedKey, algorithmIdentifier, false, ["decrypt"]);  
               
    return await window.crypto.subtle.decrypt(algorithmIdentifier, cryptoKey, encrypted_data).then(function(decryptedData){
        decoded = new Uint8Array(decryptedData) ; 
        
        let result='';
        for (let i = 0; i < decoded.length; ++i) {
            result += String.fromCharCode(decoded[i]);
        }
     return removeNullBytes(result);
    }); 
};

const  encryptJsonObject = async function(obj, password) {
    let ob = structuredClone(obj);
    for (let key in obj) {
      // Checking if value is an object and not null
      if (typeof obj[key] === 'object' && obj[key] !== null){
        ob[key] = await encryptJsonObject(obj[key]);
      } else if (typeof obj[key] === 'string'){ 
          ob[key] = await encryptAES(obj[key], password);
      }
    }

    return ob
};

const  decryptJsonObject = async function(obj, password) {
    let ob = structuredClone(obj);
    for (let key in obj) {
      // Checking if value is an object and not null
      if (typeof obj[key] === 'object' && obj[key] !== null){
        ob[key] = await decryptJsonObject(obj[key]);
      } else if (typeof obj[key] === 'string'){ 
          ob[key] = await decryptAES(obj[key], password);
          ob[key] = ob[key].replace(`/\\r|\\n|\\/|\"/g`, "").replace(/"/g, "")
      }
    }

    return ob
};

const exportPublicKey = async (keys) => {
    try {
        const spki = await window.crypto.subtle.exportKey('spki', keys.publicKey);
        const exportedAsString = ab2str(spki);
        
        return btoa(exportedAsString);
     } catch (err) {
       console.error("Error in exporting public key: ", err);
       throw err;  
    }
};

const exportPrivateKey = async (keys) => {
    try {
        const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', keys.privateKey);
        const exportedAsString = ab2str(pkcs8);
        
        return btoa(exportedAsString);
     } catch (err) {
       console.error("Error in exporting private key: ", err);
       throw err;  
    }
};


const exportJWKCryptoKey = async (key) => {
    try {
        return  await window.crypto.subtle.exportKey("jwk", key);
     } catch (err) {
       console.error("Error in exporting jwk key: ", err);
       throw err;  
    }
};

const importJWKCryptoPrivateKey = async (jwk) => {
    try {
        return  await window.crypto.subtle.importKey(
            "jwk",
            jwk,
            {
              name: "ECDH",
              namedCurve: "P-256",
            },
            true,
            ["deriveKey", "deriveBits"],
        );
     } catch (err) {
       console.error("Error in importing jwk private key: ", err);
       throw err;  
    }
};

const importJWKCryptoPublicKey = async (jwk) => {
    try {
        return  await window.crypto.subtle.importKey(
            "jwk",
            jwk,
            {
              name: "ECDH",
              namedCurve: "P-256",
            },
            true,
            [],
        );
     } catch (err) {
       console.error("Error in importing jwk public key: ", err);
       throw err;  
    }
};

const importJWKCryptoKeyPair = async (jwkPriv, jwkPub) => {
    try {
        const priv = await importJWKCryptoPrivateKey(jwkPriv);
        const pub = await importJWKCryptoPublicKey(jwkPub);
        return { privateKey: priv, publicKey: pub }
     } catch (err) {
       console.error("Error in importing jwk keys: ", err);
       throw err;  
    }
};

const getCryptoKey = async (password) => {
    const encoder = new TextEncoder();
    const keyMaterial = encoder.encode(password);
    return crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
};

const deriveKey = async (password, salt) => {
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

const generateSharedEncryptedText = async (txt, serverPub, clientPriv) => {
    const secret = await generateSharedSecret(serverPub, clientPriv);
    const cipherTxt = await encryptAES(txt, secret);

    return cipherTxt
};

const exportKey = async (key, format='spki') => {
    try {
        const exported = await window.crypto.subtle.exportKey(format, key);
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

        let location = '';
        let identifier = "AXIEL_LAUNCH_TOKEN";
        let token = window.MacaroonsBuilder.create(location, launchKey, identifier);

        return token.serialize();
    } catch (err) {
        console.error("Error in generating launch token: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};

const generateAuthToken = async (serverPub, clientPriv) => {
    try {

        let token = window.MacaroonsBuilder.create(window.location.href, await generateSharedSecret(serverPub, clientPriv), "AXIEL_SESSION");

        return token;
    } catch (err) {
        console.error("Error in generating session token: ", err);
        throw err;  // Re-throw the error so it can be caught where this function is called.
    }
};