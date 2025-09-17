window.fn.generator_keys;
window.fn.establish_data;
window.fn.stellar_keys;

// load wasm wallet and generate wallet seed right away
async function init() {
    localStorage.removeItem('PINTHEON_SESSION');
    localStorage.removeItem('PINTHEON_NODE');
    window.fn.generator_keys = await generateClientKeys(true);
};

init();

const generate_wallet = async function () {

    if(StellarSdk==undefined)
        return;

    const randomBytes =  await getRandomBytes(32);
    const buf = Buffer.from(randomBytes);
    const seed = await entropyToBip39Mnemonic(buf);
    window.fn.stellar_keys = StellarSdk.Keypair.fromRawEd25519Seed(buf);

    return seed
};

const reset_init = async () => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY
    };

    window.fn.call(body, '/reset_init', complete);
};

const new_node = async () => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'launch_key' : document.querySelector('#launch-key').value,
        'launch_token': document.querySelector('#launch-token').value,
        'generator_pub': await exportKey(window.fn.generator_keys.publicKey),
    };

    window.fn.call(body, '/new_node', establishing);

};

const establishing = (data) => {
    if('error' in data){
        ons.notification.alert('The Stellar Wallet has an Insufficient balance.');
    }else{
        window.fn.establish_data = data;
        // document.querySelector('#launch-token').value ="";
        window.fn.pushPage('establish')
        console.log("establish : ",data);
    };
};

const create_keystore = async () => {

    let keystore = {
        'name': document.querySelector('#node-name').value,
        'descriptor': document.querySelector('#node-descriptor').value,
        'meta_data': document.querySelector('#node-meta-data').value,
        'generator_priv': await exportJWKCryptoKey(window.fn.generator_keys.privateKey),
        'generator_pub': await exportJWKCryptoKey(window.fn.generator_keys.publicKey),
        'node_data': window.fn.establish_data
    };

    await window.fn.createEncryptedJSONFile( window.constants.KEYSTORE, keystore, establish );
};

const establish = async () => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'name': document.querySelector('#node-name').value,
        'descriptor': document.querySelector('#node-descriptor').value,
        'meta_data': document.querySelector('#node-meta-data').value,
        'host': window.location.host
    };

    window.fn.call(body, '/establish', established);
};

const established = (data) => {
    const seedTxt = document.querySelector('#launch-token');
    
    if(seedTxt){
        document.querySelector('#launch-token').value ="";
    };
    
    console.log("establish : ",data);
    end_session();
};

const end_session = async () => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY
    };

    window.fn.call(body, '/end_session', complete);
};

const complete = () => {
    location.reload();
};

const open_token_gen = () => {
    window.open('https://https://pintheon-token.anvil.app/', '_blank').focus();
};


document.addEventListener('init', function(event) {
    let page = event.target;
    // let inputs = ['logo-file', 'key-store-file'];

    if (page.id === 'new_node') {

        // document.querySelector('#generate-seed').onclick = async function () {
        //     let seed = await generate_wallet();
        //     document.querySelector('#launch-token').value = seed;
        // };
        document.querySelector('#open-token-gen').onclick = function () {
            open_token_gen();
        };

        document.querySelector('#establish-button').onclick = function () {
            window.fn.validateAllInputsAndCall(
                'Establish new Node?',
                 'All fields are required.',
                  new_node
                );
        };

        document.querySelector('#new-node-logo').src = window.constants.LOGO;

    } else if (page.id === 'establish') {
        // inputs.forEach(function(inp) {
        //     document.querySelector('#btn-'+inp).onclick = function () {
        //         document.querySelector('#'+inp).click();
        //     };
        // });

        document.querySelector('#btn-establish-back').onclick = function () {
            reset_init();
        };

        document.querySelector('#btn-key-store-file').onclick = function () {
            create_keystore();
        };

        document.querySelector('#btn-establish').onclick = function () {
            establish();
        };

        // document.querySelector('#btn-load-key-store-file').onclick = function () {
        //     load_keystore()
        // };
        
        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
        window.rndr.nodeCardHeader(window.constants.LOGO, 'PINTHEON', 'XRO Network');
    }
});

window.fn.pushPage = function(page) {
    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| ESTABLISH ||', logo: window.constants.LOGO}});
};