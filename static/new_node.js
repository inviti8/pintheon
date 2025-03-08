const { KeyPair, get_languages } = wasm_bindgen;
const xelis_wallet = { 'address': undefined, 'priv': undefined, 'seed': undefined };
window.fn.generator_keys;
window.fn.establish_data;

// load wasm wallet and generate wallet seed right away
async function init() {
    await wasm_bindgen();
    window.fn.generator_keys = await generateClientKeys(true);
};

init();

const generate_xelis_wallet = function () {
  
    const mainnet = "mainnet";
    const language_idx = 0;
  
    const key_pair = new KeyPair(mainnet);
    xelis_wallet.address = key_pair.address();
    xelis_wallet.priv = key_pair.secret();
    xelis_wallet.seed = key_pair.seed(language_idx);


    return xelis_wallet
};

const new_node = async () => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'launch_token': await generateLaunchToken(document.querySelector('#launch-key').value),
        'seed_cipher': await generateSharedEncryptedText(document.querySelector('#xelis-seed-text').value, window.constants.SERVER_PUBLIC_KEY, window.constants.CLIENT_SESSION_KEYS.privateKey),
        'generator_pub': await exportKey(window.fn.generator_keys.publicKey),
    };

    window.fn.call(body, '/new_node', establishing);

};

const establishing = (data) => {
    window.fn.establish_data = data;
    // document.querySelector('#xelis-seed-text').value ="";
    // document.querySelector('#launch-key').value="";
    window.fn.pushPage('establish')
    console.log("establish : ",data);
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

    await window.fn.createEncryptedJSONFile( window.constants.KEYSTORE, keystore );

    window.rndr.showELem('btn-establish');
};

const establish = async () => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'name': document.querySelector('#node-name').value,
        'descriptor': document.querySelector('#node-descriptor').value,
        'meta_data': document.querySelector('#node-meta-data').value
    };

    window.fn.call(body, '/establish', established);
};

const established = (data) => {
    document.querySelector('#xelis-seed-text').value ="";
    document.querySelector('#launch-key').value="";
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

const complete = (data) => {
    location.reload();
};



document.addEventListener('init', function(event) {
    let page = event.target;
    // let inputs = ['logo-file', 'key-store-file'];

    if (page.id === 'new_node') {

        document.querySelector('#generate-xelis-seed').onclick = function () {
            let seed = generate_xelis_wallet().seed;
            document.querySelector('#xelis-seed-text').value = seed.splice(0, (seed.length+1)).join(" ");
        };
        document.querySelector('#establish-button').onclick = function () {
            window.fn.validateAllInputsAndCall(
                'Establish new Node?',
                 'All fields are required.',
                  new_node
                );
        };
    } else if (page.id === 'establish') {
        // inputs.forEach(function(inp) {
        //     document.querySelector('#btn-'+inp).onclick = function () {
        //         document.querySelector('#'+inp).click();
        //     };
        // });

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
        window.rndr.nodeCardHeader(window.constants.LOGO, 'AXIEL', 'XRO Network');
    }
});

window.fn.pushPage = function(page) {
    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| ESTABLISH ||', logo: window.constants.LOGO}});
};