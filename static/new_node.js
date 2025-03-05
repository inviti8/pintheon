const { KeyPair, get_languages } = wasm_bindgen;
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
    const addr = key_pair.address();
    const private_key = key_pair.secret();
    const seed = key_pair.seed(language_idx);


    return seed
};

const new_node = async () => {
    window.dlg.show('loading-dialog');

    let requestBody = JSON.stringify({
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'launch_token': await generateLaunchToken(document.querySelector('#launch-key').value),
        'seed_cipher': await generateSharedEncryptedText(document.querySelector('#xelis-seed-text').value, window.constants.SERVER_PUBLIC_KEY, window.constants.CLIENT_SESSION_KEYS.privateKey),
        'generator_pub': await exportKey(window.fn.generator_keys.publicKey),
      });

    fetch('/new_node', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: requestBody
      })
      .then(response => {
        console.log(response)
        if (response.status === 200) {
            return response.json();
        } else {
            window.dlg.hide('loading-dialog');
            window.dlg.show('fail-dialog');
            throw new Error('Request failed with status ' + response.status);
        }
      })
      .then(data => {
        window.dlg.hide('loading-dialog');
        window.fn.establish_data = data;
        // document.querySelector('#xelis-seed-text').value ="";
        // document.querySelector('#launch-key').value="";
        window.fn.pushPage('establish')
        console.log("establish : ",data);
          
      });
 
};

const create_keystore = async () => {

    let keystore = {
        'name': document.querySelector('#node-name').value,
        'descriptor': document.querySelector('#node-descriptor').value,
        'meta_data': document.querySelector('#node-meta-data').value,
        'generator_pub': await exportPublicKey(window.fn.generator_keys),
        'generator_priv': await exportPrivateKey(window.fn.generator_keys),
        'node_data': window.fn.establish_data
    };

    await window.fn.createEncryptedJSONFile( window.constants.KEYSTORE, keystore );
};

const on_session_keystore_loaded = async (obj) => {
    console.log('********************')
    console.log(obj)
    console.log('********************')

};

const on_keystore_loaded = async (obj) => {
    const keystore = await obj;
    window.fn.store(window.constants.KEYSTORE, keystore);
    console.log(window.fn.getStored(window.constants.KEYSTORE));
    await window.fn.loadStoredEncryptedJSONObject(window.constants.KEYSTORE, on_session_keystore_loaded);
};

const load_keystore = async () => {
    await window.fn.loadJSONFileObject(on_keystore_loaded, false, ['node_data']);
};

const establish = async () => {
    window.dlg.show('loading-dialog');

    let requestBody = JSON.stringify({
        'token': window.constants.SESSION_TOKEN.serialize(),
        'name': document.querySelector('#node-name').value,
        'descriptor': document.querySelector('#node-descriptor').value,
        'meta_data': document.querySelector('#node-meta-data').value
      });

    fetch('/establish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: requestBody
      })
      .then(response => {
        console.log(response)
        if (response.status === 200) {
            return response.json();
        } else {
            window.dlg.hide('loading-dialog');
            window.dlg.show('fail-dialog');
            throw new Error('Request failed with status ' + response.status);
        }
      })
      .then(data => {
        window.dlg.hide('loading-dialog');
        document.querySelector('#xelis-seed-text').value ="";
        document.querySelector('#launch-key').value="";
        window.fn.pushPage('establish')
        console.log("establish : ",data);
          
      });
 
};

document.addEventListener('init', function(event) {
    let page = event.target;
    let inputs = ['logo-file', 'key-store-file'];

    if (page.id === 'new_node') {

        document.querySelector('#generate-xelis-seed').onclick = function () {
            let seed = generate_xelis_wallet();
            document.querySelector('#xelis-seed-text').value = seed.splice(0, (seed.length+1)).join(" ");
        };
        document.querySelector('#establish-button').onclick = function () {
            //console.log(document.querySelector('#launch-key').value)
            window.fn.validateAllInputsAndCall(
                'Establish new Node?',
                 'All fields are required.',
                  new_node
                );
        };
    } else if (page.id === 'establish') {
        inputs.forEach(function(inp) {
            document.querySelector('#btn-'+inp).onclick = function () {
                document.querySelector('#'+inp).click();
            };
        });

        document.querySelector('#btn-key-store-file').onclick = function () {
            //create_keystore()
            load_keystore()
        };
        
        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
        window.rndr.nodeCardHeader(window.constants.LOGO, 'AXIEL', 'XRO Network');
    }
});

window.fn.pushPage = function(page) {
    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| ESTABLISH ||', logo: window.constants.LOGO}});
};