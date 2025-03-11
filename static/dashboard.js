window.dash = {};
window.dash.data;
window.dash.SESSION_KEYS = 'AXIEL_SESSION';
window.dash.NODE = 'AXIEL_NODE';
window.dash.AUTHORIZED = false;

window.dash.CLIENT_PUBLIC_KEY;
window.dash.session_keys;
window.dash.node_data;


async function init() {

    window.dash.data = { 'logo': '/static/hvym_logo.png', 'name': 'AXIEL', 'descriptor': 'XRO Network' };

    let sess_keys = JSON.parse(localStorage.getItem(window.dash.SESSION_KEYS));
    let node = JSON.parse(localStorage.getItem(window.dash.NODE));

    if(sess_keys && node){
        window.dash.session_keys = await importJWKCryptoKeyPair(sess_keys['privateKey'], sess_keys['publicKey']);
        window.dash.node_data = node;
        window.dash.CLIENT_PUBLIC_KEY = await exportKey(window.dash.session_keys.publicKey);
        const sessToken = await generateTimestampedAuthToken(window.constants.SERVER_PUBLIC_KEY, window.dash.session_keys.privateKey, node.expires);
        const authToken = await generateNonceTimestampAuthToken(window.constants.SERVER_PUBLIC_KEY, window.dash.session_keys.privateKey, 'AXIEL_AUTH', node.nonce, node.expires);

        const body = {
            'token': sessToken.serialize(),
            'auth_token': authToken.serialize(),
            'client_pub': window.dash.CLIENT_PUBLIC_KEY
        };

        let requestBody = JSON.stringify(body);
    
        fetch('/authorized', {
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
            window.dash.data = data;
            //on_authorized(data);
          });
    
    };
    
};

init();

const load_encrypted_keystore = async () => {
    await window.fn.loadJSONFileObject( authorize, true, ['node_data'] );
};

const authorize = async (prms) => {
    
    const keystore = await prms;
    console.log(keystore)
    window.fn.generator_keys = await importJWKCryptoKeyPair(keystore['generator_priv'], keystore['generator_pub']);
    const authToken = await generateNonceAuthToken(window.constants.SERVER_GENERATOR_PUBLIC_KEY, window.fn.generator_keys.privateKey, 'AXIEL_GENERATOR', window.constants.session_nonce);

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'auth_token': authToken.serialize(),
        'generator_pub': await exportKey(window.fn.generator_keys.publicKey),
    };

    window.fn.call(body, '/authorize', on_authorized);
};

const on_authorized = async (node) => {

    if(node.authorized){

        session_jwk = {'privateKey': await exportJWKCryptoKey(window.constants.CLIENT_SESSION_KEYS.privateKey), 'publicKey': await exportJWKCryptoKey(window.constants.CLIENT_SESSION_KEYS.publicKey)};
        window.fn.store(window.dash.SESSION_KEYS, session_jwk, 'local');
        window.fn.store(window.dash.NODE, node, 'local');
        window.dash.data = node;

        window.fn.pushPage('dashboard', node);
        console.log(node)
    };
    
};

document.addEventListener('init', function(event) {
    let page = event.target;

    //Element rendering methods:
    window.rndr.nodeInfo = function(multiaddress, url){

        let _updateElem = function(clone, elem, multiaddress, url){
            clone.querySelector('#'+elem+'-multiaddress').value = multiaddress;
            clone.querySelector('#'+elem+'-gateway-url').value = url;
        }

        window.rndr.RENDER_ELEM('node-info', _updateElem, multiaddress, url);
    };

    window.rndr.networkTraffic = function(incoming, outgoing){

        let _updateElem = function(clone, elem, incoming, outgoing){
            clone.querySelector('#'+elem+'-kbs-incoming').textContent = incoming;
            clone.querySelector('#'+elem+'-kbs-outgoing').textContent = outgoing;
        }

        window.rndr.RENDER_ELEM('network-traffic', _updateElem, incoming, outgoing);
    };

    window.rndr.dashboard = function(){

        window.rndr.nodeCardHeader(window.dash.data['logo'], window.dash.data['name'], window.dash.data['descriptor']);
        window.rndr.nodeInfo('test1234556789','test.com');
        window.rndr.networkTraffic('100', '99');

    };



    if (page.id === 'authorize') {

        document.querySelector('#authorize-button').onclick = function () {
            load_encrypted_keystore();
        };

    } else if (page.id === 'dashboard') {

        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
        window.rndr.dashboard();
        

    };
});

window.fn.pushPage = function(page, node_data, callback, ...args) {
    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| AXIEL ||', node: node_data}});
    if(callback){
        callback(...args);
    }
};