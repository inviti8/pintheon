window.dash = {};
window.dash.SESSION_KEYS = 'AXIEL_SESSION';
window.dash.NODE = 'AXIEL_NODE';
window.dash.AUTHORIZED = false;

window.dash.CLIENT_PUBLIC_KEY;
window.dash.session_keys;
window.dash.node_data;


async function init() {

    let sess_keys = JSON.parse(localStorage.getItem(window.dash.SESSION_KEYS));
    let node = JSON.parse(localStorage.getItem(window.dash.NODE));

    if(sess_keys && node){
        window.dash.session_keys = await importJWKCryptoKeyPair(sess_keys['privateKey'], sess_keys['publicKey']);
        window.dash.node_data = node;
        window.dash.CLIENT_PUBLIC_KEY = await exportKey(sess_keys['publicKey']);
        const authToken = await generateNonceAuthToken(window.constants.SERVER_PUBLIC_KEY, window.dash.session_keys.privateKey, 'AXIEL_AUTH', node.nonce, node.expires);

        const body = {
            'auth_token': authToken.serialize(),
            'client_pub': window.dash.CLIENT_PUBLIC_KEY
        };
    
        window.fn.call(body, '/authorized', on_authorized)
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



    if (page.id === 'authorize') {

        document.querySelector('#authorize-button').onclick = function () {
            load_encrypted_keystore();
        };

    } else if (page.id === 'dashboard') {

        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
        window.rndr.nodeCardHeader(page.data.node['logo'], page.data.node['name'], page.data.node['descriptor']);
        window.rndr.nodeInfo('test1234556789','test.com');
        window.rndr.networkTraffic('100', '99');

    };
});

window.fn.pushPage = function(page, node_data, callback, ...args) {
    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| AXIEL ||', node: node_data}});
    if(callback){
        callback(...args);
    }
};