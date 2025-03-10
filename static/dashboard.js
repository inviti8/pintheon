
const load_encrypted_keystore = async () => {
    //window.constants.KEYSTORE
    await window.fn.loadJSONFileObject( authorize, true, ['node_data'] );
    //await window.fn.saveKeyStoreToStorage( ['node_data'] );
    //await window.fn.loadKeyStoreFromStorage(authorize);
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

const on_authorized = (data) => {

    console.log(data)

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
        window.rndr.nodeCardHeader(window.constants.LOGO, 'AXIEL', 'XRO Network');
        window.rndr.nodeInfo('test1234556789','test.com');
        window.rndr.networkTraffic('100', '99');

    };
});

window.fn.pushPage = function(page) {
    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| AXIEL ||', logo: window.constants.LOGO}});
};