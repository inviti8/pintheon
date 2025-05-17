window.dash = {};
window.dash.data = { 'logo': '/static/hvym_logo.png', 'name': 'PHILOS', 'descriptor': 'XRO Network', 'file_list': [], 'peer_list': [], 'session_token':undefined, 'auth_token':undefined };
window.dash.SESSION_KEYS = 'PHILOS_SESSION';
window.dash.NODE = 'PHILOS_NODE';
window.dash.AUTHORIZED = false;
window.dash.USING_STORED_SESSION = false;

window.dash.CLIENT_PUBLIC_KEY;
window.dash.session_keys;
window.dash.node_data;



function _updateDashData(data){
    Object.keys(data).forEach((k, i) => {
        if (k in window.dash.data){
            window.dash.data[k] = data[k];
        };
    });
};

function _getSessionData(){
    let token = window.constants.SESSION_TOKEN;
    let pub = window.constants.CLIENT_PUBLIC_KEY;

    if(window.dash.USING_STORED_SESSION ){
        token = window.dash.data.session_token;
        pub = window.dash.CLIENT_PUBLIC_KEY;
    };

    return { 'token': token, 'pub': pub }
};

async function init() {

    let sess_keys = JSON.parse(localStorage.getItem(window.dash.SESSION_KEYS));
    let node = JSON.parse(localStorage.getItem(window.dash.NODE));

    if(sess_keys && node){
        window.dash.USING_STORED_SESSION = true
        window.dash.session_keys = await importJWKCryptoKeyPair(sess_keys['privateKey'], sess_keys['publicKey']);
        window.dash.node_data = node;
        window.dash.CLIENT_PUBLIC_KEY = await exportKey(window.dash.session_keys.publicKey);
        window.dash.data.session_token = await generateTimestampedAuthToken(window.constants.SERVER_PUBLIC_KEY, window.dash.session_keys.privateKey, node.expires );
        window.dash.data.auth_token = await generateNonceTimestampAuthToken(window.constants.SERVER_PUBLIC_KEY, window.dash.session_keys.privateKey, 'PHILOS_AUTH', node.nonce, node.expires );

        const body = {
            'token': window.dash.data.session_token.serialize(),
            'auth_token': window.dash.data.auth_token.serialize(),
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
            _updateDashData(data)
            window.rndr.dashboard();
          });
    
    };
    
};

init();

const load_encrypted_keystore = async () => {
    await window.fn.loadJSONFileObject( authorize, true, ['node_data'] );
};

const authorize = async (prms) => {
    
    const keystore = await prms;
    window.fn.generator_keys = await importJWKCryptoKeyPair(keystore['generator_priv'], keystore['generator_pub']);
    const authToken = await generateNonceAuthToken(window.constants.SERVER_GENERATOR_PUBLIC_KEY, window.fn.generator_keys.privateKey, 'PHILOS_GENERATOR', window.constants.session_nonce);

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
        _updateDashData(node);

        window.fn.pushPage('dashboard', node);
    };
    
};

const deauthorize = async () => {

    const session = _getSessionData();

    const body = {
        'token': session.token.serialize(),
        'client_pub': session.pub
    };

    window.fn.call(body, '/deauthorize', logged_out);
};

const logged_out = () => {
    localStorage.removeItem(window.dash.SESSION_KEYS);
    localStorage.removeItem(window.dash.NODE);
    location.reload();
};

const upload_file_dlg = async (callback) => {
    window.dlg.showLoadFileDlg('upload-file-dialog', callback, false, [], 'FILE');
};

const upload_logo_dlg = async (callback) => {
    window.dlg.showLoadFileDlg('upload-logo-file-dialog', callback, false, [], 'FILE');
};

const update_logo = async (file) => {
    if( !file['type'].split('/')[0] === 'image')
        ons.notification.alert('File must be an image');
        return

    const session = _getSessionData();

    if(file){
        const formData = new FormData()

        formData.append('token', session.token.serialize());
        formData.append('client_pub', session.pub);
        formData.append('file', file);
        await window.fn.uploadFile(file, formData, '/update_logo', logo_updated);
    };
};

const logo_updated = (node_data) => {

    console.log(node_data)
    _updateDashData(node_data);
    window.rndr.dashboard();

};

const upload_file = async (file) => {

    const session = _getSessionData();

    if(file){
        const formData = new FormData()

        formData.append('token', session.token.serialize());
        formData.append('client_pub', session.pub);
        formData.append('file', file);
        await window.fn.uploadFile(file, formData, '/upload', file_updated);
    };
};

const file_updated = (fileList) => {

    console.log(fileList)
    _updateDashData({ 'file_list': fileList });
    window.rndr.dashboard();
    //window.rndr.fileListItems(fileList)

};

const remove_file = async (cid) => {

    const session = _getSessionData();

    if(cid){
        const formData = new FormData()

        formData.append('token', session.token.serialize());
        formData.append('client_pub', session.pub);
        formData.append('cid', cid);
        await window.fn.removeFile( formData, '/remove_file', file_updated);
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

    window.rndr.fileListItems = function(fileList){

        if(fileList.length===0)
            return;

        let _updateElem = function(clone, i, fileList){
            let fileUrl = 'https://' + window.location.host + '/ipfs/' + fileList[i]['CID'];
            let fileType = fileList[i]['Type'];
            let icon = window.icons.UNKNOWN;

            if(fileType.includes('image')){
                icon = fileUrl;
            }else if (fileType=='application/zip'||fileType=='application/x-7z-compressed'){
                icon = window.icons.ZIP;
            }else if (fileType=='application/pdf'){
                icon = window.icons.PDF;
            }else if (fileType=='application/octet-stream'||fileType=='text/plain'){
                icon = window.icons.TXT;
            }else if (fileType=='application/msword'||fileType=='application/vnd.openxmlformats-officedocument.wordprocessingml.document'){
                icon = window.icons.WORD;
            }else if (fileType=='application/vnd.ms-excel'||fileType=='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'){
                icon = window.icons.XLS;
            }else if (fileType=='text/html'){
                icon = window.icons.WEB;
            }else if (fileType=='audio/mpeg'){
                icon = window.icons.MP3;
            }else if (fileType=='audio/mp4'){
                icon = window.icons.MOV;
            }else if (fileType=='audio/wav'){
                icon = window.icons.WAV;
            }else if (fileType=='application/vnd.ms-powerpoint'){
                icon = window.icons.PPT;
            }
            console.log('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            console.log(fileUrl)
            console.log('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')

            clone.querySelector('#file-list-item-icon').src = icon;
            clone.querySelector('.truncate').textContent = fileList[i]['Name'];
            clone.querySelector('.file-size').textContent = fileList[i]['Size'];
            clone.querySelector('.file_url').href = fileUrl;
            clone.querySelector('.file_url').textContent = fileList[i]['CID'];
            clone.querySelector('#file-remove').setAttribute('onclick', 'remove_file("' + fileList[i]['CID'] + '")');
            clone.querySelector('#copy-file-url').setAttribute('onclick', 'fn.copyToClipboard("' + fileUrl + '")');
            if(fileList[i]['IsLogo'] == true){clone.querySelector('.logo').innerHTML = '<ons-icon class="right" icon="fa-star"></ons-icon>'};
        }

        window.rndr.RENDER_LIST('file-list-items', fileList, _updateElem, fileList);
    };

    window.rndr.peerListItems = function(peerList){

        let _updateElem = function(clone, i, peerList){
            clone.querySelector('ons-input').setAttribute('id', 'remove-multiaddress-' + i);
            clone.querySelector('ons-input').setAttribute('value', peerList[i]);
            clone.querySelector('ons-button').setAttribute('onclick', 'fn.bootstrapPeer("' + i + '")');
        }

        window.rndr.RENDER_LIST('peer-list-items', peerList, _updateElem, peerList);
    };

    window.rndr.dashboard = function(){

        document.querySelector('ons-toolbar .center').innerHTML = window.dash.data.name;
        window.rndr.nodeCardHeader(window.dash.data['logo'], window.dash.data.name, window.dash.data.descriptor);
        window.rndr.nodeInfo('test1234556789', window.location.host);
        window.rndr.networkTraffic('100', '99');
        window.rndr.fileListItems(window.dash.data.file_list);

    };


    if (page.id === 'authorize') {

        document.querySelector('#authorize-button').onclick = function () {
            load_encrypted_keystore();
        };

    } else if (page.id === 'dashboard') {

        document.querySelector('#deauthorize-button').onclick = function () {
            deauthorize();
        };

        document.querySelector('#update-logo-button').onclick = function () {
            upload_logo_dlg(update_logo);
        };

        document.querySelector('#upload-button').onclick = function () {
            upload_file_dlg(upload_file);
        };

        window.rndr.dashboard();

    };
});

window.fn.pushPage = function(page, node_data) {
    document.querySelector('#Nav').pushPage(page+'.html');
};