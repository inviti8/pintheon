window.dash = {};
window.dash.data = { 'logo': '/static/hvym_logo.png', 'name': 'PHILOS', 'descriptor': 'XRO Network', 'host': window.location.host, 'customization': {}, 'repo': {}, 'stats': null, 'file_list': [], 'peer_id':"", 'peer_list': [], 'session_token':undefined, 'auth_token':undefined };
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
        
    };
};

const tokenize_file_prompt = async (name, cid) => {
    window.dlg.showAndRender('tokenize-file-dialog', window.rndr.tokenize_file_dlg, name, cid);
};

const tokenize_file = async (cid) => {
    let allocation = document.querySelector('#tokenize-file-dialog-amount').value;
    const session = _getSessionData();
    const formData = new FormData()

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    formData.append('cid', cid);
    formData.append('allocation', allocation);
    await window.fn.tokenizeFile(formData, '/tokenize_file', file_tokenized, 'POST', 'tokenize-file-dialog');
};

const file_tokenized = (node_data) => {
    console.log(node_data)
    _updateDashData(node_data);
    window.rndr.dashboard();
};

const send_file_token_prompt = async (name, cid) => {
    window.dlg.showAndRender('send-file-token-dialog', window.rndr.send_file_token_dlg, name, cid);
};

const send_file_token = async (cid) => {
    let amount = document.querySelector('#send-file-token-dialog-amount').value;
    let to_address = document.querySelector('#send-file-token-dialog-to-address').value;
    const session = _getSessionData();
    const formData = new FormData();
    

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    formData.append('cid', cid);
    formData.append('to_address', to_address);
    formData.append('amount', amount);

    await window.fn.tokenizeFile(formData, '/send_file_token', file_token_sent);
};

const file_token_sent = (node_data) => {
    console.log(node_data)
    _updateDashData(node_data);
    window.rndr.dashboard();
};

const dash_data = async (callback) => {
    const session = _getSessionData();
    const formData = new FormData()

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    await window.fn.dashData( formData, '/dashboard_data', callback);
};

const dash_updated = (node) => {
    _updateDashData(node);
    window.rndr.dashboard();
};

const settings_updated = (node) => {
    _updateDashData(node);
    window.fn.pushPage('settings', node, window.rndr.settings);
};

const update_gateway = async (gateway) => {

    const session = _getSessionData();

    const formData = new FormData();

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    formData.append('gateway', gateway);
    await window.fn.updateGateway(formData, '/update_gateway', gateway_updated);
};

const gateway_updated = (node_data) => {

    console.log(node_data)
    _updateDashData(node_data);
    window.rndr.settings();
    //window.location.reload();

};

const update_theme = async (theme) => {

    const session = _getSessionData();

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'theme': theme,
    };
        
    await window.fn.call(body, '/update_theme', theme_updated);
};

const theme_updated = (data) => {

    console.log(data)
    _updateDashData({ 'customization': data.customization });
    window.rndr.settings();
    window.location.reload();
    window.fn.pushPage('settings', data);

};

const upload_bg_img_dlg = async (callback) => {
    window.dlg.showLoadFileDlg('upload-bg-img-dialog', callback, false, [], 'FILE');
};

const update_bg_img = async (file) => {

    const session = _getSessionData();

    if(file){
        const formData = new FormData();

        formData.append('token', session.token.serialize());
        formData.append('client_pub', session.pub);
        formData.append('file', file);
        await window.fn.uploadFile(file, formData, '/update_bg_img', bg_img_updated);
    };
};

const bg_img_updated = (node_data) => {

    console.log(node_data)
    _updateDashData(node_data);
    window.rndr.dashboard();
    window.location.reload();

};

const remove_bg = async () => {
    const session = _getSessionData();
    const formData = new FormData()

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
        
    await window.fn.removeBg(formData, '/remove_bg_img', bg_removed);
};

const bg_removed = (data) => {

    console.log(data)
    _updateDashData({ 'customization': data.customization });
    window.rndr.settings();
    window.location.reload();
    window.fn.pushPage('settings', data);

};

const copy_peer_id = () => {
    let multiaddress = document.querySelector('#settings-info-multiaddress').value;
    fn.copyToClipboard(multiaddress);
};


document.addEventListener('init', function(event) {
    let page = event.target;

    //Element rendering methods:
    window.rndr.updateBg = function(){
        let nav = document.querySelector('#Nav');
        let currentPage = nav.topPage;
        if(window.constants.HAS_BG_IMG && !ons.modifier.contains(currentPage, 'full_bg')){
            ons.modifier.remove(currentPage, 'gradient');
            ons.modifier.add(currentPage, 'full_bg');
        };
    }

    window.rndr.nodeInfo = function(repo_size, storage_max, percentage){

        let _updateElem = function(clone, elem, repo_size, storage_max, percentage){
            clone.querySelector('#'+elem+'-repo-size').innerHTML = " "+repo_size+" mb";
            clone.querySelector('#'+elem+'-storage-max').innerHTML= " "+storage_max+" mb";
            clone.querySelector('#'+elem+'-repo-graph').setAttribute('value', percentage);
        }

        window.rndr.RENDER_ELEM('node-info', _updateElem, repo_size, storage_max, percentage);
    };

    window.rndr.networkTraffic = function(incoming, outgoing){

        let _updateElem = function(clone, elem, incoming, outgoing){
            clone.querySelector('#'+elem+'-kbs-incoming').textContent = incoming + ' Kb/s incoming';
            clone.querySelector('#'+elem+'-kbs-outgoing').textContent = outgoing + ' Kb/s outgoing';
        }

        window.rndr.RENDER_ELEM('network-traffic', _updateElem, incoming, outgoing);
    };

    window.rndr.fileListItems = function(host, fileList){

        if(fileList.length===0)
            return;

        let _updateElem = function(clone, i, host, fileList){
            let fileUrl = host + '/ipfs/' + fileList[i]['CID'];
            let fileName = fileList[i]['Name'];
            let fileType = fileList[i]['Type'];
            let cid = fileList[i]['CID']
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
            clone.querySelector('.file-name').textContent = fileName;
            clone.querySelector('.file_url').href = fileUrl;
            clone.querySelector('.file_url').textContent = cid;
            clone.querySelector('#file-remove').setAttribute('onclick', 'remove_file("' + cid + '")');
            clone.querySelector('#copy-file-url').setAttribute('onclick', 'fn.copyToClipboard("' + fileUrl + '")');
            if (fileList[i]['IsLogo'] == true){clone.querySelector('.special_icon').insertAdjacentHTML('beforeend','<ons-icon class="right" icon="fa-star"></ons-icon>');};
            if (fileList[i]['IsBgImg'] == true){clone.querySelector('.special_icon').insertAdjacentHTML('beforeend','<ons-icon class="right" icon="fa-photo"></ons-icon>');};
            if(fileList[i]['ContractID'].length > 0){
                clone.querySelector('.special_icon').insertAdjacentHTML('beforeend','<ons-icon class="right" icon="fa-diamond"></ons-icon>');
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="send-button" class="scale-on-hover center-both" modifier="outline" onclick="send_file_token_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+' )"><ons-icon icon="fa-paper-plane"></ons-icon>_send</ons-button>');
            }else{
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="tokenize-button" class="scale-on-hover center-both" modifier="outline" onclick="tokenize_file_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+' )"><ons-icon icon="fa-diamond"></ons-icon>_tokenize</ons-button>');
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="send-button" class="scale-on-hover center-both" modifier="outline" onclick="send_file_token_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+' )" disabled><ons-icon icon="fa-paper-plane"></ons-icon>_send</ons-button>');
            }
        }

        window.rndr.RENDER_LIST('file-list-items', fileList, _updateElem, host, fileList);
    };

    window.rndr.settingsNodeInfo = function(multiaddress, url){

        let _updateElem = function(clone, elem, multiaddress, url){
            clone.querySelector('#'+elem+'-multiaddress').value = multiaddress;
            clone.querySelector('#'+elem+'-gateway-url').value = url;
            clone.querySelector('#'+elem+'-copy-peer-id').setAttribute('onclick', 'copy_peer_id()');
        }

        window.rndr.RENDER_ELEM('settings-info', _updateElem, multiaddress, url);
    };

    window.rndr.settingsAppearance = function(selected_theme, themes, bg_img){

        let _updateElem = function(clone, elem, selected_theme, themes, bg_img){
            let sel = clone.querySelector('#'+elem+'-select');
            for (let i = 0; i < themes.length; i++) {
                sel.firstChild.insertAdjacentHTML('beforeend', '<option value="'+themes[i]+'">'+themes[i]+'</option>')
            }
            sel.setAttribute('select-id', themes[selected_theme]);
            sel.value = themes[selected_theme];
        }

        window.rndr.RENDER_ELEM('settings-appearance', _updateElem, selected_theme, themes, bg_img);
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

        console.log('window.dash:')
        console.log(window.dash)
        
        document.querySelector('ons-toolbar .center').innerHTML = window.dash.data.name;
        window.rndr.nodeCardHeader(window.dash.data.logo, window.dash.data.name, window.dash.data.descriptor);
        window.rndr.nodeInfo(window.dash.data.repo.RepoSize, window.dash.data.repo.StorageMax, window.dash.data.repo.usedPercentage);
        window.rndr.networkTraffic('100', '99');
        window.rndr.fileListItems(window.dash.data.host, window.dash.data.file_list);

    };

    window.rndr.settings = function(){
        window.rndr.settingsNodeInfo(window.dash.data.peer_id, window.dash.data.host);
        window.rndr.settingsAppearance(window.dash.data.customization.current_theme, window.dash.data.customization.themes, window.dash.data.customization.bg_img);
        let gateway = document.querySelector('#settings-info-gateway-url');
        let update_gateway_btn = document.querySelector('#settings-info-update-gateway');
        let theme_select = document.querySelector('#settings-appearance-select');
        let upload_btn = document.querySelector('#settings-appearance-bg-button');
        let remove_btn = document.querySelector('#settings-appearance-remove-bg-button');

        if(window.constants.HAS_BG_IMG){
            remove_btn.disabled = false;
        };

        update_gateway_btn.onclick = function (){
            update_gateway(gateway.value);
        };

        theme_select.onchange = function  (event) {
            update_theme(event.target.selectedIndex);
        };

        upload_btn.onclick = function  () {
            upload_bg_img_dlg(update_bg_img);
        };

        remove_btn.onclick = function  () {
            remove_bg();
        };
    }

    window.rndr.tokenize_file_dlg = function  (name, cid) {
        let fileUrl = window.dash.data.host + '/ipfs/' + cid;
        let img = document.querySelector('#tokenize-file-dialog-img');
        let nameElem = document.querySelector('#tokenize-file-dialog-name');
        let btn = document.querySelector('#tokenize-file-dialog-button');

        img.setAttribute('src', fileUrl);
        nameElem.textContent = name;

        btn.onclick = function () {
            tokenize_file(cid);
        };
    };

    window.rndr.send_file_token_dlg = function  (name, cid) {
        let fileUrl = window.dash.data.host + '/ipfs/' + cid;
        let img = document.querySelector('#send-file-token-dialog-img');
        let nameElem = document.querySelector('#send-file-token-dialog-name');;
        let btn = document.querySelector('#send-file-token-dialog-button');

        img.setAttribute('src', fileUrl);
        nameElem.textContent = name;

        btn.onclick = function () {
            send_file_token(cid);
        };
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

        document.querySelector('#settings-button').onclick = function () {
            dash_data(settings_updated);
        };

        window.rndr.dashboard();

    }else if (page.id === 'settings') {
        document.querySelector('#settings-back-button').options.callback = function () {
            dash_data(dash_updated);
        };
    };

    window.rndr.updateBg();
});

window.fn.pushPage = function(page, node_data, callback = null, ...args) {
    let nav = document.querySelector('#Nav');
    nav.pushPage(page+'.html')
    .then(function(){
        if(callback){
            callback(...args);
        }
    });
};