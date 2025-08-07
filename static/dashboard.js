window.dash = {};
window.dash.data = { 'logo': '/static/hvym_logo.png', 'name': 'PINTHEON', 'descriptor': 'XRO Network', 'address': undefined, 'host': window.location.host, 'customization': {}, 'repo': {}, 'stats': null, 'token_info': [], 'file_list': [], 'peer_id':"", 'peer_list': [], 'session_token':undefined, 'auth_token':undefined, 'access_tokens': [],};
window.dash.SESSION_KEYS = 'PINTHEON_SESSION';
window.dash.NODE = 'PINTHEON_NODE';
window.dash.AUTHORIZED = false;
window.dash.USING_STORED_SESSION = false;

window.dash.CLIENT_PUBLIC_KEY;
window.dash.session_keys;
window.dash.node_data;



window.dash.updateDashData = async function (data){
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
        window.dash.data.auth_token = await generateNonceTimestampAuthToken(window.constants.SERVER_PUBLIC_KEY, window.dash.session_keys.privateKey, 'PINTHEON_AUTH', node.nonce, node.expires );

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
            console.log('GOT DASH DATA!!!!!!!')
            console.log(data)
            window.dlg.hide('loading-dialog');
            window.dash.updateDashData(data)
            window.dash.AUTHORIZED = true;
            window.rndr.dashboard();
          });
    
    };
    
};

init();

// --- Heartbeat Logic ---
function startHeartbeat() {
    let missed = 0;

    setInterval(() => {
        if(window.dash.AUTHORIZED){
            fetch('/api/heartbeat', { method: 'GET' })
            .then(res => {
                if (!res.ok) throw new Error('Server error');
                missed = 0; // Reset on success
                if (res.status === 200) {
                    return res.json();
                };
            })
            .then(data => {
                console.log(data)
                check_for_balance_changes(data);
                window.dash.updateDashData(data);
            })
            .catch(() => {
                missed++;
                if (missed === 3) { // 3 missed = 15 seconds
                    alert('Lost connection to server! You need to log in again.');
                    logged_out();
                }
            });
        };
    }, 10000);
}

startHeartbeat();

const check_for_balance_changes = async (loaded_dash_data) =>{
    let tokens = loaded_dash_data['token_info'];
    let xlm_changed = false;
    let opus_changed = false;
    let xlm = null;
    let opus = null;
    let old_xlm = null;
    let old_opus = null;

    for (let i = 0; i < tokens.length; i++) {
        // console.log(tokens[i]['Balance'])
        if(tokens[i]['Name'] == 'xlm'){
            xlm = tokens[i];
        }else if(tokens[i]['Name'] == 'opus'){
            opus = tokens[i];
        }
    };
    
    let client_tokens = window.dash.data['token_info'];

    for (let i = 0; i < client_tokens.length; i++) {
        // console.log(client_tokens[i]['Balance'])
        if(client_tokens[i]['Name'] == 'xlm'){
            if(client_tokens[i]['Balance'] != xlm['Balance']){
                xlm_changed = true;
                old_xlm = client_tokens[i];
            };
            
        }else if(client_tokens[i]['Name'] == 'opus'){
            if(client_tokens[i]['Balance'] != opus['Balance']){
                opus_changed = true;
                old_opus = client_tokens[i];
            };
        }
    };
    
    let toast_txt = null;
    if(xlm_changed == true){
        console.log(xlm_changed)
        if(old_xlm['Balance'] < xlm['Balance']){
            let recieved = xlm['Balance'] - old_xlm['Balance'];
            toast_txt = "You have recieved "+recieved+" XLM. \n"
        }else if(old_xlm['Balance'] > xlm['Balance']){
            let debited = old_xlm['Balance'] - xlm['Balance'];
            toast_txt = "A transaction for "+debited+" XLM has been debited from your account.\n"
        }
    };

    if(opus_changed == true){
        if(old_opus['Balance'] < opus['Balance']){
            let recieved = opus['Balance'] - old_opus['Balance'];
            toast_txt += "You have recieved "+recieved+" OPUS."
        }else if(old_opus['Balance'] > opus['Balance']){
            let debited = old_opus['Balance'] - opus['Balance'];
            toast_txt += "A transaction for "+debited+" OPUS has been debited from your account."
        }
    };

    if(toast_txt != null){
        let anim = { 'timeout': 6000, 'animation': 'fall' }
        ons.notification.toast(toast_txt, anim)
    };

};

const load_encrypted_keystore = async () => {
    await window.fn.loadJSONFileObject( authorize, true, ['node_data'] );
};

const authorize = async (prms) => {
    
    const keystore = await prms;
    window.fn.generator_keys = await importJWKCryptoKeyPair(keystore['generator_priv'], keystore['generator_pub']);
    const authToken = await generateNonceAuthToken(window.constants.SERVER_GENERATOR_PUBLIC_KEY, window.fn.generator_keys.privateKey, 'PINTHEON_GENERATOR', window.constants.session_nonce);

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
        window.dash.updateDashData(node);
        window.dash.AUTHORIZED = true;

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
    window.dash.AUTHORIZED = false;
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
    window.dash.updateDashData(node_data);
    window.rndr.dashboard();

};

const upload_file = async (file, id=undefined) => {
    const session = _getSessionData();
    let upload = true;
    const tgl = document.querySelector('#'+id+'-encrypt-toggle');

    if(file){
        const formData = new FormData()

        formData.append('token', session.token.serialize());
        formData.append('client_pub', session.pub);

        if(tgl != undefined && tgl.checked){
            const key_input = document.querySelector('#'+id+'-key-input');
            formData.append('encrypted', tgl.checked);
            formData.append('reciever_pub', key_input.value);
            if(key_input.value.length==0){
                upload=false;
            };
        }else{
            formData.append('encrypted', false);
            formData.append('reciever_pub', "");
        }

        formData.append('file', file);
        
        if(upload){
            await window.fn.uploadFile(file, formData, '/upload', file_updated);
        }else{
            window.dlg.show('fail-dialog');
        };
    };
};

const file_updated = (fileList) => {

    console.log(fileList)
    window.dash.updateDashData({ 'file_list': fileList });
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
    await window.fn.tokenizeFile(formData, '/tokenize_file', transaction_sent, 'POST', 'tokenize-file-dialog');
};

const transaction_sent = async(node_data) => {
    console.log('[transaction_sent] node_data:', node_data);
    if(node_data.transaction_data){
        console.log('[transaction_sent] transaction_data:', node_data.transaction_data);
        console.log('[transaction_sent] transaction_data.successful:', node_data.transaction_data.successful);
    } else {
        console.log('[transaction_sent] No transaction_data in response!');
    }
    if(node_data.transaction_data && node_data.transaction_data.successful){
        const session = _getSessionData();
        const formData = new FormData()

        formData.append('token', session.token.serialize());
        formData.append('client_pub', session.pub)
        window.dlg.showAndRender('transaction-confirmed-dialog', window.rndr.send_token_transaction_dlg, node_data.transaction_data);
        await window.fn.formCall('get dashboard data failed', formData, '/dashboard_data', dash_updated, 'POST', false);
    }else{
        ons.notification.alert('Transaction Failed');
    };
};

const send_file_token_prompt = async (name, cid, icon) => {
    window.dlg.showAndRender('send-file-token-dialog', window.rndr.send_file_token_dlg, name, cid, icon);
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

    await window.fn.sendFileToken(formData, '/send_file_token', transaction_sent, 'POST', 'send-file-token-dialog');
};

const recieve_token_prompt = async (qrcode, address) => {
    window.dlg.showAndRender('recieve-token-dialog', window.rndr.recieve_token_dlg, qrcode, address);
};

const send_token_prompt = async (name, token_id, logo) => {
    window.dlg.showAndRender('send-token-dialog', window.rndr.send_token_dlg, name, token_id, logo);
};

const send_token = async (name, token_id) => {
    let amount = document.querySelector('#send-token-dialog-amount').value;
    let to_address = document.querySelector('#send-token-dialog-to-address').value;
    const session = _getSessionData();
    const formData = new FormData();
    
    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    formData.append('name', name);
    formData.append('token_id', token_id);
    formData.append('to_address', to_address);
    formData.append('amount', amount);

    await window.fn.sendFileToken(formData, '/send_token', transaction_sent, 'POST', 'send-token-dialog');
};

const publish_file_token_prompt = async (name, cid, icon, encrypted, reciever_pub=undefined) => {
    window.dlg.showAndRender('publish-file-dialog', window.rndr.publish_file_token_dlg, name, cid, icon, encrypted, reciever_pub);
};

const publish_file = async (name, cid, encrypted, reciever_pub) => {

    const session = _getSessionData();
    const formData = new FormData();
    
    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    formData.append('name', name);
    formData.append('cid', cid);
    formData.append('encrypted', encrypted);
    formData.append('reciever_pub', reciever_pub);

    await window.fn.publishFile(formData, '/publish_file', transaction_sent, 'POST', 'publish-file-dialog');
};

const dash_data = async (callback) => {
    const session = _getSessionData();
    const formData = new FormData()

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    await window.fn.dashData( formData, '/dashboard_data', callback);
};

const dash_updated = (node) => {
    window.dash.updateDashData(node);
    window.rndr.dashboard();
};

const settings_updated = (node) => {
    window.dash.updateDashData(node);
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
    window.dash.updateDashData(node_data);
    window.rndr.settings();
    //window.location.reload();

};

const update_theme = async (theme) => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'theme': theme,
    };
        
    await window.fn.call(body, '/update_theme', theme_updated);
};

const theme_updated = (data) => {

    console.log(data)
    window.dash.updateDashData({ 'customization': data.customization });
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
    window.dash.updateDashData(node_data);
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

const upload_homepage = async (file) => {
    const session = _getSessionData();

    if(file){
        const formData = new FormData()

        formData.append('token', session.token.serialize());
        formData.append('client_pub', session.pub);
        formData.append('file', file);
        await window.fn.uploadFile(file, formData, '/upload_homepage', homepage_updated);
    };
};

const homepage_updated = (response) => {
    console.log(response)
    if(response.success){
        ons.notification.alert('Homepage uploaded successfully!');
        get_homepage_status();
    } else {
        ons.notification.alert('Error uploading homepage: ' + response.error);
    }
};

const remove_homepage = async () => {
    const session = _getSessionData();
    const formData = new FormData()

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
        
    await window.fn.formCall('Remove homepage failed', formData, '/remove_homepage', homepage_removed, 'POST', false);
};

const homepage_removed = (response) => {
    console.log(response)
    if(response.success){
        ons.notification.alert('Homepage removed successfully!');
        get_homepage_status();
    } else {
        ons.notification.alert('Error removing homepage: ' + response.error);
    }
};

const get_homepage_status = async () => {
    const session = _getSessionData();
    const formData = new FormData()

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
        
    await window.fn.formCall('Get homepage status failed', formData, '/homepage_status', homepage_status_updated, 'POST', false);
};

const homepage_status_updated = (response) => {
    console.log(response)
    // Update UI to show homepage status
    const statusElement = document.querySelector('#settings-homepage-status');
    const uploadButton = document.querySelector('#settings-homepage-upload-button');
    const removeButton = document.querySelector('#settings-homepage-remove-button');
    
    if(statusElement){
        if(response.exists){
            statusElement.textContent = `Active (${response.index_file})`;
            statusElement.className = 'status-active';
            if(removeButton) removeButton.disabled = false;
        } else {
            statusElement.textContent = 'No custom homepage';
            statusElement.className = 'status-inactive';
            if(removeButton) removeButton.disabled = true;
        }
    }
};

const bg_removed = (data) => {

    console.log(data)
    window.dash.updateDashData({ 'customization': data.customization });
    window.rndr.settings();
    window.location.reload();
    window.fn.pushPage('settings', data);

};

const copy_peer_id = () => {
    let multiaddress = document.querySelector('#settings-info-multiaddress').value;
    fn.copyToClipboard(multiaddress);
};

const add_access_token_dlg = async (callback) => {
    await window.dlg.show('add-access-token-dialog', callback);
    let name = document.querySelector('#add-access-token-dialog-name');
    let pub = document.querySelector('#add-access-token-dialog-pub');
    if(name != undefined && pub != undefined){
        name.value = "";
        pub.value = "";
    }
};

const add_access_token = async () => {
    let name = document.querySelector('#add-access-token-dialog-name');
    let pub = document.querySelector('#add-access-token-dialog-pub');
    const session = _getSessionData();

    const formData = new FormData();

    if(name != undefined && pub != undefined){
        if (approve.value(name.value, window.fn.input_rules).approved && approve.value(pub.value, window.fn.input_rules).approved){
            formData.append('token', session.token.serialize());
            formData.append('client_pub', session.pub);
            formData.append('name', name.value);
            formData.append('stellar_25519_pub', pub.value)
            await window.fn.addAccessToken(formData, '/add_access_token', access_token_added);
        }else{
            ons.notification.alert('All fields must be filled out');
        };
    }else{
        ons.notification.alert('Something went wrong');
    };
};

const access_token_added = async (response) => {
    window.dlg.hide('add-access-token-dialog')

    console.log(response)
    window.dlg.showAndRender('copy-access-token-dialog', window.rndr.copy_access_token_dlg, response.access_token);

    const session = _getSessionData();
    const formData = new FormData()

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    await window.fn.dashData( formData, '/dashboard_data', access_tokens_updated );

};

const access_tokens_updated = async (data) => {

    console.log(data)
    await window.dash.updateDashData({ 'access_tokens': data.access_tokens});
    window.rndr.settings();

};

const remove_access_token = async (stellar_25519_pub) => {

    const session = _getSessionData();

    const formData = new FormData();

    formData.append('token', session.token.serialize());
    formData.append('client_pub', session.pub);
    formData.append('stellar_25519_pub', stellar_25519_pub)
    await window.fn.removeAccessToken(formData, '/remove_access_token', access_token_removed);
    
};

const access_token_removed = (node_data) => {

    console.log(node_data)
    window.dash.updateDashData(node_data);
    window.rndr.settings();
    //window.location.reload();

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

    window.rndr.tokenInfo = function(tokenList, address){

        let _updateElem = function(clone, i, tokenList){
            if(tokenList[i]==undefined)
                return;

            let name = tokenList[i]['Name'];
            let logo = tokenList[i]['Logo'];
            let balance = tokenList[i]['Balance'];
            let tokenId = tokenList[i]['TokenId'];

            clone.querySelector('#token-list-item-icon').src = logo;
            clone.querySelector('#token-list-item-name').textContent = name;
            clone.querySelector('#token-list-item-balance').textContent = balance;
            clone.querySelector('#token-list-item-send').setAttribute('onclick', 'send_token_prompt("' + name + '","' + tokenId + '","' + logo + '")');
            
            if(name == 'xlm'){
                clone.querySelector('#token-list-item-recieve').setAttribute('onclick', 'recieve_token_prompt("/static/stellar_wallet_qr.png", "' + address + '")');
            }else if(name == 'opus'){
                clone.querySelector('#token-list-item-recieve').setAttribute('onclick', 'recieve_token_prompt("/static/opus_wallet_qr.png", "' + address + '")');
            };

        }

        window.rndr.RENDER_LIST('token-list-items', tokenList, _updateElem, tokenList);
    };

    window.rndr.networkTraffic = function(incoming, outgoing){

        let _updateElem = function(clone, elem, incoming, outgoing){
            clone.querySelector('#'+elem+'-kbs-incoming').textContent = incoming + ' Kb/s incoming';
            clone.querySelector('#'+elem+'-kbs-outgoing').textContent = outgoing + ' Kb/s outgoing';
        }

        window.rndr.RENDER_ELEM('network-traffic', _updateElem, incoming, outgoing);
    };

    window.rndr.fileListItems = function(host, fileList, logo){

        if(fileList.length===0)
            return;
        
        let _updateElem = function(clone, i, host, fileList, logo){
            // Ensure file URLs have the correct protocol (HTTP/HTTPS)
            let protocol = window.location.protocol;
            let fileUrl = protocol + '//' + host + '/ipfs/' + fileList[i]['CID'];

            let fileName = fileList[i]['Name'];
            let fileType = fileList[i]['Type'];
            let cid = fileList[i]['CID']
            let balance = fileList[i]['Balance']
            let encrypted = fileList[i]['Encrypted']
            let reciever_pub = fileList[i]['RecieverPub']
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
            clone.querySelector('#file-list-item-stellar-logo').src = logo;
            clone.querySelector('#file-list-item-balance').textContent = balance;
            clone.querySelector('#file-list-item-encrypted').textContent = encrypted;
            if(reciever_pub != null){
                clone.querySelector('#file-list-item-reciever-pub').textContent = reciever_pub;
            }else{
                clone.querySelector('#file-list-item-reciever-pub').textContent = 'N/A';
            }
            clone.querySelector('.file-name').textContent = fileName;
            clone.querySelector('.file_url').href = fileUrl;
            clone.querySelector('.file_url').textContent = cid;
            clone.querySelector('.file-remove').setAttribute('onclick', 'remove_file("' + cid + '")');
            clone.querySelector('#copy-file-url').setAttribute('onclick', 'fn.copyToClipboard("' + fileUrl + '")');
            if (fileList[i]['IsLogo'] == true){clone.querySelector('.special_icon').insertAdjacentHTML('beforeend','<ons-icon class="right" icon="fa-star"></ons-icon>');};
            if (fileList[i]['IsBgImg'] == true){clone.querySelector('.special_icon').insertAdjacentHTML('beforeend','<ons-icon class="right" icon="fa-photo"></ons-icon>');};
            if(fileList[i]['ContractID'].length > 0){
                clone.querySelector('.special_icon').insertAdjacentHTML('beforeend','<ons-icon class="right" icon="fa-diamond"></ons-icon>');
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="send-button" class="scale-on-hover center-both" modifier="outline" onclick="send_file_token_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+', '+"'"+icon+"'"+' )"><ons-icon icon="fa-paper-plane"></ons-icon>_send</ons-button>');
            }else{
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="tokenize-button" class="scale-on-hover center-both" modifier="outline" onclick="tokenize_file_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+' )"><ons-icon icon="fa-diamond"></ons-icon>_tokenize</ons-button>');
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="send-button" class="scale-on-hover center-both" modifier="outline" onclick="send_file_token_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+', '+"'"+icon+"'"+' )" disabled><ons-icon icon="fa-paper-plane"></ons-icon>_send</ons-button>');
            }

            if(fileList[i]['Encrypted'] == "true"){
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="publish-button" class="scale-on-hover center-both" modifier="outline" onclick="publish_file_token_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+', '+"'"+icon+"'"+', '+true+', '+"'"+reciever_pub+"'"+', )" ><ons-icon icon="fa-bolt"></ons-icon>_publish</ons-button>');
            }else{
                clone.querySelector('#file-list-items-token-buttons').insertAdjacentHTML('beforeend','<ons-button id="publish-button" class="scale-on-hover center-both" modifier="outline" onclick="publish_file_token_prompt( '+"'"+fileName+"'"+','+"'"+cid+"'"+', '+"'"+icon+"'"+', '+false+' )" ><ons-icon icon="fa-bolt"></ons-icon>_publish</ons-button>');
            };
        }

        window.rndr.RENDER_LIST('file-list-items', fileList, _updateElem, host, fileList, logo);
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

    window.rndr.settingsHomepage = function(){

        let _updateElem = function(clone, elem){
            // Initialize homepage status
            get_homepage_status();
        }

        window.rndr.RENDER_ELEM('settings-homepage', _updateElem);
    };

    window.rndr.peerListItems = function(peerList){

        let _updateElem = function(clone, i, peerList){
            clone.querySelector('ons-input').setAttribute('id', 'remove-multiaddress-' + i);
            clone.querySelector('ons-input').setAttribute('value', peerList[i]);
            clone.querySelector('ons-button').setAttribute('onclick', 'fn.bootstrapPeer("' + i + '")');
        }

        window.rndr.RENDER_LIST('peer-list-items', peerList, _updateElem, peerList);
    };

    window.rndr.accessTokenListItems = function(tokenList){

        let _updateElem = function(clone, i, tokenList){
            if (tokenList[i] == undefined)
                return;
            clone.querySelector('#access-token-name').textContent = tokenList[i]['name']
            clone.querySelector('#access-token-pub').textContent = tokenList[i]['pub']
            clone.querySelector('#access-token-remove').setAttribute('onclick', 'remove_access_token("' + tokenList[i]['pub'] + '")');
        }

        window.rndr.RENDER_LIST('access-token-list-items', tokenList, _updateElem, tokenList);
    };

    window.rndr.dashboard = function(){

        console.log('window.dash:')
        console.log(window.dash)
        
        document.querySelector('ons-toolbar .center').innerHTML = window.dash.data.name;
        window.rndr.nodeCardHeader(window.dash.data.logo, window.dash.data.name, window.dash.data.descriptor);
        window.rndr.nodeInfo(window.dash.data.repo.RepoSize, window.dash.data.repo.StorageMax, window.dash.data.repo.usedPercentage);
        window.rndr.tokenInfo(window.dash.data.token_info, window.dash.data.address);
        //window.rndr.networkTraffic('100', '99');
        window.rndr.fileListItems(window.dash.data.host, window.dash.data.file_list, window.dash.data.customization.logo);

    };

    window.rndr.settings = function(){
        window.rndr.settingsNodeInfo(window.dash.data.peer_id, window.dash.data.host);
        window.rndr.settingsAppearance(window.dash.data.customization.current_theme, window.dash.data.customization.themes, window.dash.data.customization.bg_img);
        window.rndr.settingsHomepage();
        
        let gateway = document.querySelector('#settings-info-gateway-url');
        let update_gateway_btn = document.querySelector('#settings-info-update-gateway');
        let theme_select = document.querySelector('#settings-appearance-select');
        let upload_btn = document.querySelector('#settings-appearance-bg-button');
        let remove_btn = document.querySelector('#settings-appearance-remove-bg-button');
        let add_token_btn = document.querySelector('#settings-add-access-token-button');
        
        // Homepage settings elements
        let homepage_upload_btn = document.querySelector('#settings-homepage-upload-button');
        let homepage_remove_btn = document.querySelector('#settings-homepage-remove-button');
        let homepage_upload_input = document.querySelector('#settings-homepage-upload-input');

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

        add_token_btn.onclick = function (){
            add_access_token_dlg(add_access_token);
        };

        // Homepage event handlers
        if(homepage_upload_btn){
            homepage_upload_btn.onclick = function () {
                homepage_upload_input.click();
            };
        }

        if(homepage_upload_input){
            homepage_upload_input.onchange = function (event) {
                if(event.target.files.length > 0){
                    upload_homepage(event.target.files[0]);
                }
            };
        }

        if(homepage_remove_btn){
            homepage_remove_btn.onclick = function () {
                remove_homepage();
            };
        }

        window.rndr.accessTokenListItems(window.dash.data.access_tokens)
    }

    window.rndr.tokenize_file_dlg = function  (name, cid) {
        // Ensure file URLs have the correct protocol (HTTP/HTTPS)
        let protocol = window.location.protocol;
        let fileUrl = protocol + '//' + window.dash.data.host + '/ipfs/' + cid;
        let img = document.querySelector('#tokenize-file-dialog-img');
        let nameElem = document.querySelector('#tokenize-file-dialog-name');
        let btn = document.querySelector('#tokenize-file-dialog-button');

        img.setAttribute('src', fileUrl);
        nameElem.textContent = name;

        btn.onclick = function () {
            tokenize_file(cid);
        };
    };

    window.rndr.send_file_token_dlg = function  (name, cid, icon) {
        let img = document.querySelector('#send-file-token-dialog-img');
        let nameElem = document.querySelector('#send-file-token-dialog-name');;
        let btn = document.querySelector('#send-file-token-dialog-button');

        img.setAttribute('src', icon);
        nameElem.textContent = name;

        btn.onclick = function () {
            send_file_token(cid);
        };
    };

    window.rndr.publish_file_token_dlg = function  (name, cid, icon, encrypted, reciever_pub) {
        let img = document.querySelector('#publish-file-dialog-img');
        let nameElem = document.querySelector('#publish-file-dialog-name');;
        let btn = document.querySelector('#publish-file-dialog-button');

        img.setAttribute('src', icon);
        nameElem.textContent = name;

        btn.onclick = function () {
            publish_file(name, cid, encrypted, reciever_pub);
        };
    };

    window.rndr.send_token_dlg = function  (name, token_id, logo) {
        let img = document.querySelector('#send-token-dialog-img');
        let nameElem = document.querySelector('#send-token-dialog-name');;
        let btn = document.querySelector('#send-token-dialog-button');

        img.setAttribute('src', logo);
        nameElem.textContent = name;

        btn.onclick = function () {
            send_token(name, token_id);
        };
    };

    window.rndr.recieve_token_dlg = function  (qrcode, address) {
        let qr = document.querySelector('#recieve-token-dialog-qrcode');
        let input = document.querySelector('#recieve-token-dialog-address');
        let btn = document.querySelector('#recieve-token-dialog-copy-address');

        qr.setAttribute('src', qrcode);
        input.value = address;

        btn.onclick = function () {
            fn.copyToClipboard(input.value);
        };
    };

    window.rndr.file_tokenize_transaction_dlg = function  (transaction) {
        let fileUrl = window.dash.data.customization.logo;
        let transactionUrl = document.querySelector('#transaction-confirmed-dialog-url');
        let logo = document.querySelector('#transaction-confirmed-dialog-logo');
        let description= document.querySelector('#transaction-confirmed-dialog-description');;
        transactionUrl.href = transaction.transaction_url;
        logo.src = fileUrl;
        description.textContent = "File tokenized on Stellar Blockchain.";
    };

    window.rndr.send_token_transaction_dlg = function  (transaction) {
        let fileUrl = window.dash.data.customization.logo;
        let transactionUrl = document.querySelector('#transaction-confirmed-dialog-url');
        let logo = document.querySelector('#transaction-confirmed-dialog-icon');
        let description= document.querySelector('#transaction-confirmed-dialog-description');;
        transactionUrl.href = transaction.transaction_url;
        logo.src = fileUrl;
        description.textContent = "Transaction confirmed on the Stellar Blockchain.";
    };

    window.rndr.copy_access_token_dlg = function  (token) {
        let input = document.querySelector('#copy-access-token-dialog-input');
        let btn = document.querySelector('#copy-access-token-dialog-button');

        input.value = token;

        btn.onclick = function () {
            fn.copyToClipboard(input.value);
        };
    };


    if (page.id === 'authorize') {

        document.querySelector('#authorize-button').onclick = function () {
            load_encrypted_keystore();
        };

    } else if (page.id === 'dashboard') {

        document.querySelector('#deauthorize-button').onclick = function () {
            ons.notification.confirm('Are you sure you want to logout?')
            .then(function(yes) {
                if(yes){
                    deauthorize();
                };
            })
            
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

window.onbeforeunload = function() {
    const session = _getSessionData();
    const data = new FormData();
    data.append('token', session.token.serialize());
    data.append('client_pub', session.pub);

    // Use sendBeacon for logout
    navigator.sendBeacon('/deauthorize', data);
};