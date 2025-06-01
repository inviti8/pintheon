window.fn = {};
window.rndr = {};

// This file is for shared application wide for ui related js methods
document.addEventListener('init', function(event) {

    let nav = document.querySelector('#Nav');

    if(nav){
        nav.setAttribute('page', window.constants.active_page);
    };

    const buttonClasses = ['scale-on-hover', 'lighten-on-over'];
    const buttons = document.querySelectorAll('ons-button');

    buttons.forEach(function(btn) {
        buttonClasses.forEach(function(cls) {
            btn.classList.add(cls);
        });
    });

    //Shared Rendering methods

    window.rndr.RENDER_ELEM = function(elem, callback, ...args){
        console.log(elem)
        let list = document.querySelector('#'+elem);

        try {

            list.delegate = {
                createItemContent: function(i) {
                  var template = document.getElementById(elem+'-template');
                  var clone = document.importNode(template.content, true);

                  if(callback){
                    // Update the clone
                    callback(clone, elem, ...args);
                  }
        
                  return clone.firstElementChild; // Ensure that the returned value is a proper DOM element
                },
                countItems: function() {
                  return 1;
                }
            };
    
            list.refresh();

        }catch (err) {
            throw err;
        };

    };

    window.rndr.RENDER_LIST = function(elem, itemList, callback, ...args){
        let list = document.querySelector('#'+elem);

        try {

            list.delegate = {
                createItemContent: function(i) {
                  var template = document.getElementById(elem+'-template');
                  var clone = document.importNode(template.content, true);
        
                  // Update the clone
                  callback(clone, i, ...args);
        
                  return clone.firstElementChild; // Ensure that the returned value is a proper DOM element
                },
                countItems: function() {
                  return itemList.length;
                }
            };
    
            list.refresh();

        }catch (err) {
            throw err;
        };

    };

    window.rndr.nodeCardHeader = function(logo, name, descriptor){

        let _updateElem = function(clone, elem, logo, name, descriptor){
            clone.querySelector('#'+elem+'-logo').setAttribute('src', logo);
            clone.querySelector('#'+elem+'-name').textContent = name;
            clone.querySelector('#'+elem+'-descriptor').textContent = descriptor;
        }

        window.rndr.RENDER_ELEM('node-data-card-header', _updateElem, logo, name, descriptor);
    };

    window.rndr.showELem = function(id){
        document.getElementById(id).classList.remove('hidden');
    };

    window.rndr.hideElem = function(id){
        document.getElementById(id).classList.add('hidden');
    };

    //Validation Methods
    let input_rules = {
        required: true
    };

    var password_rules = {
        required: true,
        strength: {
            min: 6,
            bonus: 7
        }
    };

    window.fn.filterItems = function(searchTerm) {
        console.log('filterItems!!!', searchTerm);
        var itemList = document.getElementById("file-list-main");
        var items = Array.from(itemList.children);

        items.forEach(function(item) {
          // console.info(item)
          var itemText = item.textContent.toLowerCase();
          var showItem = searchTerm === "" || itemText.includes(searchTerm.toLowerCase());
          item.style.display = showItem ? "block" : "none";
        });
    };

    window.fn.validateAllInputsAndCall = function(confirmMsg, failMsg, callback, ...args) {
        const inputs = document.querySelectorAll('input,  select, textarea');
        let result = true;
        for (let i = 0; i < inputs.length; i++) {
            const input = inputs[i];
            if (!approve.value(input.value, input_rules).approved) {
            result = false;
            break;
            };
        };

        window.fn.handleBoolDescisionDlgs(result, confirmMsg, failMsg, callback, ...args)
    };

    window.fn.handleBoolDescisionDlgs = function(result, confirmMsg, failMsg, callback, ...args){
        if(result){
            ons.notification.confirm(confirmMsg)
        .then(function(answer) {
            if(answer>0){
                callback(...args);    
            };
         });
        }else{
            ons.notification.alert(failMsg);
        };
    };

    window.fn.validateNewPassword = function(id) {
        let result = false;
        const dialog = document.getElementById(id);
        const pwInput = document.getElementById(id + '-input');
        const confirmPwInput = document.getElementById(id + '-confirm-input');
      
        if(dialog){
          result = (pwInput.value === confirmPwInput.value);
          console.log(approve.value(pwInput.value, password_rules))
        };
      
        return result
    };

    window.fn.validatePassword = function(id) {
        let result = false;
        const dialog = document.getElementById(id);
        const pwInput = document.getElementById(id + '-input');
      
        if(dialog){
            result = true;
            console.log(approve.value(pwInput.value, password_rules))
        };
      
        return result
    };

    window.fn.call = async (body, endpoint, callback, method='POST') => {
        window.dlg.show('loading-dialog');
    
        let requestBody = JSON.stringify(body);
    
        fetch(endpoint, {
            method: method,
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
            callback(data);
          });
     
    };

    window.fn.formCall = async (error_msg, formData, endpoint, callback, method='POST', loadingDlg=true) => {
        if(loadingDlg){
            window.dlg.show('loading-dialog');
        };
        
        fetch(endpoint, {
            method: method,
            body: formData
        })
        .then(response => {
            if (response.ok) {
                if(loadingDlg){
                    window.dlg.hide('loading-dialog');
                };
                return response.json();
            } else {
                window.dlg.show('fail-dialog');
                throw new Error(error_msg);
            }
        })
        .then(data => {
            console.log('Server response:', data);
            callback(data);
        })
        .catch(error => {
            if(loadingDlg){
                window.dlg.hide('loading-dialog');
            };
            console.error(error_msg, error);
        });
    };

    window.fn.confirmedCall = async (confirm_msg, error_msg, formData, endpoint, callback, method='POST', loadingDlg=false, hideDlg=undefined) => {
        ons.notification.confirm(confirm_msg)
        .then(function(yes) {
            if(yes){
                if(hideDlg){
                    window.dlg.hide(hideDlg);
                };
                window.fn.formCall(error_msg, formData, endpoint, callback, method, loadingDlg);
            };
        })
    };

    window.fn.uploadFile = async (file, formData, endpoint, callback, method='POST') => {
        window.dlg.show('loading-dialog');

        const reader = new FileReader();

        reader.onload = function(event) {
            fetch(endpoint, {
                method: method,
                body: formData
            })
            .then(response => {
                if (response.ok) {
                  return response.json();
                } else {
                    window.dlg.hide('loading-dialog');
                    window.dlg.show('fail-dialog');
                    throw new Error('File upload failed');
                }
            })
            .then(data => {
                console.log('Server response:', data);
                window.dlg.hide('loading-dialog');
                callback(data);
            })
            .catch(error => {
                window.dlg.hide('loading-dialog');
                console.error('Error uploading file:', error);
            });
        };

        reader.readAsArrayBuffer(file);
    };

    window.fn.removeFile = async (formData, endpoint, callback, method='POST') => {
        window.fn.confirmedCall('Are you sure you want to delete this file?', 'Error removing file', formData, endpoint, callback, method);

    };

    window.fn.tokenizeFile = async (formData, endpoint, callback, method='POST', hideDlg=undefined) => {
        window.fn.confirmedCall('Tokenize this file?', 'file tokenize failed', formData, endpoint, callback, method, true, hideDlg);
    };

    window.fn.sendFileToken = async (formData, endpoint, callback, method='POST', hideDlg=undefined) => {
        window.fn.confirmedCall('Send file token?', 'token transfer failed', formData, endpoint, callback, method, true, hideDlg);
    };

    window.fn.updateGateway = async (formData, endpoint, callback, method='POST') => {
        window.fn.confirmedCall('Update Gateway url?', 'Error updating gateway', formData, endpoint, callback, method);
    };

    window.fn.removeBg = async (formData, endpoint, callback, method='POST') => {
        window.fn.confirmedCall('Remove the background image?', 'bg image removal failed', formData, endpoint, callback, method);
    };

    window.fn.dashData = async (formData, endpoint, callback, method='POST') => {
        window.fn.formCall('Get Dash Data failed', formData, endpoint, callback, method, false, undefined);
    };

    //utils
    window.fn.copyToClipboard = function(text) {
        navigator.clipboard.writeText(text).then(function() {
            ons.notification.toast('Copied to clipboard!', { timeout: 2000 });
        }).catch(function(error) {
            console.error("Could not copy text: ", error);
        });
    };

    window.fn.download = function(content, mimeType, filename){
        const a = document.createElement('a') // Create "a" element
        const blob = new Blob([content], {type: mimeType}) // Create a blob (file-like object)
        const url = URL.createObjectURL(blob) // Create an object URL from blob
        a.setAttribute('href', url) // Set "a" element link
        a.setAttribute('download', filename) // Set download filename
        a.click() // Start downloading
    };

    window.fn.saveEncryptedJSONFile = async ( encObj, dlgName, fileName, onCompleted, ...args) => {
        if(window.fn.validateNewPassword(dlgName)){
            const password = document.querySelector('#'+dlgName+'-input').value;
            const encrypted = await encryptJsonObject (encObj, password);
            window.fn.download(JSON.stringify(encrypted), 'text/plain', fileName+'.json');
            window.dlg.hide(dlgName);
            if(onCompleted){
                onCompleted(...args);
            }
        }else{
            window.dlg.show('fail-dialog');
        };
    };
    
    window.fn.createEncryptedJSONFile = async (fileName, jsonObj, onCompleted, dlgName='new-password-dialog', ...args) => {
        window.dlg.show(dlgName, window.fn.saveEncryptedJSONFile, jsonObj, dlgName, fileName, onCompleted, ...args);
    };

    window.fn.loadJSONFileObject = async (callback, encrypted=false, pruneKeys=[], dlgName='load-file-dialog') => {
        if(encrypted && dlgName === 'load-file-dialog'){
            dlgName='load-encrypted-file-dialog';
        };
        window.dlg.showLoadFileDlg(dlgName, callback, encrypted, pruneKeys);
    };

    window.fn.getStoredEncryptedJSONObject = async ( key, callback, dlgName='load-encrypted-file-dialog' ) => {
        if(window.fn.validatePassword(dlgName)){
            const password = document.querySelector('.pw-input').value;
            let obj = await window.fn.getStored(key);
            try{
                obj = await decryptJsonObject(obj, password);
                callback(obj);
                window.dlg.hide(dlgName);
            }catch(err){
                window.dlg.show('fail-dialog');
            };
            
        }else{
            window.dlg.show('fail-dialog');
        };
    };

    window.fn.loadStoredEncryptedJSONObject = async (key, callback, dlgName='load-encrypted-file-dialog') => {
        window.dlg.show(dlgName, window.fn.getStoredEncryptedJSONObject, key, callback, dlgName);
    };

    window.fn.onKeyStoreLoadedSaveIt = async (obj) => {
        const keystore = await obj;
        window.fn.store(window.constants.KEYSTORE, keystore);
    };

    window.fn.loadKeyStoreFromStorage = async (callback) => {
        await window.fn.loadStoredEncryptedJSONObject(window.constants.KEYSTORE, callback);
    };

    window.fn.saveKeyStoreToStorage = async (pruneKeys=[]) => {
        await window.fn.loadJSONFileObject(window.fn.onKeyStoreLoadedSaveIt, false, pruneKeys);
    };

    window.fn.pruneJsonKeys = (obj, keys) => {
        const clone = structuredClone(obj);
        Object.keys(clone).forEach((key) => {
          if (keys.includes(key)) {
            delete clone[key];
          } else {
            if (typeof clone[key] === 'object') {
                window.fn.pruneJsonKeys(clone[key], keys);
            }
          }
        });
        return clone;
    };

    window.fn.store = (key, obj, type='session') => {
        if(type  === 'local') {
            localStorage.setItem(key, JSON.stringify(obj));
         } else {
            sessionStorage.setItem(key, JSON.stringify(obj));
        };
    };

    window.fn.getStored = (key, type='session') => {
        let result;
        if(type  === 'local') {
            result = JSON.parse(localStorage.getItem(key));
         } else {
            result = JSON.parse(sessionStorage.getItem(key));
        };

        return result
    };

    window.fn.removeStored = (key, type='session') => {
        if(type  === 'local') {
            localStorage.removeItem(key);
         } else {
            sessionStorage.removeItem(key);
        };
    };
});

