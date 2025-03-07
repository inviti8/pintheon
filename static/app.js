window.fn = {};
window.rndr = {};

// This file is for shared application wide for ui related js methods
document.addEventListener('init', function(event) {

    const buttonClasses = ['scale-on-hover', 'lighten-on-over'];
    const buttons = document.querySelectorAll('ons-button');

    buttons.forEach(function(btn) {
        buttonClasses.forEach(function(cls) {
            btn.classList.add(cls);
        });
    });

    //Shared Rendering methods
    window.rndr.nodeCardHeader = function(logo, name, descriptor, qty=1){
        const elem = 'node-data-card-header';
        let list = document.querySelector('#'+elem);

        list.delegate = {
            createItemContent: function(i) {
              var template = document.getElementById(elem+'-template');
              var clone = document.importNode(template.content, true);
    
              // Update the clone
              clone.querySelector('#'+elem+'-logo').setAttribute('src', logo);
              clone.querySelector('#'+elem+'-name').textContent = name;
              clone.querySelector('#'+elem+'-descriptor').textContent = descriptor;
    
              return clone.firstElementChild; // Ensure that the returned value is a proper DOM element
            },
            countItems: function() {
              return qty;
            }
        };

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

    //utils
    window.fn.download = function(content, mimeType, filename){
        const a = document.createElement('a') // Create "a" element
        const blob = new Blob([content], {type: mimeType}) // Create a blob (file-like object)
        const url = URL.createObjectURL(blob) // Create an object URL from blob
        a.setAttribute('href', url) // Set "a" element link
        a.setAttribute('download', filename) // Set download filename
        a.click() // Start downloading
    };

    window.fn.saveEncryptedJSONFile = async ( encObj, dlgName, fileName) => {
        let result = false;
        if(window.fn.validateNewPassword(dlgName)){
            const password = document.querySelector('#'+dlgName+'-input').value;
            const encrypted = await encryptJsonObject (encObj, password);
            window.fn.download(JSON.stringify(encrypted), 'text/plain', fileName+'.json');
            window.dlg.hide(dlgName);
            result = true;
        }else{
            window.dlg.show('fail-dialog');
        };

        return result
    };
    
    window.fn.createEncryptedJSONFile = async (fileName, jsonObj, dlgName='new-password-dialog') => {
        window.dlg.show(dlgName, window.fn.saveEncryptedJSONFile, jsonObj, dlgName, fileName);
    };

    window.fn.loadJSONFileObject = async (callback, encrypted=false, pruneKeys=[], dlgName='load-file-dialog') => {
        if(encrypted && dlgName === 'load-file-dialog'){
            dlgName='load-encrypted-file-dialog';
        };
        window.dlg.showLoadJsonFileDlg(dlgName, callback, encrypted, pruneKeys);
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

