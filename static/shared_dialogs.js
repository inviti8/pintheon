window.dlg = {};

const _jsonFileLoaderInputChangeCallback = function(id, input, encrypted, pruneKeys, callback){

  input.addEventListener('change', () => {
    let files = input.files;
    let text;
 
    if (files.length == 0){
      window.dlg.hide(id);
      return;
    };
    const file = files[0];
    let reader = new FileReader();
 
    reader.onload = (e) => {
        const file = e.target.result;

        const lines = file.split(/\r\n|\n/);
        text = lines.join('\n');
        let obj = JSON.parse(text);
        obj = window.fn.pruneJsonKeys(obj, pruneKeys);

        if(encrypted){
          const pw = document.getElementById(id).querySelector('.pw-input');

          try{
            obj = decryptJsonObject(obj, pw.value);

            if(callback){
              callback(obj);
            };
          }catch(err){
            window.dlg.show('fail-dialog');
          };

        }else{

          if(callback){
            callback(obj);
          };

        };

        window.dlg.hide(id);
 
    };
 
    reader.onerror = (e) => alert(e.target.error.name);
    reader.readAsText(file);
  });

};

window.dlg.show = function(id, callback, ...args) {
    let dialog = document.getElementById(id);

    if (dialog) {
        dialog.show();
    } else {
      ons.createElement(id+'.html', { append: true })
        .then(function(dialog) {
          if(callback){
            dialog.querySelector('.can-callback').onclick = function () {
              callback(...args);
            };
          };
            dialog.show();
          });
      }

    return dialog;
};

window.dlg.showLoadJsonFileDlg = function(id, callback, encrypted=false, pruneKeys=[]) {
  let dialog = document.getElementById(id);

  if (dialog) {
      dialog.show();
  } else {
    ons.createElement(id+'.html', { append: true })
      .then(function(dialog) {
        const input = document.querySelector('#'+id+'-input');

        _jsonFileLoaderInputChangeCallback(id, input, encrypted, pruneKeys, callback);

        if(callback){
          dialog.querySelector('.can-callback').onclick = function () {
            input.click();
          };
        };
          dialog.show();
        });
    }

    return dialog;
};

window.dlg.hide = function(id) {
  let dialog = document.getElementById(id);
  if(dialog){
    document
    .getElementById(id)
    .hide();
  };
};

window.dlg.setText = function(id, text) {
  let dialog = document.getElementById(id);
  if(dialog){
    document
    .getElementById(id)
    .then(function(dialog) {
      const txt = dialog.querySelector('#'+id+'-text');
      if(txt){
        txt.innerHTML = text;
      };
    });
  };
};