window.dlg = {};

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
  };

window.dlg.hide = function(id) {
  let dialog = document.getElementById(id);
  if(dialog){
    document
    .getElementById(id)
    .hide();
  };
};