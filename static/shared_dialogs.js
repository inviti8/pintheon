window.fn.showDialog = function(id) {
    let dialog = document.getElementById(id);

    if (dialog) {
        dialog.show();
    } else {
      ons.createElement(id+'.html', { append: true })
        .then(function(dialog) {
            dialog.show();
          });
      }
  };

window.fn.hideDialog = function(id) {
  let dialog = document.getElementById(id);
  if(dialog){
    document
    .getElementById(id)
    .hide();
  };
};