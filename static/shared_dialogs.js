window.fn.showDialog = function(id) {
    var dialog = document.getElementById(id);

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
    document
    .getElementById(id)
    .hide();
};