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

window.fn.validatePasswords = function(id) {
  let result = false;
  const dialog = document.getElementById(id);
  const pwInput = document.getElementById(id + '-input');
  const confirmPwInput = document.getElementById(id + '-confirm-input');

  if(dialog){
    result = (pwInput.value === confirmPwInput.value);
  };

  return result
};