window.fn.showDialog = function(id, callback, ...args) {
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

window.fn.hideDialog = function(id) {
  let dialog = document.getElementById(id);
  if(dialog){
    document
    .getElementById(id)
    .hide();
  };
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