window.fn = {};

document.addEventListener('init', function(event) {
    var page = event.target;

    if (page.id === 'page1') {
        // page.querySelector('#push-button').onclick = function() {
        //   document.querySelector('#Nav').pushPage('page2.html', {data: {title: 'Page 2'}});
        // };
    } else if (page.id === 'page2') {
        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
    }
});

window.fn.showLoadingDialog = function() {
    var dialog = document.getElementById('loading-dialog');

    if (dialog) {
        dialog.show();
    } else {
    ons.createElement('loading-dialog.html', { append: true })
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