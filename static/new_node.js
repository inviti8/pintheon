window.fn = {};

document.addEventListener('init', function(event) {
    var page = event.target;

    if (page.id === 'new_node') {
        // page.querySelector('#push-button').onclick = function() {
        //   document.querySelector('#Nav').pushPage('page2.html', {data: {title: 'Page 2'}});
        // };
    } else if (page.id === 'establish') {
        document.querySelector('#btn-logo-file').onclick = function () {
            document.querySelector('#logo-file').click();
        };
        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
        window.fn.renderNodeCardHeader(window.constants.LOGO, 'AXIEL', 'XRO Network');
    }
});

window.fn.pushPage = function(page) {

    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| ESTABLISH ||', logo: window.constants.LOGO}});
};