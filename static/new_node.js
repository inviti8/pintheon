window.fn = {};

document.addEventListener('init', function(event) {
    var page = event.target;
    console.log('page!!!!!!!!!!!!!!!')
    console.log(page)

    if (page.id === 'new_node') {
        // page.querySelector('#push-button').onclick = function() {
        //   document.querySelector('#Nav').pushPage('page2.html', {data: {title: 'Page 2'}});
        // };
    } else if (page.id === 'establish') {
        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
        page.querySelector('#logo').src = page.data.logo;
    }
});

window.fn.pushPage = function(page) {

    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| ESTABLISH ||', logo: window.constants.LOGO}});
};