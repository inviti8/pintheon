
const authorize = async () => {

    const body = {
        'token': window.constants.SESSION_TOKEN.serialize(),
        'client_pub': window.constants.CLIENT_PUBLIC_KEY,
        'launch_token': await generateLaunchToken(document.querySelector('#launch-key').value),
        'seed_cipher': await generateSharedEncryptedText(document.querySelector('#xelis-seed-text').value, window.constants.SERVER_PUBLIC_KEY, window.constants.CLIENT_SESSION_KEYS.privateKey),
        'generator_pub': await exportKey(window.fn.generator_keys.publicKey),
      };

    window.fn.call(body, '/authorize', on_authorized);
};

const on_authorized = (data) => {

};

document.addEventListener('init', function(event) {
    let page = event.target;

    if (page.id === 'authorize') {

        document.querySelector('#authorize-button').onclick = function () {

        };
    } else if (page.id === 'dashboard') {

        page.querySelector('ons-toolbar .center').innerHTML = page.data.title;
        window.rndr.nodeCardHeader(window.constants.LOGO, 'AXIEL', 'XRO Network');

    };
});

window.fn.pushPage = function(page) {
    document.querySelector('#Nav').pushPage(page+'.html', {data: {title: '|| AXIEL ||', logo: window.constants.LOGO}});
};