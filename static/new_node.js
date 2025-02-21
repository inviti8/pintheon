const { KeyPair, get_languages } = wasm_bindgen;
window.fn = {};

// load wasm wallet and generate wallet seed right away
async function load_xelis_wallet() {
    await wasm_bindgen();
};

load_xelis_wallet();

window.fn.generate_xelis_wallet = function () {
  
    const mainnet = "mainnet";
    const language_idx = 0;
  
    const key_pair = new KeyPair(mainnet);
    const addr = key_pair.address();
    const private_key = key_pair.secret();
    const seed = key_pair.seed(language_idx);


    return seed
};

document.addEventListener('init', function(event) {
    var page = event.target;

    if (page.id === 'new_node') {
        document.querySelector('#generate-xelis-seed').onclick = function () {
            let seed = window.fn.generate_xelis_wallet();
            document.querySelector('#xelis-seed-text').value = seed.splice(0, (seed.length+1)).join(" ");
        };
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