// This file is for shared application wide for ui related js methods
document.addEventListener('init', function(event) {

    const buttonClasses = ['scale-on-hover', 'lighten-on-over'];
    const buttons = document.querySelectorAll('ons-button');

    buttons.forEach(function(btn) {
        buttonClasses.forEach(function(cls) {
            btn.classList.add(cls);
        });
    });
    
});

