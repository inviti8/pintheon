// This file is for shared application wide for ui related js methods
document.addEventListener('init', function(event) {

    const buttonClasses = ['scale-on-hover', 'lighten-on-over'];
    const buttons = document.querySelectorAll('ons-button');

    buttons.forEach(function(btn) {
        buttonClasses.forEach(function(cls) {
            btn.classList.add(cls);
        });
    });

    //Shared Rendering methods
    window.fn.renderNodeCardHeader = function(logo, name, descriptor, qty=1){
        const elem = 'node-data-card-header';
        let list = document.querySelector('#'+elem);

        list.delegate = {
            createItemContent: function(i) {
              var template = document.getElementById(elem+'-template');
              var clone = document.importNode(template.content, true);
    
              // Update the clone
              clone.querySelector('#'+elem+'-logo').setAttribute('src', logo);
              clone.querySelector('#'+elem+'-name').textContent = name;
              clone.querySelector('#'+elem+'-descriptor').textContent = descriptor;
    
              return clone.firstElementChild; // Ensure that the returned value is a proper DOM element
            },
            countItems: function() {
              return qty;
            }
        };

    };
    
});

