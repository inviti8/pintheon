window.fn = {};

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

    //Validation Methods
    let rules = {
        required: true
    };

    window.fn.validateAllInputsAndCall = function(confirmMsg, failMsg, callback, ...args) {
        const inputs = document.querySelectorAll('input,  select, textarea');
        let result = true;
        for (let i = 0; i < inputs.length; i++) {
            const input = inputs[i];
            if (!approve.value(input.value, rules).approved) {
            result = false;
            break;
            };
        };

        window.fn.handleBoolDescisionDlgs(result, confirmMsg, failMsg, callback, ...args)
    };

    window.fn.download = function(content, mimeType, filename){
        const a = document.createElement('a') // Create "a" element
        const blob = new Blob([content], {type: mimeType}) // Create a blob (file-like object)
        const url = URL.createObjectURL(blob) // Create an object URL from blob
        a.setAttribute('href', url) // Set "a" element link
        a.setAttribute('download', filename) // Set download filename
        a.click() // Start downloading
    };
    
});

