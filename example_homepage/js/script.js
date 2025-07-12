// Simple JavaScript for the test homepage
document.addEventListener('DOMContentLoaded', function() {
    console.log('Pintheon test homepage loaded!');
    
    // Add some interactivity
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            // Add a small animation on click
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = '';
            }, 150);
        });
    });
    
    // Add a welcome message
    const logo = document.querySelector('.logo');
    if (logo) {
        logo.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.1)';
        });
        
        logo.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
    }
    
    // Show current time
    const timeElement = document.createElement('div');
    timeElement.style.cssText = 'position: fixed; top: 10px; right: 10px; background: rgba(255,255,255,0.9); padding: 5px 10px; border-radius: 5px; font-size: 12px; color: #666;';
    timeElement.textContent = new Date().toLocaleTimeString();
    document.body.appendChild(timeElement);
    
    // Update time every second
    setInterval(() => {
        timeElement.textContent = new Date().toLocaleTimeString();
    }, 1000);
}); 