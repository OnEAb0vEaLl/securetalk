/**
 * Cloudflare Turnstile helper for SecureTalk
 * Prevents form submission if Turnstile is not completed
 */

document.addEventListener('DOMContentLoaded', function() {
    // Find all forms with Turnstile
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        const turnstile = form.querySelector('.cf-turnstile');
        if (!turnstile) return;
        
        form.addEventListener('submit', function(e) {
            const response = form.querySelector('input[name="cf-turnstile-response"]');
            
            if (!response || !response.value) {
                e.preventDefault();
                
                // Show error
                showTurnstileError(form);
                return false;
            }
        });
    });
});

function showTurnstileError(form) {
    // Remove existing error
    const existingError = form.querySelector('.turnstile-error');
    if (existingError) existingError.remove();
    
    // Create error message
    const error = document.createElement('div');
    error.className = 'alert alert-error turnstile-error';
    error.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span>Please complete the security check.</span>
    `;
    
    // Insert before submit button
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.parentNode.insertBefore(error, submitBtn);
    }
    
    // Remove after 5 seconds
    setTimeout(() => {
        error.remove();
    }, 5000);
}

// Turnstile callbacks
function onTurnstileSuccess(token) {
    console.log('Turnstile verified');
}

function onTurnstileError() {
    console.error('Turnstile error');
}

function onTurnstileExpire() {
    console.warn('Turnstile expired');
    // Reload the widget
    if (typeof turnstile !== 'undefined') {
        turnstile.reset();
    }
}