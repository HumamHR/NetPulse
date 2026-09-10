document.addEventListener('DOMContentLoaded', function() {
    const container = document.getElementById('container');
    const registerBtn = document.getElementById('register');
    const loginBtn = document.getElementById('login');
    const signInForm = document.querySelector('.sign-in form');
    const signUpForm = document.querySelector('.sign-up form');
    
    // Toggle between login and register
    if (registerBtn) {
        registerBtn.addEventListener('click', () => {
            container.classList.add("active");
        });
    }
    
    if (loginBtn) {
        loginBtn.addEventListener('click', () => {
            container.classList.remove("active");
        });
    }
    
    // Form validation for sign in
    if (signInForm) {
        signInForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = this.querySelector('input[name="username"]').value.trim();
            const password = this.querySelector('input[name="password"]').value.trim();
            
            if (!username) {
                alert('Please enter your username or email');
                return;
            }
            
            if (!password) {
                alert('Please enter your password');
                return;
            }
            
            // Here you would normally send the data to your server
            console.log('Login attempt:', { username, password });
            
            // Simulate successful login
            alert('Access granted! Welcome back, Agent.');
            // window.location.href = '/dashboard'; // Redirect to dashboard
        });
    }
    
    // Form validation for sign up
    if (signUpForm) {
        signUpForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = this.querySelector('input[name="username"]').value.trim();
            const email = this.querySelector('input[name="email"]').value.trim();
            const password = this.querySelector('input[name="password"]').value.trim();
            const confirmPassword = this.querySelector('input[name="confirm_password"]').value.trim();
            
            // Validation
            if (!username) {
                alert('Please enter a username');
                return;
            }
            
            if (!email) {
                alert('Please enter your email');
                return;
            }
            
            // Basic email validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                alert('Please enter a valid email address');
                return;
            }
            
            if (!password) {
                alert('Please enter a password');
                return;
            }
            
            if (password.length < 6) {
                alert('Password must be at least 6 characters long');
                return;
            }
            
            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return;
            }
            
            // Here you would normally send the data to your server
            console.log('Registration attempt:', { username, email, password });
            
            // Simulate successful registration
            alert('Registration successful! Welcome to NETPULSE.');
            container.classList.remove("active"); // Switch back to login form
            
            // Clear form
            this.reset();
        });
    }
    
    // Add some cyber effects
    const dataPoints = document.querySelectorAll('.data-point');
    dataPoints.forEach(point => {
        point.addEventListener('mouseenter', () => {
            point.style.opacity = '1';
            point.style.transform = 'scale(2)';
        });
        
        point.addEventListener('mouseleave', () => {
            point.style.opacity = '0.5';
            point.style.transform = 'scale(1)';
        });
    });
});