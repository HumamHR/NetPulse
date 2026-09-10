/* custom_script.js */
document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('pcap-upload');
    const uploadForm = document.getElementById('upload-form');
    const analyzingPopup = document.getElementById('analyzing-popup');
    
    // Elements inside popup
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const statusMessage = document.getElementById('status-message');
    const fileNameDisplay = document.getElementById('file-name-text');
    const fileInfoSection = document.getElementById('file-info-section');

    // Flag to control the animation loops
    let isAnalysisComplete = false; 

    // 1. AUTO-UPLOAD ON FILE SELECTION
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            if (this.files && this.files.length > 0) {
                fileNameDisplay.textContent = this.files[0].name;
                fileInfoSection.style.display = 'block';
                startUploadProcess();
            }
        });
    }

    // --- ANIMATION HELPER ---
    function showAnalyzingPopup() {
        if (!analyzingPopup) return;
        analyzingPopup.style.display = 'flex';
        void analyzingPopup.offsetWidth; // Force Reflow
        analyzingPopup.classList.add('active');
    }

    function startUploadProcess() {
        // Reset flag
        isAnalysisComplete = false; 

        showAnalyzingPopup();
        
        // Static message
        if(statusMessage) statusMessage.textContent = "Analyzing Capture File...";
        
        // Start the slow simulation
        simulateRealisticProgress();

        const formData = new FormData(uploadForm);

        fetch(uploadForm.action, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            if (data.status === 'success') {
                // Server is done! Now we trigger the smooth finish.
                smoothlyFinishProgress(data.redirect_url);
            } else {
                handleError(data.message || "Unknown error");
            }
        })
        .catch(error => {
            handleError("An error occurred during upload/analysis.");
            console.error('Error:', error);
        });
    }

    function handleError(msg) {
        isAnalysisComplete = true; // Stop animations
        setTimeout(() => {
            alert("Analysis failed: " + msg);
            if(analyzingPopup) {
                analyzingPopup.classList.remove('active');
                setTimeout(() => { analyzingPopup.style.display = 'none'; }, 500);
            }
            if(fileInput) fileInput.value = ''; 
        }, 500);
    }

    // --- UPDATE: New Logic to Smoothly Fill Bar to 100% ---
    function smoothlyFinishProgress(url) {
        // 1. Stop the slow random loop
        isAnalysisComplete = true; 

        // 2. Get current width to start fast-forward from
        let currentWidth = parseFloat(progressBar.style.width) || 0;
        
        // 3. Interval to fill the rest quickly (e.g. 10ms per step)
        const fastInterval = setInterval(() => {
            if (currentWidth >= 100) {
                // STOP: We reached 100%
                clearInterval(fastInterval);
                
                // Ensure UI is exact
                if (progressBar) progressBar.style.width = '100%';
                if (progressText) progressText.textContent = '100%';
                if (statusMessage) statusMessage.textContent = "Complete!";

                // 4. Wait a moment for user to see "100%", then redirect
                setTimeout(() => {
                    // Fade out popup
                    if (analyzingPopup) analyzingPopup.classList.remove('active');

                    // Wait for fade transition, then go
                    setTimeout(() => {
                        window.location.href = url;
                    }, 500); // Matches CSS transition time

                }, 800); // How long to sit at 100%

            } else {
                // MOVE: Increment quickly
                currentWidth += 2; // Increases by 2% every 10ms (Fast)
                if(currentWidth > 100) currentWidth = 100;
                
                if (progressBar) progressBar.style.width = currentWidth + '%';
                if (progressText) progressText.textContent = Math.round(currentWidth) + '%';
            }
        }, 10); // Run every 10ms
    }

    // --- REALISTIC PROGRESS SIMULATION (SLOW) ---
    function simulateRealisticProgress() {
        let currentWidth = 0;
        
        if(progressBar) progressBar.style.width = '0%';
        if(progressText) progressText.textContent = '0%';

        function loop() {
            // --- UPDATE: Stop if server finished or we hit 95% ---
            if (isAnalysisComplete) return; 
            if (currentWidth >= 95) return; 

            let increment = 0;
            let timeout = 0;

            // Logic determines speed
            if (currentWidth < 30) {
                increment = Math.random() * 2 + 1; 
                timeout = Math.random() * 100 + 50; 
            } 
            else if (currentWidth < 70) {
                increment = Math.random() * 1.5; 
                timeout = Math.random() * 200 + 100; 
            } 
            else {
                increment = Math.random() * 0.5; 
                timeout = Math.random() * 400 + 200; 
            }

            currentWidth += increment;
            if (currentWidth > 95) currentWidth = 95;

            const roundedWidth = Math.round(currentWidth);
            if(progressBar) progressBar.style.width = roundedWidth + '%';
            if(progressText) progressText.textContent = roundedWidth + '%';

            // Recursive call
            setTimeout(loop, timeout);
        }

        loop();
    }
});