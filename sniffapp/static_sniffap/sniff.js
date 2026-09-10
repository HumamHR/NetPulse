/* sniff.js */
const analyzingPopup = document.getElementById('analyzing-popup');
const progressBar = document.getElementById('progress-bar');
const progressText = document.getElementById('progress-text');
const statusMessage = document.getElementById('status-message');

let isAnalysisComplete = false;

function showAnalyzingPopup() {
    if (!analyzingPopup) return;
    analyzingPopup.style.display = 'flex';
    void analyzingPopup.offsetWidth;
    analyzingPopup.classList.add('active');
}

function simulateProgress() {
    let current = 0;
    progressBar.style.width = '0%';
    progressText.textContent = '0%';

    function loop() {
        if (isAnalysisComplete || current >= 95) return;
        current += Math.random() * 2;
        if (current > 95) current = 95;

        progressBar.style.width = Math.round(current) + '%';
        progressText.textContent = Math.round(current) + '%';
        setTimeout(loop, 150);
    }
    loop();
}

(function(){
    const out = document.getElementById('output');
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    const downloadBtn = document.getElementById('downloadBtn');
    const clearBtn = document.getElementById('clearBtn');
    const bpfInput = document.getElementById('bpf');
    const ifaceInput = document.getElementById('iface');
    const analyzeBtn = document.getElementById('analyzeBtn');

    const wsProto = (location.protocol === 'https:') ? 'wss' : 'ws';
    const socket = new WebSocket(wsProto + '://' + window.location.host + '/ws/sniff/');

    let packetCount = 0;

    function getCsrfToken() {
        const tokenElement = document.querySelector('input[name="csrfmiddlewaretoken"]');
        return tokenElement ? tokenElement.value : '';
    }

    function updateButtonStates(isSniffing, isAnalyzing = false) {
        startBtn.disabled = isSniffing || isAnalyzing;
        stopBtn.disabled = !isSniffing || isAnalyzing;
        downloadBtn.disabled = isSniffing || isAnalyzing;
        clearBtn.disabled = isSniffing || isAnalyzing;
        bpfInput.disabled = isSniffing || isAnalyzing;
        ifaceInput.disabled = isSniffing || isAnalyzing;

        analyzeBtn.disabled = isSniffing || isAnalyzing;
        analyzeBtn.textContent = isAnalyzing ? 'Analyzing...' : `Analyze Captured Packets (${packetCount})`;
    }

    socket.onopen = () => {
        appendLine('[ws] connected');
        updateButtonStates(false);
        // Request current status
        socket.send(JSON.stringify({ action: 'status' }));
    }
    
    socket.onmessage = (e) => {
        try {
            const d = JSON.parse(e.data);
            
            if (d.status) {
                appendLine('[status] ' + d.status);
                const isSniffing = ['started', 'running', 'Starting'].includes(d.status);
                updateButtonStates(isSniffing);
                
                if (d.packet_count !== undefined) {
                    packetCount = d.packet_count;
                    updateButtonStates(isSniffing);
                }
            }

            if (d.summary) {
                packetCount++;
                appendLine(d.timestamp + ' ' + d.summary + ' ' + (d.src ? d.src + '>' + d.dst : ''));
                updateButtonStates(true); // Update button text with new count
            }

            if (d.download_url) {
                appendLine('[download ready] ' + d.download_url);
                window.open(d.download_url, '_blank');
            }
            if (d.error) appendLine('[error] ' + d.error);
        } catch(err){
            appendLine('[raw] ' + e.data);
        }
    }
    
    socket.onclose = () => appendLine('[ws] disconnected');

    function appendLine(s){
        out.textContent += s + '\n';
        out.scrollTop = out.scrollHeight;
    }

    startBtn.addEventListener('click', ()=>{
        packetCount = 0;
        updateButtonStates(true); 
        socket.send(JSON.stringify({ action: 'start', bpf: bpfInput.value || null, iface: ifaceInput.value || null }));
    });
    
    stopBtn.addEventListener('click', ()=>{
        socket.send(JSON.stringify({ action: 'stop' }));
    });
    
    downloadBtn.addEventListener('click', ()=>{
        socket.send(JSON.stringify({ action: 'download' }));
    });
    
    clearBtn.addEventListener('click', ()=>{
        socket.send(JSON.stringify({ action: 'clear' }));
        out.textContent = '';
        packetCount = 0;
        updateButtonStates(false);
    });
    
    analyzeBtn.addEventListener('click', ()=>{
        if (packetCount === 0) {
            appendLine('[error] No packets to analyze. Start sniffing first.');
            return;
        }

        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            appendLine('[error] CSRF token not found. Cannot analyze.');
            return;
        }

        updateButtonStates(false, true);

        fetch('/analyze_live/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken,
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({}) 
        })
        .then(response => {
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                return response.text().then(text => {
                    appendLine(`[error] Live Analysis Failed. Status: ${response.status}`);
                    updateButtonStates(false, false);
                });
            }
        })
        .catch(error => {
            appendLine(`[error] Network/Fetch Error: ${error}`);
            updateButtonStates(false, false);
        });
    });
    
    updateButtonStates(false);
})();