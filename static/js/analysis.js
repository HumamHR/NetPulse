document.addEventListener('DOMContentLoaded', function() {
    // Tab Switching Logic
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));
            // Add active class to clicked tab
            tab.classList.add('active');
            
            // Hide all content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Show corresponding content
            const tabId = tab.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // Initialize Protocol Chart
    const initProtocolChart = () => {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;

        try {
            const protocolData = JSON.parse(document.getElementById('protocol-data').textContent);
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(protocolData),
                    datasets: [{
                        data: Object.values(protocolData),
                        backgroundColor: [
                            '#4d8cff', '#ff6384', '#36a2eb',
                            '#ffce56', '#4bc0c0', '#9966ff',
                            '#ff9f40', '#8c64ff', '#00cc99'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: '#fff',
                                font: {
                                    size: 14
                                },
                                padding: 20
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return `${context.label}: ${context.raw} packets (${context.raw}%)`;
                                }
                            }
                        }
                    },
                    cutout: '60%'
                }
            });
        } catch (error) {
            console.error('Chart initialization error:', error);
            document.getElementById('chart-error').style.display = 'block';
        }
    };


    // Show loading state when navigating
    const showLoading = () => {
        document.getElementById('loading-overlay').classList.add('active');
    };

    // Initialize everything
    initProtocolChart();
    initDataTables();

    // Add loading state to all internal links
    document.querySelectorAll('a[href^="/"]').forEach(link => {
        link.addEventListener('click', showLoading);
    });
});