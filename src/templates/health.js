// Auto-refresh every 15 seconds
let autoRefresh = true;
let refreshInterval;

function toggleAutoRefresh() {
    autoRefresh = !autoRefresh;
    const btn = document.getElementById('refreshBtn');
    
    if (autoRefresh) {
        btn.textContent = 'Auto-refresh: ON';
        btn.style.background = '#28a745';
        startAutoRefresh();
    } else {
        btn.textContent = 'Auto-refresh: OFF';
        btn.style.background = '#dc3545';
        stopAutoRefresh();
    }
}

function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        location.reload();
    }, 15000);
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
}

// Start auto-refresh on page load
window.onload = function() {
    if (autoRefresh) {
        startAutoRefresh();
    }
};
