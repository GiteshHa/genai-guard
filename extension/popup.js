// ============================================
// GENAI GUARD - popup.js
// Live UI Updater for Extension Popup
// ============================================

function updateUI(data) {
    document.getElementById('count-critical').innerText = data.critical || 0;
    document.getElementById('count-high').innerText     = data.high     || 0;
    document.getElementById('count-medium').innerText   = data.medium   || 0;
    document.getElementById('count-low').innerText      = data.low      || 0;

    const lastEl = document.getElementById('last-incident-text');
    if (data.lastIncident && data.lastIncident.violation) {
        lastEl.innerText = `${data.lastIncident.violation} [${data.lastIncident.severity}] at ${data.lastIncident.time}`;
    } else {
        lastEl.innerText = "None this session";
    }
}

function loadStats() {
    chrome.storage.local.get(
        ['critical', 'high', 'medium', 'low', 'lastIncident'],
        (result) => {
            console.log("📊 Popup loaded:", result);
            updateUI(result);
        }
    );
}

document.addEventListener('DOMContentLoaded', () => {
    // Load immediately
    loadStats();

    // Load again after delays to catch recent updates
    setTimeout(loadStats, 300);
    setTimeout(loadStats, 800);

    // Real-time updates while popup is open
    chrome.storage.onChanged.addListener(() => {
        setTimeout(loadStats, 100);
    });
});