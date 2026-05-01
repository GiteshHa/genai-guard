// ============================================
// GENAI GUARD - popup.js
// Live UI Updater for Extension Popup
// ============================================

function updateUI(data) {
    document.getElementById('count-critical').innerText = data.critical || 0;
    document.getElementById('count-high').innerText     = data.high     || 0;
    document.getElementById('count-medium').innerText   = data.medium   || 0;
    document.getElementById('count-low').innerText      = data.low      || 0;

    // Show total incident count in header if element exists
    const totalEl = document.getElementById('count-total');
    if (totalEl) {
        const total = (data.critical || 0) + (data.high || 0) +
                      (data.medium   || 0) + (data.low  || 0);
        totalEl.innerText = `${total} Total Incidents`;
    }

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

function setConfigStatus(message, isError = false) {
    const statusEl = document.getElementById("config-status");
    statusEl.innerText = message;
    statusEl.style.color = isError ? "#b42318" : "#027a48";
}

function loadSocConfig() {
    chrome.storage.local.get(["socApiKey"], (result) => {
        document.getElementById("soc-api-key").value = result.socApiKey || "";
        setConfigStatus(result.socApiKey ? "SOC settings loaded." : "⚠️ API key not set.");
    });
}

function saveSocConfig() {
    const apiKey = document.getElementById("soc-api-key").value.trim();

    if (!apiKey) {
        setConfigStatus("API key is required.", true);
        return;
    }

    chrome.storage.local.set(
        { socApiKey: apiKey },
        () => {
            setConfigStatus("✅ SOC settings saved.");
        }
    );
}

function resetStats() {
    chrome.storage.local.set(
        { critical: 0, high: 0, medium: 0, low: 0, threatCount: 0, lastIncident: null },
        () => {
            loadStats();
            setConfigStatus("Stats reset.");
        }
    );
}

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadSocConfig();

    // Load again after delays to catch recent updates
    setTimeout(loadStats, 300);
    setTimeout(loadStats, 800);

    // Real-time updates while popup is open
    chrome.storage.onChanged.addListener(() => {
        setTimeout(loadStats, 100);
    });

    document.getElementById("save-config").addEventListener("click", saveSocConfig);

    // Reset button (optional — only wire if element exists)
    const resetBtn = document.getElementById("reset-stats");
    if (resetBtn) resetBtn.addEventListener("click", resetStats);
});