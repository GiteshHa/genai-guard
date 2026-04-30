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

function setConfigStatus(message, isError = false) {
    const statusEl = document.getElementById("config-status");
    statusEl.innerText = message;
    statusEl.style.color = isError ? "#b42318" : "#027a48";
}

function loadSocConfig() {
    chrome.storage.local.get(["socApiBaseUrl", "socApiKey"], (result) => {
        document.getElementById("soc-base-url").value =
            result.socApiBaseUrl || "https://genai-guard.onrender.com";
        document.getElementById("soc-api-key").value = result.socApiKey || "";
        setConfigStatus("SOC settings loaded.");
    });
}

function saveSocConfig() {
    const baseUrl = document.getElementById("soc-base-url").value.trim();
    const apiKey = document.getElementById("soc-api-key").value.trim();

    if (!baseUrl) {
        setConfigStatus("Base URL is required.", true);
        return;
    }

    try {
        new URL(baseUrl);
    } catch (_err) {
        setConfigStatus("Enter a valid URL (http://... or https://...).", true);
        return;
    }

    chrome.storage.local.set(
        {
            socApiBaseUrl: baseUrl,
            socApiKey: apiKey
        },
        () => {
            setConfigStatus("SOC settings saved.");
        }
    );
}

document.addEventListener('DOMContentLoaded', () => {
    // Load immediately
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
});