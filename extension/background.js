// ============================================
// GENAI GUARD - background.js
// Service Worker - Storage & Counter Manager
// ============================================

// Initialize storage when extension is installed
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.get(
        [
            "threatCount",
            "critical",
            "high",
            "medium",
            "low",
            "lastIncident",
            "socApiBaseUrl"
        ],
        (existing) => {
            chrome.storage.local.set({
                threatCount: existing.threatCount ?? 0,
                critical: existing.critical ?? 0,
                high: existing.high ?? 0,
                medium: existing.medium ?? 0,
                low: existing.low ?? 0,
                lastIncident: existing.lastIncident ?? null,
                socApiBaseUrl: existing.socApiBaseUrl || "https://genai-guard.onrender.com"
            });
            console.log("🛡️ GenAI Guard: Storage Initialized.");
        }
    );
});

// Keep service worker alive
chrome.runtime.onStartup.addListener(() => {
    console.log("🛡️ GenAI Guard: Service Worker Started.");
});

// Listen for threat messages from content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("📨 Message received:", request);

    if (request.action === "GET_SOC_CONFIG") {
        chrome.storage.local.get(["socApiBaseUrl", "socApiKey"], (result) => {
            if (chrome.runtime.lastError) {
                sendResponse({
                    ok: false,
                    error: chrome.runtime.lastError.message
                });
                return;
            }
            sendResponse({
                ok: true,
                config: {
                    baseUrl: result.socApiBaseUrl || "https://genai-guard.onrender.com",
                    apiKey: result.socApiKey || ""
                }
            });
        });
        return true;
    }
    
    if (request.action === "THREAT_BLOCKED") {
        const severity = (request.severity || "low").toLowerCase();
        console.log(`🚨 Processing threat: [${severity}] ${request.violation}`);

        chrome.storage.local.get(
            ["threatCount", "critical", "high", "medium", "low"],
            (result) => {
                let update = {
                    threatCount: (result.threatCount || 0) + 1,
                    critical:    (result.critical    || 0),
                    high:        (result.high        || 0),
                    medium:      (result.medium      || 0),
                    low:         (result.low         || 0),
                    lastIncident: {
                        violation: request.violation,
                        severity:  request.severity,
                        time:      new Date().toLocaleTimeString()
                    }
                };

                update[severity] = (result[severity] || 0) + 1;
                
                chrome.storage.local.set(update, () => {
                    console.log(`✅ Storage updated:`, update);
                });
            }
        );
    }
    
    // Keep message channel open
    sendResponse({status: "received"});
    return true;
});