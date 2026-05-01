// ============================================
// GENAI GUARD - content.js
// Core DLP Detection Engine - Complete Fix
// ============================================
console.log("🛡️ GenAI Guard: CONNECTED & ACTIVE.");

// ============================================
// PART A: SAFE CHROME API WRAPPER
// ============================================
function safeChromeCall(callback, fallback = null) {
    try {
        // Check if chrome.runtime exists and has an id
        if (!chrome || !chrome.runtime || !chrome.runtime.id) {
            console.log("Extension context invalid - skipping Chrome API call");
            return fallback;
        }
        return callback();
    } catch (e) {
        console.log("Chrome API call failed:", e.message);
        return fallback;
    }
}

// Check if extension is alive
function isExtensionAlive() {
    try {
        return !!(chrome && chrome.runtime && chrome.runtime.id);
    } catch (e) {
        return false;
    }
}

const DEFAULT_SOC_BASE_URL = "https://genai-guard.onrender.com";
let socConfigCache = {
    baseUrl: DEFAULT_SOC_BASE_URL,
    apiKey: ""
};

function getSocConfig() {
    return new Promise((resolve) => {
        // If chrome APIs are unavailable, fall back to cached defaults.
        if (!isExtensionAlive()) {
            resolve(socConfigCache);
            return;
        }
        try {
            chrome.storage.local.get(["socApiBaseUrl", "socApiKey"], (result) => {
                if (chrome.runtime.lastError) {
                    console.warn("⚠️ Failed to read SOC config:", chrome.runtime.lastError.message);
                    resolve(socConfigCache);
                    return;
                }

                const directConfig = {
                    baseUrl: result.socApiBaseUrl || DEFAULT_SOC_BASE_URL,
                    apiKey: result.socApiKey || ""
                };
                if (directConfig.apiKey) {
                    socConfigCache = directConfig;
                    resolve(socConfigCache);
                    return;
                }

                chrome.runtime.sendMessage({ action: "GET_SOC_CONFIG" }, (response) => {
                    if (chrome.runtime.lastError || !response?.ok) {
                        resolve(directConfig);
                        return;
                    }
                    socConfigCache = {
                        baseUrl: response.config.baseUrl || DEFAULT_SOC_BASE_URL,
                        apiKey: response.config.apiKey || ""
                    };
                    resolve(socConfigCache);
                });
            });
        } catch (error) {
            console.warn("⚠️ Exception while reading SOC config:", error?.message || error);
            resolve(socConfigCache);
        }
    });
}

// ============================================
// PART B: SENSITIVE PATTERNS LIBRARY
// ============================================
const sensitivePatterns = [
    // CRITICAL
    { name: "Credential",      regex: /(password|passwd|api_key|access_key|secret_key)/i, severity: "CRITICAL" },
    { name: "Private Key",     regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,            severity: "CRITICAL" },
    { name: "JWT Token",       regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+/,              severity: "CRITICAL" },

    // HIGH
    { name: "AWS Key",         regex: /AKIA[0-9A-Z]{16}/,                                 severity: "HIGH" },
    { name: "Google Key",      regex: /AIza[0-9A-Za-z\-_]{35}/,                           severity: "HIGH" },
    { name: "Credit Card",     regex: /\b(?:\d[ -]?){13,16}\b/,                           severity: "HIGH" },
    { name: "Internal IP",     regex: /(192\.168\.\d{1,3}|10\.\d{1,3}\.\d{1,3})/,        severity: "HIGH" },
    // Bank Account: 9–18 digits, but NOT exactly 12 digits (those are Aadhaar) and NOT spaces (Aadhaar uses spaces)
    { name: "Bank Account",    regex: /\b(?!(\d{4}\s\d{4}\s\d{4}|\d{12})\b)[0-9]{9,18}\b/, severity: "HIGH" },
    { name: "IFSC Code",       regex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/,                        severity: "HIGH" },
    { name: "Passport Number", regex: /\b[A-Z][1-9][0-9]{7}\b/,                          severity: "HIGH" },

    // MEDIUM
    { name: "Financial",       regex: /(salary|payroll|budget|revenue|\$\d{3,})/i,         severity: "MEDIUM" },
    // Aadhaar: exactly 12 digits starting with 2-9, optionally space-separated in groups of 4
    { name: "Aadhaar",         regex: /\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/,                  severity: "MEDIUM" },
    { name: "PAN Card",        regex: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/,                    severity: "MEDIUM" },
    { name: "GST Number",      regex: /\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b/, severity: "MEDIUM" },
    { name: "Driving License", regex: /\b[A-Z]{2}[0-9]{2}[0-9]{11}\b/,                   severity: "MEDIUM" },
    { name: "Voter ID",        regex: /\b[A-Z]{3}[0-9]{7}\b/,                             severity: "MEDIUM" },

    // LOW
    { name: "Email",           regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, severity: "LOW" },
    { name: "Phone Number",    regex: /(\+91[\-\s]?)?[6-9]\d{9}/,                         severity: "LOW" },
];

// ============================================
// PART C: SEVERITY UTILITIES
// ============================================
const severityStyles = {
    CRITICAL: { bg: "#7b0000", emoji: "☠️" },
    HIGH:     { bg: "#ff4444", emoji: "🔴" },
    MEDIUM:   { bg: "#ffaa00", emoji: "🟡" },
    LOW:      { bg: "#28a745", emoji: "🟢" }
};

function getHighestSeverity(matchedPatterns) {
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    for (let level of order) {
        if (matchedPatterns.some(p => p.severity === level)) return level;
    }
    return "LOW";
}

// ============================================
// PART D: ALERT BOX UI
// ============================================
const alertBox = document.createElement("div");
alertBox.className = "genai-guard-alert";
alertBox.style.display = "none";
document.body.appendChild(alertBox);

function showAlert(severity, violationName) {
    const style = severityStyles[severity];
    alertBox.className = `genai-guard-alert severity-${severity.toLowerCase()}`;
    alertBox.innerHTML = `
        ${style.emoji} <strong>[${severity}] BLOCKED</strong><br/>
        <small>${violationName} detected — submission prevented.</small>
    `;
    alertBox.style.display = "block";

    clearTimeout(alertBox._dismissTimer);
    alertBox._dismissTimer = setTimeout(() => {
        alertBox.classList.add("dismissing");
        setTimeout(() => {
            alertBox.style.display = "none";
            alertBox.classList.remove("dismissing");
        }, 300);
    }, 5000);
}

function hideAlert() {
    alertBox.style.display = "none";
}

// ============================================
// PART E: GET PUBLIC IP
// ============================================
async function getPublicIP() {
    try {
        const res = await fetch("https://api.ipify.org?format=json");
        const data = await res.json();
        return data.ip;
    } catch {
        return "Unavailable";
    }
}

// ============================================
// PART F: UPDATE POPUP COUNTER (SAFE)
// ============================================
function updatePopupCounter(violation, severity) {
    // SAFE: Check if extension is alive first
    if (!isExtensionAlive()) {
        console.log("Extension not alive - skipping counter update");
        return;
    }
    
    safeChromeCall(() => {
        const sev = severity.toLowerCase();
        chrome.storage.local.get(
            ["threatCount", "critical", "high", "medium", "low"],
            (result) => {
                if (chrome.runtime.lastError) {
                    console.log("Storage error:", chrome.runtime.lastError);
                    return;
                }
                let update = {
                    threatCount: (result.threatCount || 0) + 1,
                    critical:    (result.critical    || 0),
                    high:        (result.high        || 0),
                    medium:      (result.medium      || 0),
                    low:         (result.low         || 0),
                    lastIncident: {
                        violation: violation,
                        severity:  severity,
                        time:      new Date().toLocaleTimeString()
                    }
                };
                update[sev] = (result[sev] || 0) + 1;
                chrome.storage.local.set(update, () => {
                    console.log(`✅ Counter updated: [${severity}] ${violation}`);
                });
            }
        );
    });
}

// ============================================
// PART G: SOC REPORTING (SAFE)
// ============================================
async function reportToSOC(text, violation, severity) {
    console.log(`📡 Reporting to SOC: [${severity}] ${violation}`);

    // Deduplicate — skip if same violation reported within 10 seconds
    if (isDuplicate(violation, severity, text)) return;

    // Only update counter if extension is alive
    if (isExtensionAlive()) {
        updatePopupCounter(violation, severity);
    }

    let publicIP = await getPublicIP();
    const socConfig = await getSocConfig();
    console.log(
        `🔧 SOC config loaded: baseUrl=${socConfig.baseUrl}, keyLength=${(socConfig.apiKey || "").length}`
    );
    if (!socConfig.apiKey) {
        console.warn("⚠️ SOC API key not configured — report skipped");
        return;
    }

    try {
        const response = await fetch(`${socConfig.baseUrl}/log`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": socConfig.apiKey
            },
            body: JSON.stringify({
                violation:  violation,
                severity:   severity,
                platform:   window.location.hostname,
                snippet:    text.substring(0, 200),
                userAgent:  navigator.userAgent,
                ip_address: publicIP,
                timestamp:  new Date().toISOString()
            })
        });
        
        if (response.ok) {
            console.log(`✅ SOC Report Sent [${severity}]: ${violation}`);
        } else {
            console.warn(`⚠️ SOC Server returned ${response.status}`);
        }
    } catch (error) {
        console.warn("⚠️ SOC Server Offline — report skipped", error.message);
    }
}

// ============================================
// PART H: CORE THREAT DETECTION
// ============================================
let isThreatDetected    = false;
let lastMatchedPatterns = [];

// Deduplication: track last reported incident key + timestamp
let lastReportedKey  = "";
let lastReportedTime = 0;
const DEDUP_WINDOW_MS = 10000; // 10 seconds

function isDuplicate(violation, severity, snippet) {
    const key = `${violation}|${severity}|${snippet.substring(0, 50)}`;
    const now  = Date.now();
    if (key === lastReportedKey && (now - lastReportedTime) < DEDUP_WINDOW_MS) {
        console.log("⏭️ Duplicate incident suppressed:", key);
        return true;
    }
    lastReportedKey  = key;
    lastReportedTime = now;
    return false;
}

function checkTextForThreats(text, source = "TEXT_INPUT") {
    const matched = sensitivePatterns.filter(p => p.regex.test(text));

    if (matched.length > 0) {
        const severity     = getHighestSeverity(matched);
        const topViolation = matched.find(p => p.severity === severity);

        showAlert(severity, topViolation.name);

        if (source === "TEXT_INPUT" && document.activeElement) {
            document.activeElement.style.backgroundColor = "#ffe6e6";
            document.activeElement.style.border          = "2px solid red";
        }

        isThreatDetected    = true;
        lastMatchedPatterns = matched;
        return true;

    } else {
        hideAlert();

        if (source === "TEXT_INPUT" && document.activeElement) {
            document.activeElement.style.backgroundColor = "";
            document.activeElement.style.border          = "";
        }

        isThreatDetected    = false;
        lastMatchedPatterns = [];
        return false;
    }
}

// ============================================
// PART I: TEXT INPUT INTERCEPTION
// ============================================

// MutationObserver for contenteditable divs
function setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            const target = mutation.target;
            if (target && target.isContentEditable) {
                const text = target.innerText || "";
                const trimmedText = text.slice(-500);
                if (trimmedText.length > 0) {
                    checkTextForThreats(trimmedText, "TEXT_INPUT");
                }
            }
        }
    });

    observer.observe(document.body, {
        childList:     true,
        subtree:       true,
        characterData: true
    });

    console.log("👁️ MutationObserver active");
}

setupMutationObserver();

// Standard input event (fallback)
document.addEventListener('input', (e) => {
    const tag        = e.target.tagName.toLowerCase();
    const isEditable = e.target.isContentEditable;
    const isInput    = tag === 'input' || tag === 'textarea';

    if (!isInput && !isEditable) return;

    const text        = e.target.value ||
                       (isEditable ? e.target.innerText : "") || "";
    const trimmedText = text.slice(-500);
    checkTextForThreats(trimmedText, "TEXT_INPUT");
}, true);

// Block Enter key if threat detected
window.addEventListener('keydown', (e) => {
    if (e.key === "Enter" && isThreatDetected) {
        const text = e.target.value || e.target.innerText || "";

        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();

        const severity     = getHighestSeverity(lastMatchedPatterns);
        const topViolation = lastMatchedPatterns.find(p => p.severity === severity);

        if (topViolation) {
            reportToSOC(text, topViolation.name, severity);
            alert(`🛑 BLOCKED [${severity}]: ${topViolation.name} detected.\nIncident reported to SOC.`);
        }
    }
}, true);

// Block submit button clicks
document.addEventListener('click', (e) => {
    const btn = e.target.closest(
        'button[data-testid="send-button"], button[aria-label="Send message"], button[aria-label="Send"]'
    );
    if (btn && isThreatDetected) {
        e.preventDefault();
        e.stopImmediatePropagation();

        const severity     = getHighestSeverity(lastMatchedPatterns);
        const topViolation = lastMatchedPatterns.find(p => p.severity === severity);
        const text         = document.activeElement?.value || document.activeElement?.innerText || "";

        if (topViolation) {
            reportToSOC(text, topViolation.name, severity);
            alert(`🛑 BLOCKED [${severity}]: ${topViolation.name} detected.\nIncident reported to SOC.`);
        }
    }
}, true);

// ============================================
// PART J: IMAGE PROTECTION (Google Vision API)
// ============================================
function showScanningIndicator(message) {
    let indicator = document.getElementById('genai-guard-scanning');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'genai-guard-scanning';
        indicator.style.cssText = `
            position: fixed; top: 20px; right: 20px;
            background: #1a1a2e; color: white;
            padding: 12px 20px; border-radius: 8px;
            font-family: sans-serif; font-size: 13px;
            font-weight: 600; z-index: 999999;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 999999;
        `;
        document.body.appendChild(indicator);
    }
    indicator.innerText = message;
    indicator.style.display = 'block';
}

function hideScanningIndicator() {
    const el = document.getElementById('genai-guard-scanning');
    if (el) el.style.display = 'none';
}

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload  = () => resolve(reader.result.split(',')[1]);
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

function reportImageThreat(source) {
    const severity     = getHighestSeverity(lastMatchedPatterns);
    const topViolation = lastMatchedPatterns.find(p => p.severity === severity);
    reportToSOC(
        `Sensitive image ${source} blocked`,
        topViolation ? topViolation.name : "Image Content",
        severity
    );
}

async function scanImage(file) {
    try {
        showScanningIndicator("🔍 Scanning image for sensitive data...");
        const socConfig = await getSocConfig();
        console.log(
            `🔧 SOC image config loaded: baseUrl=${socConfig.baseUrl}, keyLength=${(socConfig.apiKey || "").length}`
        );
        if (!socConfig.apiKey) {
            console.warn("⚠️ SOC API key not configured — image scan skipped");
            hideScanningIndicator();
            return false;
        }

        const base64 = await fileToBase64(file);

        const response = await fetch(`${socConfig.baseUrl}/scan_image`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": socConfig.apiKey
            },
            body: JSON.stringify({ image: base64 })
        });

        const data = await response.json();
        const text = data.text || "";

        console.log("📄 Google Vision OCR:", text.substring(0, 100));
        hideScanningIndicator();

        return checkTextForThreats(text, "IMAGE_UPLOAD");

    } catch (err) {
        console.error("❌ Vision API Error:", err);
        hideScanningIndicator();
        return false;
    }
}

// ============================================
// PART K: FILE UPLOAD INTERCEPTION
// ============================================
let isOurPickerActive = false;

document.addEventListener('click', async (e) => {
    if (isOurPickerActive) return;

    const fileInput = e.target.closest('input[type="file"]');
    if (!fileInput) return;

    e.preventDefault();
    e.stopImmediatePropagation();

    const ourPicker = document.createElement('input');
    ourPicker.type   = 'file';
    ourPicker.accept = 'image/*,.pdf,.doc,.docx';
    ourPicker.style.display = 'none';
    document.body.appendChild(ourPicker);

    ourPicker.onchange = async () => {
        if (!ourPicker.files || ourPicker.files.length === 0) {
            document.body.removeChild(ourPicker);
            return;
        }

        const file = ourPicker.files[0];

        if (file.type.startsWith('image/')) {
            const threat = await scanImage(file);

            if (threat) {
                reportImageThreat("upload");
                alert(`🛑 BLOCKED: Sensitive data detected in image.\nIncident reported to SOC.`);
                document.body.removeChild(ourPicker);
                return;
            }
        }

        try {
            const dt = new DataTransfer();
            dt.items.add(file);
            fileInput.files = dt.files;

            isOurPickerActive = true;
            fileInput.dispatchEvent(new Event('change', { bubbles: true }));
            isOurPickerActive = false;
        } catch (err) {
            console.error("❌ File transfer error:", err);
        }

        document.body.removeChild(ourPicker);
    };

    isOurPickerActive = true;
    ourPicker.click();
    isOurPickerActive = false;
}, true);

// Paste image (Ctrl+V)
document.addEventListener('paste', async (event) => {
    const items = event.clipboardData?.items;
    if (!items) return;
    for (const item of items) {
        if (item.type.startsWith('image/')) {
            const file = item.getAsFile();
            event.preventDefault();
            event.stopImmediatePropagation();

            const threat = await scanImage(file);
            if (threat) {
                reportImageThreat("paste");
                alert(`🛑 BLOCKED: Sensitive data detected in pasted image.`);
            }
            break;
        }
    }
}, true);

// Drag & drop image
document.addEventListener('drop', async (event) => {
    const files = event.dataTransfer?.files;
    if (!files || files.length === 0) return;
    const file = files[0];
    if (file.type.startsWith('image/')) {
        event.preventDefault();
        event.stopImmediatePropagation();

        const threat = await scanImage(file);
        if (threat) {
            reportImageThreat("drop");
            alert(`🛑 BLOCKED: Sensitive data detected in dropped image.`);
        }
    }
}, true);

// ============================================
// PART L: KEEP RENDER SERVER ALIVE
// ============================================
async function pingServer() {
    const socConfig = await getSocConfig();
    fetch(`${socConfig.baseUrl}/health`)
        .then(() => console.log("🟢 Render server pinged"))
        .catch(() => console.log("🔴 Render server sleeping"));
}

// Ping on page load
pingServer();

// Ping every 10 minutes
setInterval(pingServer, 10 * 60 * 1000);

console.log("✅ GenAI Guard fully loaded and ready!");