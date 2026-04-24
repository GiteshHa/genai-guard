// ============================================
// GENAI GUARD - content.js
// Core DLP Detection Engine - Final Version
// ============================================
console.log("🛡️ GenAI Guard: CONNECTED & ACTIVE.");

// ============================================
// PART A: SENSITIVE PATTERNS LIBRARY
// ============================================
const sensitivePatterns = [
    // CRITICAL
    { name: "Credential",  regex: /(password|passwd|api_key|access_key|secret_key)/i, severity: "CRITICAL" },
    { name: "Private Key", regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,            severity: "CRITICAL" },
    { name: "JWT Token",   regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+/,              severity: "CRITICAL" },

    // HIGH
    { name: "AWS Key",     regex: /AKIA[0-9A-Z]{16}/,                                 severity: "HIGH" },
    { name: "Google Key",  regex: /AIza[0-9A-Za-z\-_]{35}/,                           severity: "HIGH" },
    { name: "Credit Card", regex: /\b(?:\d[ -]?){13,16}\b/,                           severity: "HIGH" },
    { name: "Internal IP", regex: /(192\.168\.\d{1,3}|10\.\d{1,3}\.\d{1,3})/,        severity: "HIGH" },

    // MEDIUM
    { name: "Financial",   regex: /(salary|payroll|budget|revenue|\$\d{3,})/i,         severity: "MEDIUM" },
    { name: "Aadhaar",     regex: /\b[2-9]{1}\d{3}\s?\d{4}\s?\d{4}\b/,               severity: "MEDIUM" },
    { name: "PAN Card",    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/,                    severity: "MEDIUM" },

    // LOW
    { name: "Email",       regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, severity: "LOW" },
    { name: "Phone",       regex: /(\+91[\-\s]?)?[6-9]\d{9}/,                         severity: "LOW" },
];

// ============================================
// PART B: SEVERITY UTILITIES
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
// PART C: ALERT BOX UI
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
// PART D: GET PUBLIC IP
// ============================================
async function getPublicIP() {
    try {
        const res  = await fetch("https://api.ipify.org?format=json");
        const data = await res.json();
        return data.ip;
    } catch {
        return "Unavailable";
    }
}

// ============================================
// PART E: UPDATE POPUP COUNTER
// ============================================
function updatePopupCounter(violation, severity) {
    if (typeof chrome === 'undefined' || !chrome.storage) return;
    const sev = severity.toLowerCase();
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
}

// ============================================
// PART F: SOC REPORTING
// ============================================
async function reportToSOC(text, violation, severity) {
    console.log(`📡 Reporting to SOC: [${severity}] ${violation}`);

    updatePopupCounter(violation, severity);

    let publicIP = "Unavailable";
    try {
        const res  = await fetch("https://api.ipify.org?format=json");
        const data = await res.json();
        publicIP   = data.ip;
    } catch {
        publicIP = "Unavailable";
    }

    try {
        await fetch("https://genai-guard.onrender.com/log", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": "genai-guard-secret-2024"
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
        console.log(`✅ SOC Report Sent [${severity}]: ${violation}`);
    } catch {
        console.warn("⚠️ SOC Server Offline — report skipped");
    }
}

// ============================================
// PART G: CORE THREAT DETECTION
// ============================================
let isThreatDetected    = false;
let lastMatchedPatterns = [];

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
// PART H: TEXT INPUT INTERCEPTION
// ============================================

// MutationObserver for contenteditable divs
function setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            const target = mutation.target;
            if (target.isContentEditable) {
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

        reportToSOC(text, topViolation.name, severity);
        alert(`🛑 BLOCKED [${severity}]: ${topViolation.name} detected.\nIncident reported to SOC.`);
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

        reportToSOC(text, topViolation.name, severity);
        alert(`🛑 BLOCKED [${severity}]: ${topViolation.name} detected.\nIncident reported to SOC.`);
    }
}, true);

// ============================================
// PART I: IMAGE PROTECTION (Google Vision API)
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

// Convert file to base64
function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload  = () => resolve(reader.result.split(',')[1]);
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

// Helper — report image threat to SOC
function reportImageThreat(source) {
    const severity     = getHighestSeverity(lastMatchedPatterns);
    const topViolation = lastMatchedPatterns.find(p => p.severity === severity);
    reportToSOC(
        `Sensitive image ${source} blocked`,
        topViolation ? topViolation.name : "Image Content",
        severity
    );
}

// Google Vision OCR Scanner
async function scanImage(file) {
    try {
        showScanningIndicator("🔍 Scanning image for sensitive data...");

        const base64 = await fileToBase64(file);

        const response = await fetch("https://genai-guard.onrender.com/scan_image", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": "genai-guard-secret-2024"
            },
            body: JSON.stringify({ image: base64 })
        });

        const data = await response.json();
        const text = data.text || "";

        console.log("📄 Google Vision OCR:", text);
        hideScanningIndicator();

        return checkTextForThreats(text, "IMAGE_UPLOAD");

    } catch (err) {
        console.error("❌ Vision API Error:", err);
        hideScanningIndicator();
        return false;
    }
}

// ============================================
// PART J: FILE UPLOAD CLICK INTERCEPTION
// Intercepts BEFORE ChatGPT gets the file!
// ============================================
let isOurPickerActive = false;

document.addEventListener('click', async (e) => {
    // Skip if our own picker triggered this
    if (isOurPickerActive) return;

    const fileInput = e.target.closest('input[type="file"]');
    if (!fileInput) return;

    // Intercept the click
    e.preventDefault();
    e.stopImmediatePropagation();

    // Create our controlled file picker
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
            // Scan image with Google Vision
            const threat = await scanImage(file);

            if (threat) {
                // BLOCKED
                reportImageThreat("upload");
                alert(`🛑 BLOCKED: Sensitive data detected in image.\nIncident reported to SOC.`);
                document.body.removeChild(ourPicker);
                return;
            }
        }

        // SAFE — transfer file to original input
        try {
            const dt = new DataTransfer();
            dt.items.add(file);
            fileInput.files = dt.files;

            // Trigger original change event
            isOurPickerActive = true;
            fileInput.dispatchEvent(new Event('change', { bubbles: true }));
            isOurPickerActive = false;
        } catch (err) {
            console.error("❌ File transfer error:", err);
        }

        document.body.removeChild(ourPicker);
    };

    // Open our picker
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
        }
    }
}, true);