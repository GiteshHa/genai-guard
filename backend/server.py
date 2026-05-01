from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import json
import tempfile
from datetime import datetime
import smtplib
import base64
import hmac
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load .env only if running locally
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

app = Flask(__name__)
CORS(app)

# Config
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit_logs.db')
API_KEY  = os.getenv("SOC_API_KEY")

# Email config
EMAIL_SENDER   = os.getenv("ALERT_EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("ALERT_EMAIL_RECEIVER")

print(f"📧 Email Sender: {EMAIL_SENDER}")
print(f"📧 Email Receiver: {EMAIL_RECEIVER}")
print(f"📧 Email Password set: {'Yes' if EMAIL_PASSWORD else 'No'}")
print(f"🔑 SOC API key configured: {'Yes' if API_KEY else 'No'}")

# Google Vision credentials
google_creds_json = os.getenv("GOOGLE_CREDENTIALS_JSON")

if google_creds_json:
    try:
        creds_dict = json.loads(google_creds_json)
        temp_file  = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump(creds_dict, temp_file)
        temp_file.close()
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = temp_file.name
        print("✅ Google credentials loaded from environment")
    except Exception as e:
        print(f"❌ Google credentials error: {e}")
else:
    local_key = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "google_vision_key.json"
    )
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = local_key
    print("✅ Google credentials loaded from local file")

# --- DB SETUP ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            ip_address  TEXT,
            platform    TEXT,
            violation   TEXT,
            severity    TEXT,
            snippet     TEXT,
            user_agent  TEXT,
            status      TEXT DEFAULT 'OPEN'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- SEVERITY VALIDATION ---
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

def validate_severity(sev):
    return sev.upper() if sev and sev.upper() in VALID_SEVERITIES else "MEDIUM"

def is_request_authorized():
    """Validate the request API key without leaking timing details."""
    provided_key = request.headers.get("X-API-Key", "")
    if not API_KEY:
        return False
    return hmac.compare_digest(provided_key, API_KEY)

# --- EMAIL ALERT ---
def send_email_alert(entry):
    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        print("⚠️ Email not configured — skipping alert")
        return

    try:
        subject = f"🚨 GenAI Guard Alert [{entry['severity']}]: {entry['violation']} Detected"

        body = f"""
        ╔══════════════════════════════════════╗
              GenAI Guard — SOC Incident Alert
        ╚══════════════════════════════════════╝

        🚨 SEVERITY    : {entry['severity']}
        📋 VIOLATION   : {entry['violation']}
        🌐 PLATFORM    : {entry['platform']}
        🖥️  IP ADDRESS  : {entry['ip_address']}
        ⏰ TIMESTAMP   : {entry['timestamp']}
        📝 SNIPPET     : {entry['snippet']}
        🔍 USER AGENT  : {entry['user_agent']}
        📌 STATUS      : {entry['status']}

        ──────────────────────────────────────
        Action Required: Please investigate immediately.
        Login to SOC Dashboard for full details.
        ──────────────────────────────────────
        GenAI Guard | Automated Security Alert
        """

        msg = MIMEMultipart()
        msg['From']    = EMAIL_SENDER
        msg['To']      = EMAIL_RECEIVER
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=20) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

        print(f"📧 Email Alert Sent to {EMAIL_RECEIVER}", flush=True)
        return True

    except smtplib.SMTPAuthenticationError:
        print("❌ Email Auth Failed — check App Password", flush=True)
        return False
    except Exception as e:
        print(f"❌ Email Error: {e}", flush=True)
        return False

# --- MAIN LOGGING ENDPOINT ---
@app.route('/log', methods=['POST'])
def log_threat():
    if not is_request_authorized():
        return jsonify({"status": "unauthorized"}), 401

    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    entry = {
        "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": ip_address,
        "platform":   data.get("platform", "Unknown"),
        "violation":  data.get("violation", "Unknown"),
        "severity":   validate_severity(data.get("severity", "MEDIUM")),
        "snippet":    data.get("snippet", "")[:200],
        "user_agent": data.get("userAgent", "Unknown"),
        "status":     "OPEN"
    }

    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            INSERT INTO incidents
            (timestamp, ip_address, platform, violation, severity, snippet, user_agent, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', tuple(entry.values()))
        conn.commit()
        conn.close()

        print(f"🚨 INCIDENT LOGGED [{entry['severity']}]: {entry['violation']} from {ip_address}")

        if entry['severity'] in ["CRITICAL", "HIGH"]:
            # Send email in non-daemon thread so Render does not kill it
            email_thread = threading.Thread(target=send_email_alert, args=(entry,), daemon=False)
            email_thread.start()
            sev = entry['severity']
            print(f"📧 Email thread started for [{sev}] incident", flush=True)

        return jsonify({"status": "logged", "severity": entry['severity']}), 200

    except Exception as e:
        print(f"❌ DB Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --- GET ALL INCIDENTS ---
@app.route('/incidents', methods=['GET'])
def get_incidents():
    if not is_request_authorized():
        return jsonify({"status": "unauthorized"}), 401

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM incidents ORDER BY timestamp DESC')
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(rows), 200

# --- GOOGLE VISION IMAGE SCAN ---
@app.route('/scan_image', methods=['POST'])
def scan_image():
    if not is_request_authorized():
        return jsonify({"status": "unauthorized"}), 401

    data = request.json
    if not data or 'image' not in data:
        return jsonify({"status": "error", "message": "No image received"}), 400

    try:
        from google.cloud import vision

        client     = vision.ImageAnnotatorClient()
        image_data = base64.b64decode(data['image'])
        image      = vision.Image(content=image_data)
        response   = client.text_detection(image=image)
        texts      = response.text_annotations

        if texts:
            extracted_text = texts[0].description
            print(f"📄 Vision OCR extracted: {extracted_text[:100]}")
            return jsonify({"status": "success", "text": extracted_text}), 200
        else:
            return jsonify({"status": "success", "text": ""}), 200

    except Exception as e:
        print(f"❌ Vision API Error: {e}")
        return jsonify({"status": "error", "text": "", "message": str(e)}), 500

# --- HEALTH CHECK ---
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "GenAI Guard SOC Server Running ✅"}), 200

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    print(f"📡 GenAI Guard SOC Server running on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)