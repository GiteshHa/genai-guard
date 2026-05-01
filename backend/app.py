import streamlit as st
import pandas as pd
import requests
import time
import os
from streamlit_autorefresh import st_autorefresh

# --- PAGE CONFIG (MUST BE FIRST) ---
st.set_page_config(
    page_title="GenAI Guard SOC",
    layout="wide",
    page_icon="🛡️"
)

# --- RENDER API CONFIG ---
RENDER_URL = "https://genai-guard.onrender.com"
try:
    API_KEY = st.secrets.get("SOC_API_KEY", "")
except Exception:
    API_KEY = os.getenv("SOC_API_KEY", "")

# --- SESSION STATE INITIALIZATION ---
if "incident_data" not in st.session_state:
    st.session_state.incident_data = None
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = None

# --- LOAD DATA FROM BACKEND ---
def load_logs_from_api():
    if not API_KEY:
        st.error("❌ SOC API key is not configured. Set SOC_API_KEY in Streamlit secrets.")
        return pd.DataFrame()
    try:
        response = requests.get(
            f"{RENDER_URL}/incidents",
            headers={"X-API-Key": API_KEY},
            timeout=30
        )
        data = response.json()
        if not data:
            return pd.DataFrame()
        df = pd.DataFrame(data)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp', ascending=False)
        return df
    except Exception as e:
        st.error(f"❌ Error fetching incidents: {e}")
        return pd.DataFrame()

# --- SEVERITY COLOR FUNCTION ---
def severity_color(val):
    colors = {
        "CRITICAL": "background-color: #7b0000; color: white;",
        "HIGH":     "background-color: #ff4444; color: white;",
        "MEDIUM":   "background-color: #ffaa00; color: black;",
        "LOW":      "background-color: #28a745; color: white;"
    }
    return colors.get(str(val).upper(), "")

# --- MANUAL REFRESH CALLBACK ---
def refresh_data():
    st.session_state.incident_data = load_logs_from_api()
    st.session_state.last_refresh = time.strftime("%Y-%m-%d %H:%M:%S") + " (manual)"
    st.toast("✅ Data refreshed from backend!", icon="🔄")

# --- MAIN UI ---
st.title("🛡️ GenAI Guard — SOC Threat Triage Center")
st.caption("Real-time monitoring of sensitive data violations across AI platforms")

# --- AUTO-REFRESH every 30 seconds ---
refresh_count = st_autorefresh(interval=30_000, key="auto_refresh")

# Reload on every auto-refresh tick
if refresh_count > 0:
    st.session_state.incident_data = load_logs_from_api()
    st.session_state.last_refresh = time.strftime("%Y-%m-%d %H:%M:%S") + " (auto)"

# --- REFRESH CONTROLS ---
col_refresh, col_status = st.columns([1, 4])
with col_refresh:
    if st.button("🔄 Refresh Data", type="primary", use_container_width=True):
        refresh_data()
with col_status:
    if st.session_state.last_refresh:
        st.caption(f"Last refreshed: {st.session_state.last_refresh}")
    else:
        st.caption("Loading data...")

st.divider()

# --- LOAD DATA ON FIRST VISIT ---
if st.session_state.incident_data is None:
    with st.spinner("Loading incidents from SOC server..."):
        st.session_state.incident_data = load_logs_from_api()
        st.session_state.last_refresh = time.strftime("%Y-%m-%d %H:%M:%S") + " (initial)"

df = st.session_state.incident_data

# --- EMPTY STATE ---
if df.empty:
    st.success("✅ No threats detected yet. System is live and monitoring.")
    st.info("💡 Try typing a password or Aadhaar number in ChatGPT or Gemini to trigger a test alert.")
    st.stop()

# --- KPI CARDS ---
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("📋 Total Incidents", len(df))
col2.metric("⚫ Critical", len(df[df['severity'] == 'CRITICAL']))
col3.metric("🔴 High",     len(df[df['severity'] == 'HIGH']))
col4.metric("🟡 Medium",   len(df[df['severity'] == 'MEDIUM']))
col5.metric("🟢 Low",      len(df[df['severity'] == 'LOW']))

st.divider()

# --- FILTERS ---
st.subheader("🔍 Filter Incidents")

if "severity_filter" not in st.session_state:
    st.session_state.severity_filter = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
if "platform_filter" not in st.session_state:
    st.session_state.platform_filter = df['platform'].dropna().unique().tolist()
if "violation_filter" not in st.session_state:
    st.session_state.violation_filter = df['violation'].dropna().unique().tolist()

platform_options  = df['platform'].dropna().unique().tolist()
violation_options = df['violation'].dropna().unique().tolist()

st.session_state.platform_filter  = [p for p in st.session_state.platform_filter  if p in platform_options]  or platform_options
st.session_state.violation_filter = [v for v in st.session_state.violation_filter if v in violation_options] or violation_options

f1, f2, f3 = st.columns(3)
with f1:
    st.multiselect("Severity", options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   default=st.session_state.severity_filter, key="severity_filter")
with f2:
    st.multiselect("Platform", options=platform_options,
                   default=st.session_state.platform_filter, key="platform_filter")
with f3:
    st.multiselect("Violation Type", options=violation_options,
                   default=st.session_state.violation_filter, key="violation_filter")

filtered = df[
    df['severity'].isin(st.session_state.severity_filter) &
    df['platform'].isin(st.session_state.platform_filter) &
    df['violation'].isin(st.session_state.violation_filter)
]

st.divider()

# --- CHARTS ---
st.subheader("📊 Analytics")
c1, c2 = st.columns(2)
with c1:
    st.markdown("**Violations by Type**")
    violation_counts = filtered['violation'].value_counts().head(10)
    if not violation_counts.empty:
        st.bar_chart(violation_counts)
    else:
        st.info("No data for selected filters")
with c2:
    st.markdown("**Violations by Platform**")
    platform_counts = filtered['platform'].value_counts()
    if not platform_counts.empty:
        st.bar_chart(platform_counts)
    else:
        st.info("No data for selected filters")

st.divider()

# --- INCIDENTS TABLE ---
st.subheader(f"🚨 Incident Log ({len(filtered)} records)")

display_columns = ['timestamp', 'ip_address', 'platform', 'violation', 'severity', 'snippet', 'status']
available_cols  = [col for col in display_columns if col in filtered.columns]
display_df      = filtered[available_cols].copy()

if 'timestamp' in display_df.columns:
    display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')

styled = display_df.style.map(severity_color, subset=['severity'])
st.dataframe(styled, use_container_width=True, height=500)

st.divider()

# --- EXPORT ---
csv = filtered.to_csv(index=False).encode('utf-8')
st.download_button(
    label="📥 Export Incidents as CSV",
    data=csv,
    file_name=f"incidents_{pd.Timestamp.now().strftime('%Y%m%d_%H%M')}.csv",
    mime='text/csv'
)

st.divider()
st.caption("🔄 Dashboard auto-refreshes every 30 seconds.")
st.caption("🔒 All incident data is stored securely on the backend server.")