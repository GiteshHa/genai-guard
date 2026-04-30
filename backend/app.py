import streamlit as st
import pandas as pd
import requests
import time
import os

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
# This ensures data persists across reruns
if "incident_data" not in st.session_state:
    st.session_state.incident_data = None
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = None

# --- LOAD DATA FROM BACKEND (CACHED) ---
def load_logs_from_api():
    """Fetch incidents from backend. This is fast because it only calls the API."""
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
        
        # Ensure proper data types
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Sort by timestamp - most recent first
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

# --- MANUAL REFRESH BUTTON ---
def refresh_data():
    """Callback function to manually refresh data"""
    st.session_state.incident_data = load_logs_from_api()
    st.session_state.last_refresh = time.strftime("%Y-%m-%d %H:%M:%S")
    st.toast("✅ Data refreshed from backend!", icon="🔄")

# --- MAIN UI ---
st.title("🛡️ GenAI Guard — SOC Threat Triage Center")
st.caption("Real-time monitoring of sensitive data violations across AI platforms")

# --- REFRESH CONTROLS (Top of Dashboard) ---
col_refresh, col_status = st.columns([1, 4])

with col_refresh:
    if st.button("🔄 Refresh Data", type="primary", use_container_width=True):
        refresh_data()

with col_status:
    if st.session_state.last_refresh:
        st.caption(f"Last refreshed: {st.session_state.last_refresh}")
    else:
        st.caption("Click 'Refresh Data' to load incidents")

st.divider()

# --- LOAD DATA (Only on first load or manual refresh) ---
if st.session_state.incident_data is None:
    with st.spinner("Loading incidents from SOC server..."):
        st.session_state.incident_data = load_logs_from_api()
        st.session_state.last_refresh = time.strftime("%Y-%m-%d %H:%M:%S")

df = st.session_state.incident_data

# --- EMPTY STATE ---
if df.empty:
    st.success("✅ No threats detected yet. System is live and monitoring.")
    st.info("💡 Try typing a password or Aadhaar number in ChatGPT or Gemini to trigger a test alert.")
    st.stop()

# --- KPI CARDS ---
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("📋 Total Incidents",  len(df))
col2.metric("⚫ Critical",  len(df[df['severity'] == 'CRITICAL']))
col3.metric("🔴 High",      len(df[df['severity'] == 'HIGH']))
col4.metric("🟡 Medium",    len(df[df['severity'] == 'MEDIUM']))
col5.metric("🟢 Low",       len(df[df['severity'] == 'LOW']))

st.divider()

# --- FILTERS ---
st.subheader("🔍 Filter Incidents")

# Initialize filter defaults in session state
if "severity_filter" not in st.session_state:
    st.session_state.severity_filter = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
if "platform_filter" not in st.session_state:
    platform_options = df['platform'].dropna().unique().tolist()
    st.session_state.platform_filter = platform_options
if "violation_filter" not in st.session_state:
    violation_options = df['violation'].dropna().unique().tolist()
    st.session_state.violation_filter = violation_options

# Get unique values (in case new violations appear)
platform_options = df['platform'].dropna().unique().tolist()
violation_options = df['violation'].dropna().unique().tolist()

f1, f2, f3 = st.columns(3)

with f1:
    st.multiselect(
        "Severity",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=st.session_state.severity_filter,
        key="severity_filter"
    )
with f2:
    st.multiselect(
        "Platform",
        options=platform_options,
        default=st.session_state.platform_filter,
        key="platform_filter"
    )
with f3:
    st.multiselect(
        "Violation Type",
        options=violation_options,
        default=st.session_state.violation_filter,
        key="violation_filter"
    )

# Apply filters
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
    # Get top 10 violation types
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

# Prepare display columns
display_columns = ['timestamp', 'ip_address', 'platform', 'violation', 'severity', 'snippet', 'status']
available_cols = [col for col in display_columns if col in filtered.columns]
display_df = filtered[available_cols].copy()

# Format timestamp for better display
if 'timestamp' in display_df.columns:
    display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')

# Apply severity styling
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

# --- AUTO-REFRESH TIP (Not automatic - user controlled) ---
st.divider()
st.caption("💡 **Tip:** Click the 'Refresh Data' button at the top to see new incidents from the SOC server.")
st.caption("🔒 **Data Persistence:** All incident data is stored securely on the backend server. Dashboard refreshes will never erase your data.")