import streamlit as st
import sqlite3
import pandas as pd
import os
import time

# --- CONFIG ---
st.set_page_config(
    page_title="GenAI Guard SOC",
    layout="wide",
    page_icon="🛡️"
)

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit_logs.db')

# --- LOAD FROM SQLITE ---
def load_logs():
    if not os.path.exists(DB_FILE):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query(
            "SELECT * FROM incidents ORDER BY timestamp DESC", conn
        )
        conn.close()
        return df
    except Exception as e:
        st.error(f"❌ DB Error: {e}")
        return pd.DataFrame()

# --- SEVERITY COLOR ---
def severity_color(val):
    colors = {
        "CRITICAL": "background-color: #7b0000; color: white;",
        "HIGH":     "background-color: #ff4444; color: white;",
        "MEDIUM":   "background-color: #ffaa00; color: black;",
        "LOW":      "background-color: #28a745; color: white;"
    }
    return colors.get(str(val).upper(), "")

# --- MAIN ---
def main():
    st.title("🛡️ GenAI Guard — SOC Threat Triage Center")
    st.caption("Real-time monitoring of sensitive data violations across AI platforms")

    df = load_logs()

    # --- EMPTY STATE ---
    if df.empty:
        st.success("✅ No threats detected yet. System is live and monitoring.")
        st.info("💡 Try typing a password or Aadhaar number in ChatGPT or Gemini to trigger a test alert.")
        return

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
    f1, f2, f3 = st.columns(3)

    with f1:
        sev_filter = st.multiselect(
            "Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    with f2:
        platform_options = df['platform'].dropna().unique().tolist()
        plat_filter = st.multiselect(
            "Platform",
            options=platform_options,
            default=platform_options
        )
    with f3:
        violation_options = df['violation'].dropna().unique().tolist()
        viol_filter = st.multiselect(
            "Violation Type",
            options=violation_options,
            default=violation_options
        )

    # Apply filters
    filtered = df[
        df['severity'].isin(sev_filter) &
        df['platform'].isin(plat_filter) &
        df['violation'].isin(viol_filter)
    ]

    st.divider()

    # --- CHARTS ---
    st.subheader("📊 Analytics")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Violations by Type**")
        st.bar_chart(filtered['violation'].value_counts())
    with c2:
        st.markdown("**Violations by Platform**")
        st.bar_chart(filtered['platform'].value_counts())

    st.divider()

    # --- INCIDENTS TABLE ---
    st.subheader(f"🚨 Incident Log ({len(filtered)} records)")
    
    display_df = filtered[[
        'timestamp', 'ip_address', 'platform',
        'violation', 'severity', 'snippet', 'status'
    ]]

    styled = display_df.style.map(
        severity_color, subset=['severity']
    )

    st.dataframe(styled, use_container_width=True, height=400)

    st.divider()

    # --- EXPORT ---
    csv = filtered.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Export Incidents as CSV",
        data=csv,
        file_name=f"incidents_{pd.Timestamp.now().strftime('%Y%m%d_%H%M')}.csv",
        mime='text/csv'
    )

    # --- AUTO REFRESH ---
    st.caption("⏱️ Auto-refreshing every 30 seconds...")
    time.sleep(30)
    st.rerun()

if __name__ == "__main__":
    main()