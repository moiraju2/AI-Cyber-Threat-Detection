import time
import streamlit as st
import pandas as pd
import requests
from datetime import datetime

VT_API_KEY = "440148dedf3ca5421ff8b4aaf267d68523173a52740f0f0e187e7095825d1c85"

# ---------------- VIRUSTOTAL SCAN ---------------- #

def virustotal_scan(file):

    headers = {

        "x-apikey": VT_API_KEY

    }

    files = {

        "file": (
            file.name,
            file.getvalue()
        )

    }

    upload_url = (
        "https://www.virustotal.com/api/v3/files"
    )

    response = requests.post(
        upload_url,
        headers=headers,
        files=files
    )

    st.write(
        "VT Upload:",
        response.status_code
    )

    if response.status_code == 200:

        data = response.json()

        analysis_id = data[
            "data"
        ][
            "id"
        ]

        time.sleep(8)
        
        analysis_url = (

            "https://www.virustotal.com/api/v3/analyses/"
            + analysis_id
        )

        for i in range(10):

            time.sleep(10)

    result_response = requests.get(
        analysis_url,
        headers=headers
    )

    if result_response.status_code == 200:

        result_data = (
            result_response.json()
        )

        status = result_data[
            "data"
        ][
            "attributes"
        ][
            "status"
        ]

        if status == "completed":

            stats = result_data[
                "data"
            ][
                "attributes"
            ][
                "stats"
            ]

            malicious = stats[
                "malicious"
            ]

            total = sum(
                stats.values()
            )

            return (
                f"{malicious}/{total} engines detected malware"
            )

        return (
            "VirusTotal scan still processing"
            )

        return (
            f"{malicious}/{total} engines detected malware"
            )

        return (
            "VirusTotal scan failed"
            )


from phishing_model import (
    predict_url,
    predict_url_probability
)

from malware_model import check_file

from report_generator import generate_pdf_report

# ---------------- CUSTOM HACKER UI ---------------- #

st.markdown("""
    <style>

    .stApp {
        background-color: #0d1117;
        color: #00ff00;
    }

    h1, h2, h3 {
        color: #00ff00;
        text-align: center;
    }

    .stButton>button {
        background-color: #00ff00;
        color: black;
        font-weight: bold;
        border-radius: 10px;
    }

    .stTextInput>div>div>input {
        background-color: #white;
        color: #black;
    }

    </style>
""", unsafe_allow_html=True)

# ---------------- LOGIN SYSTEM ---------------- #

USERS = {
    "RAJU": {
        "password": "120302",
        "role": "Admin"
    },

    "USER": {
        "password": "1234",
        "role": "User"
    }
}

if "logged_in" not in st.session_state:
    if "last_activity" not in st.session_state:
        st.session_state.last_activity = time.time()
    st.session_state.logged_in = False

if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0

# LOGIN

if not st.session_state.logged_in:

    st.sidebar.title("🔐 Login")

    username = st.sidebar.text_input(
        "Username"
    )

    password = st.sidebar.text_input(
        "Password",
        type="password"
    )

    if st.session_state.login_attempts >= 3:

        st.sidebar.error(
            "Too many wrong attempts"
        )
        if st.sidebar.button("Reset Login Attempts"):
            st.session_state.login_attempts = 0 
            st.rerun()

        st.stop()

    if st.sidebar.button("Login"):

        if (
            username in USERS
            and USERS[username]["password"] == password
        ):

            st.session_state.logged_in = True
            st.session_state.role = USERS[username]["role"]
            st.session_state.login_attempts = 0
            st.rerun()

        else:

            st.session_state.login_attempts += 1

            st.sidebar.error(
                f"Wrong Login ({st.session_state.login_attempts}/3)"
            )

    st.stop()

# AUTO LOGOUT (3 MIN)

current_time = time.time()

if (
    current_time
    - st.session_state.last_activity
    > 180
):

    st.session_state.logged_in = False
    st.rerun()

# USER ACTIVITY UPDATE

st.session_state.last_activity = current_time

# LOGOUT

if st.sidebar.button("🚪 Logout"):

    st.session_state.logged_in = False
    st.rerun()

# ---------------- TITLE ---------------- #

st.set_page_config(
    page_title="AI Cyber Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("AI Cyber Threat Detection System")

history = pd.read_csv("scan_history.csv")

# ADMIN PANEL

if (
    st.session_state.role
    == "Admin"
):

    st.sidebar.markdown("---")

    st.sidebar.subheader(
        "🛠 Admin Panel"
    )

    st.sidebar.write(
        f"Role: {st.session_state.role}"
    )

    history = pd.read_csv(
        "scan_history.csv"
    )

    st.sidebar.write(
        f"Total Scans: {len(history)}"
    )

        # THREAT ANALYTICS

    phishing_count = len(
        history[
            history["Result"]
            == "Phishing"
        ]
    )

    safe_count = len(
        history[
            history["Result"]
            == "Safe"
        ]
    )

    malware_count = len(
        history[
            history["Result"]
            == "Malware"
        ]
    )

    st.sidebar.markdown("---")

    st.sidebar.subheader(
        "📊 Threat Analytics"
    )

    st.sidebar.write(
        f"🟢 Safe: {safe_count}"
    )

    st.sidebar.write(
        f"🔴 Phishing: {phishing_count}"
    )

    st.sidebar.write(
        f"☠ Malware: {malware_count}"
    )

# USER PANEL

if (
    st.session_state.role
    == "User"
):

    st.sidebar.markdown("---")

    st.sidebar.subheader(
        "👤 User Panel"
    )

    st.sidebar.write(
        f"Role: {st.session_state.role}"
    )

    st.sidebar.write(
        "Access: Scan Only"
    )

st.write("Phishing + Malware Detection Using AI")

# =====================================================
# PHISHING URL DETECTION
# ===================================================== #

st.header("🌐 Phishing URL Detection")

url = st.text_input("Enter URL")

if st.button("Check URL"):

    result = predict_url(url)

    safe_percent, phishing_percent = predict_url_probability(url)

    # RESULT

    if result == "Phishing":

        st.error("⚠️ Phishing Website Detected")

    else:

        st.success("✅ Safe Website")

    # DASHBOARD

    st.subheader("URL Security")

    phishing_data = pd.DataFrame({
        'Status': ['Safe', 'Phishing'],
        'Percentage': [safe_percent, phishing_percent]
    })

    st.bar_chart(phishing_data.set_index('Status'))

    st.write(f"Safe Probability: {safe_percent}%")
    st.write(f"Phishing Probability: {phishing_percent}%")

# PDF REPORT

    generate_pdf_report(
        "url_report.pdf",
        "URL Scan",
        result,
        f"""
        URL: {url}
        Safe Probability: {safe_percent}%
        Phishing Probability: {phishing_percent}%
        """
    )

    with open("url_report.pdf", "rb") as file:

        st.download_button(
            "⬇ Download URL Report",
            file,
            file_name="url_report.pdf"
        )


    # SAVE HISTORY

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    new_data = pd.DataFrame({
        "Time":[current_time],
        "Type":["URL"],
        "Input":[url],
        "Result":[result],
        "VirusTotal":["N/A"]
    })

    history = pd.concat(
        [history,new_data],
        ignore_index=True
    )

    history.to_csv(
        "scan_history.csv",
        index=False
    )

# =====================================================
# MALWARE FILE DETECTION
# ===================================================== #

st.header("🦠 Malware File Detection")

uploaded_files = st.file_uploader(
    "Upload Files",
    accept_multiple_files=True
)

if uploaded_files:

    for uploaded_file in uploaded_files:

        st.subheader(
            f"📄 {uploaded_file.name}"
        )

        result, risk_score, file_hash = check_file(
            uploaded_file
        )

        # RESULT

        if result == "Malware":

            st.error(
                "🚨 Malware File Detected"
            )

        else:

            st.success(
                "✅ Safe File"
            )

        # SHOW RESULT

        st.write(
            f"Risk Score: {risk_score}%"
        )

        st.write(
            f"SHA256: {file_hash}"
        )

        vt_result = virustotal_scan(
            uploaded_file
        )

        st.write(
        "🦠 VirusTotal:",
        vt_result
        )
        
        
        
# PDF REPORT

    generate_pdf_report(
        "malware_report.pdf",
        "File Scan",
        result,
        f"""
        File: {uploaded_file.name}
        Risk Score: {risk_score}%
        SHA256: {file_hash}
        VirusTotal: {vt_result}
        """
    )

    with open("malware_report.pdf", "rb") as file:

        st.download_button(
            "⬇ Download Malware Report",
            file,
            file_name="malware_report.pdf"
        )                              

        # SAVE HISTORY

        history = pd.read_csv(
            "scan_history.csv"
        )

        current_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        new_data = pd.DataFrame({
            "Time":[current_time],
            "Type":["File"],
            "Input":[uploaded_file.name],
            "Result":[result],
            "VirusTotal":[vt_result]
        })

        history = pd.concat(
            [history,new_data],
            ignore_index=True
        )

        history.to_csv(
            "scan_history.csv",
            index=False
        )

# =====================================================
# SCAN HISTORY
# ===================================================== #

st.header("📜 Scan History")

history_data = pd.read_csv(
    "scan_history.csv"
)

st.dataframe(history_data)

# ---------------- CLEAR HISTORY ---------------- #

# ADMIN ONLY CLEAR HISTORY

if (
    st.session_state.role
    == "Admin"
):

    if st.button(
        "🗑 Clear History"
    ):

        history = pd.DataFrame(
            columns=[
                "Time",
                "Type",
                "Input",
                "Result",
                "VirusTotal"
            ]
        )

        history.to_csv(
            "scan_history.csv",
            index=False
        )

        st.success(
            "History Cleared"
        )

else:

    st.info(
        "Only Admin can clear history"
    )