import os
import json
from datetime import date

import streamlit as st
import validators
import plotly.graph_objects as go

from modules.ssl_checker import check_ssl
from modules.domain_age import get_domain_age
from modules.https_checker import check_https
from modules.trust_score import calculate_trust_score
from modules.website_info import get_website_info
from modules.ip_info import get_ip_info
from modules.blacklist_checker import check_blacklist
from modules.predict import predict_website
from modules.virustotal_checker import check_virustotal
from modules.history import save_history, load_history, clear_history
from modules.report import generate_report
from modules.saved_websites import (
    save_website,
    load_saved_websites,
    delete_saved_website,
    clear_saved_websites
)
from modules.reviews import (
    add_review,
    load_reviews,
    get_website_reviews,
    get_average_rating
)
from modules.auth import (
    initialize_database,
    register_user,
    login_user
)

# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Website Trust Score Analyzer",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# LOAD CSS
# =========================================================

def load_css():
    css_path = "assets/style.css"

    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(
                f"<style>{f.read()}</style>",
                unsafe_allow_html=True
            )


load_css()
initialize_database()


# =========================================================
# GUEST DAILY SCAN LIMIT
# =========================================================

GUEST_LIMIT = 2
GUEST_USAGE_FILE = "data/guest_usage.json"


def load_guest_usage():
    os.makedirs("data", exist_ok=True)
    today = date.today().isoformat()

    if not os.path.exists(GUEST_USAGE_FILE):
        return {"date": today, "count": 0}

    try:
        with open(GUEST_USAGE_FILE, "r", encoding="utf-8") as f:
            usage = json.load(f)
    except (json.JSONDecodeError, OSError):
        usage = {"date": today, "count": 0}

    if usage.get("date") != today:
        usage = {"date": today, "count": 0}
        save_guest_usage(usage)

    return usage


def save_guest_usage(usage):
    os.makedirs("data", exist_ok=True)
    with open(GUEST_USAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(usage, f)


def get_guest_scans_remaining():
    usage = load_guest_usage()
    return max(0, GUEST_LIMIT - int(usage.get("count", 0)))


def use_guest_scan():
    usage = load_guest_usage()

    if int(usage.get("count", 0)) >= GUEST_LIMIT:
        return False

    usage["count"] = int(usage.get("count", 0)) + 1
    save_guest_usage(usage)
    return True


# =========================================================
# SESSION STATE
# =========================================================

if "analysis_done" not in st.session_state:
    st.session_state.analysis_done = False

if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "user" not in st.session_state:
    st.session_state.user = None

if "guest_mode" not in st.session_state:
    st.session_state.guest_mode = False


# =========================================================
# LOGIN / REGISTER / GUEST
# =========================================================

if not st.session_state.authenticated and not st.session_state.guest_mode:

    st.title("🛡️ TrustLens AI")
    st.markdown("### AI-Powered Website Security Analyzer")
    st.write("Login, create an account, or continue as a guest.")

    if "auth_page" not in st.session_state:
        st.session_state.auth_page = "🔐 Login"

    if "login_email" not in st.session_state:
        st.session_state.login_email = ""

    # Apply page changes BEFORE the radio widget is created.
    if st.session_state.pop("switch_to_login", False):
        st.session_state.auth_page = "🔐 Login"
        if "auth_selector" in st.session_state:
            del st.session_state["auth_selector"]

    if st.session_state.pop("switch_to_create", False):
        st.session_state.auth_page = "📝 Create Account"
        if "auth_selector" in st.session_state:
            del st.session_state["auth_selector"]

    def change_auth_page():
        st.session_state.auth_page = st.session_state.auth_selector

    if "auth_selector" not in st.session_state:
        st.session_state.auth_selector = st.session_state.auth_page

    auth_view = st.radio(
        "Account",
        ["🔐 Login", "📝 Create Account"],
        horizontal=True,
        key="auth_selector",
        on_change=change_auth_page
    )

    if auth_view == "🔐 Login":

        with st.form("login_form"):
            login_email = st.text_input(
                "Email",
                key="login_email"
            )

            login_password = st.text_input(
                "Password",
                type="password",
                key="login_password"
            )

            st.markdown("**Don't have an account yet?**")

            st.caption(
                "📝 Create an account to get started."
            )

            login_submitted = st.form_submit_button(
                "🔐 Login",
                type="primary",
                use_container_width=True
            )

        if login_submitted:
            success, message, user_data = login_user(
                login_email,
                login_password
            )

            if success:
                st.session_state.authenticated = True
                st.session_state.user = user_data
                st.session_state.guest_mode = False
                st.rerun()
            else:
                st.error(message)

    else:

        with st.form("register_form"):
            register_name = st.text_input(
                "Name",
                key="register_name"
            )

            register_email = st.text_input(
                "Email",
                key="register_email"
            )

            register_password = st.text_input(
                "Password",
                type="password",
                key="register_password"
            )

            confirm_password = st.text_input(
                "Confirm Password",
                type="password",
                key="confirm_password"
            )

            register_submitted = st.form_submit_button(
                "📝 Create Account",
                type="primary",
                use_container_width=True
            )

        if register_submitted:

            if register_password != confirm_password:
                st.error("Passwords do not match.")

            else:
                success, message = register_user(
                    register_name,
                    register_email,
                    register_password
                )

                if success:
                    st.session_state.login_email = (
                        register_email.strip().lower()
                    )
                    st.session_state.switch_to_login = True
                    st.session_state.registration_success = True
                    st.rerun()

                else:
                    st.error(message)

    if st.session_state.get("registration_success"):
        st.success(
            "✅ Account created successfully. "
            "Enter your password to login."
        )
        st.session_state.registration_success = False

    st.markdown("---")
    st.write("### Continue without an account")
    st.caption(
        "Guest users can analyze up to 2 websites per day. "
        "Create an account or login for unrestricted access."
    )

    if st.button(
        "👤 Continue as Guest",
        use_container_width=True
    ):
        st.session_state.guest_mode = True
        st.session_state.authenticated = False
        st.session_state.user = None
        st.rerun()

    st.stop()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("🛡️ TrustLens AI")

if st.session_state.authenticated and st.session_state.user:
    st.sidebar.success(
        f"👤 {st.session_state.user.get('name', 'User')}"
    )
    st.sidebar.caption(
        st.session_state.user.get("email", "")
    )
else:
    remaining_scans = get_guest_scans_remaining()
    st.sidebar.info("👤 Guest Mode")
    st.sidebar.caption(
        f"🔍 Free scans remaining today: {remaining_scans}/{GUEST_LIMIT}"
    )

if st.sidebar.button("🚪 Logout / Exit Guest"):
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.guest_mode = False
    st.session_state.analysis_done = False
    st.session_state.analysis_data = None
    st.rerun()

st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "🔍 Analyze Website",
        "📜 History",
        "⭐ Saved Websites",
        "💬 Reviews",
        "📄 Reports",
        "⚙️ Settings",
        "ℹ️ About"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info("Version 1.0")


# =========================================================
# DASHBOARD
# =========================================================

if page == "🏠 Dashboard":

    st.title("🛡️ Welcome to TrustLens AI")
    st.markdown("### AI-Powered Website Security Analyzer")

    st.write(
        "Analyze websites using SSL, HTTPS, Domain Age, "
        "Blacklist Detection, VirusTotal and Machine Learning."
    )

    st.markdown("---")

    # Load history
    try:
        user_id = st.session_state.user["id"] if st.session_state.authenticated and st.session_state.user else None
        history = load_history(user_id)
    except Exception:
        history = None

    # Load saved websites for the current user only
    try:
        user_id = (
            st.session_state.user.get("id")
            if st.session_state.authenticated and st.session_state.user
            else None
        )

        if user_id is not None:
            saved_websites = load_saved_websites(user_id)
        else:
            saved_websites = None
    except Exception:
        saved_websites = None

    total_scans = 0
    safe_count = 0
    dangerous_count = 0
    saved_count = 0

    # Calculate scan statistics
    if history is not None and not history.empty:

        total_scans = len(history)

        if "AI Verdict" in history.columns:
            verdict_column = "AI Verdict"

        elif "Result" in history.columns:
            verdict_column = "Result"

        else:
            verdict_column = None

        if verdict_column:

            safe_count = (
                history[verdict_column]
                .astype(str)
                .str.contains(
                    "Safe",
                    case=False,
                    na=False
                )
                .sum()
            )

            dangerous_count = (
                history[verdict_column]
                .astype(str)
                .str.contains(
                    "Suspicious",
                    case=False,
                    na=False
                )
                .sum()
            )

    # Saved website count
    if (
        saved_websites is not None
        and not saved_websites.empty
    ):
        saved_count = len(saved_websites)


    # -----------------------------------------------------
    # DASHBOARD METRICS
    # -----------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "📊 Total Scans",
            total_scans
        )

    with col2:
        st.metric(
            "🟢 Safe",
            safe_count
        )

    with col3:
        st.metric(
            "🔴 Suspicious",
            dangerous_count
        )

    with col4:
        st.metric(
            "⭐ Saved",
            saved_count
        )

    st.markdown("---")


    # -----------------------------------------------------
    # SCAN OVERVIEW CHART
    # -----------------------------------------------------

    st.subheader("📈 Scan Overview")

    if total_scans > 0:

        chart_data = {
            "Safe": safe_count,
            "Suspicious": dangerous_count
        }

        dashboard_chart = go.Figure(
            data=[
                go.Bar(
                    x=list(chart_data.keys()),
                    y=list(chart_data.values())
                )
            ]
        )

        dashboard_chart.update_layout(
            title="Safe vs Suspicious Websites",
            xaxis_title="Website Status",
            yaxis_title="Number of Scans",
            height=350
        )

        st.plotly_chart(
            dashboard_chart,
            use_container_width=True
        )


        # -------------------------------------------------
        # RECENT SCANS
        # -------------------------------------------------

        st.subheader("🕒 Recent Scans")

        st.dataframe(
            history.tail(5),
            use_container_width=True
        )

    else:
        st.info(
            "Analyze some websites to see "
            "dashboard analytics."
        )

    st.markdown("---")


    # -----------------------------------------------------
    # QUICK START
    # -----------------------------------------------------

    st.subheader("🚀 Quick Start")

    st.success(
        "Click **Analyze Website** from the sidebar "
        "and enter a website URL to begin scanning."
    )


    # -----------------------------------------------------
    # FEATURES
    # -----------------------------------------------------

    st.subheader("🛡️ Features")

    feature_col1, feature_col2 = st.columns(2)

    with feature_col1:

        st.write("✅ SSL Certificate Check")
        st.write("✅ HTTPS Detection")
        st.write("✅ Domain Age")
        st.write("✅ IP Information")

    with feature_col2:

        st.write("✅ Blacklist Detection")
        st.write("✅ VirusTotal")
        st.write("✅ AI Prediction")
        st.write("✅ Trust Score")


# =========================================================
# ANALYZE WEBSITE
# =========================================================

elif page == "🔍 Analyze Website":

    st.title("🔍 Analyze Website")

    with st.form("analyze_website_form"):
        url = st.text_input(
            "Enter Shopping Website URL",
            placeholder="https://www.amazon.in"
        )

        analyze_button = st.form_submit_button(
            "🔍 Analyze Website",
            type="primary"
        )


    # -----------------------------------------------------
    # RUN ANALYSIS
    # -----------------------------------------------------

    if analyze_button:

        guest_limit_reached = (
            st.session_state.guest_mode
            and get_guest_scans_remaining() <= 0
        )

        if guest_limit_reached:

            st.error(
                "🚫 You have used your 2 free website analyses for today. "
                "Login or create an account to continue analyzing websites."
            )

        elif not url.strip():

            st.error(
                "Please enter a website URL."
            )

        elif not validators.url(url):

            st.error(
                "Invalid Website URL. "
                "Enter the complete URL, for example: "
                "https://www.amazon.in"
            )

        else:

            # Count only a valid analysis attempt by a guest.
            if st.session_state.guest_mode:
                use_guest_scan()

            with st.spinner(
                "Analyzing website..."
            ):

                # SSL
                try:
                    ssl_status = check_ssl(url)

                except Exception:
                    ssl_status = False


                # DOMAIN AGE
                try:
                    domain_age = get_domain_age(url)

                except Exception:
                    domain_age = None


                # HTTPS
                try:
                    https_status = check_https(url)

                except Exception:
                    https_status = False


                # BLACKLIST
                try:
                    blacklist_status = check_blacklist(url)

                except Exception:
                    blacklist_status = None


                # TRUST SCORE
                trust_score = calculate_trust_score(
                    ssl_status,
                    https_status,
                    domain_age
                )


                # -------------------------------------------------
                # ML FEATURES
                # -------------------------------------------------

                blacklist_feature = (
                    0
                    if blacklist_status is True
                    else 1
                )

                features = [
                    1 if ssl_status else 0,
                    1 if https_status else 0,
                    domain_age
                    if domain_age is not None
                    else 0,
                    blacklist_feature,
                    trust_score
                ]


                # AI PREDICTION
                try:
                    ai_result = predict_website(
                        features
                    )

                except Exception as e:
                    ai_result = (
                        f"Prediction Error: {e}"
                    )


                # WEBSITE INFO
                try:
                    website_info = get_website_info(
                        url
                    )

                except Exception:
                    website_info = None


                # IP INFO
                try:
                    ip_info = get_ip_info(
                        url
                    )

                except Exception:
                    ip_info = None


                # VIRUSTOTAL
                try:
                    virustotal_result = (
                        check_virustotal(url)
                    )

                except Exception as e:

                    virustotal_result = {
                        "error": str(e)
                    }


                # -------------------------------------------------
                # STORE ANALYSIS
                # -------------------------------------------------

                st.session_state.analysis_data = {

                    "url": url,

                    "ssl_status":
                        ssl_status,

                    "domain_age":
                        domain_age,

                    "https_status":
                        https_status,

                    "trust_score":
                        trust_score,

                    "blacklist_status":
                        blacklist_status,

                    "ai_result":
                        ai_result,

                    "website_info":
                        website_info,

                    "ip_info":
                        ip_info,

                    "virustotal_result":
                        virustotal_result
                }

                st.session_state.analysis_done = True


                # -------------------------------------------------
                # SAVE HISTORY
                # -------------------------------------------------

                try:

                    user_id = (
                        st.session_state.user["id"]
                        if st.session_state.authenticated and st.session_state.user
                        else None
                    )

                    save_history(
                        url,
                        trust_score,
                        ai_result,
                        user_id
                    )

                except Exception as e:

                    st.warning(
                        "Analysis completed, "
                        "but history could not "
                        f"be saved: {e}"
                    )


                # -------------------------------------------------
                # GENERATE PDF
                # -------------------------------------------------

                try:

                    generate_report(
                        "Website_Report.pdf",
                        url,
                        trust_score,
                        ai_result,
                        ssl_status,
                        https_status,
                        blacklist_status
                    )

                except Exception as e:

                    st.warning(
                        "Analysis completed, "
                        "but PDF report could not "
                        f"be generated: {e}"
                    )


            st.success(
                "Website analysis completed successfully."
            )


    # =====================================================
    # DISPLAY ANALYSIS RESULTS
    # =====================================================

    if (
        st.session_state.analysis_done
        and
        st.session_state.analysis_data
        is not None
    ):

        data = (
            st.session_state.analysis_data
        )

        url = data["url"]

        ssl_status = (
            data["ssl_status"]
        )

        domain_age = (
            data["domain_age"]
        )

        https_status = (
            data["https_status"]
        )

        trust_score = (
            data["trust_score"]
        )

        blacklist_status = (
            data["blacklist_status"]
        )

        ai_result = (
            data["ai_result"]
        )

        website_info = (
            data["website_info"]
        )

        ip_info = (
            data["ip_info"]
        )

        virustotal_result = (
            data["virustotal_result"]
        )

        st.markdown("---")


        # -------------------------------------------------
        # ANALYSIS SUMMARY
        # -------------------------------------------------

        st.subheader(
            "📊 Analysis Summary"
        )

        summary_col1, summary_col2, summary_col3 = (
            st.columns(3)
        )

        with summary_col1:

            st.metric(
                "🎯 Trust Score",
                f"{trust_score}/100"
            )

        with summary_col2:

            st.metric(
                "🤖 AI Verdict",
                ai_result
            )

        with summary_col3:

            if blacklist_status is True:

                st.metric(
                    "🚫 Blacklist",
                    "Listed"
                )

            elif blacklist_status is False:

                st.metric(
                    "🚫 Blacklist",
                    "Not Listed"
                )

            else:

                st.metric(
                    "🚫 Blacklist",
                    "Unknown"
                )


        st.markdown("---")


        # -------------------------------------------------
        # RESULT TABS
        # -------------------------------------------------

        tab1, tab2, tab3, tab4, tab5 = (
            st.tabs(
                [
                    "🛡️ Security",
                    "🌐 Website Info",
                    "🌍 IP Info",
                    "🚫 Blacklist",
                    "🦠 VirusTotal"
                ]
            )
        )


        # -------------------------------------------------
        # SECURITY
        # -------------------------------------------------

        with tab1:

            if ssl_status:

                st.success(
                    "🔒 SSL Certificate: Valid"
                )

            else:

                st.error(
                    "❌ SSL Certificate: Invalid"
                )


            if https_status:

                st.success(
                    "🔒 HTTPS: Enabled"
                )

            else:

                st.warning(
                    "⚠️ HTTPS: Not Enabled"
                )


            if domain_age is not None:

                st.info(
                    f"🌐 Domain Age: "
                    f"{domain_age} years"
                )

            else:

                st.warning(
                    "⚠️ Could not determine "
                    "domain age."
                )


            # TRUST SCORE GAUGE

            st.subheader(
                "🎯 Website Trust Score"
            )

            trust_gauge = go.Figure(
                go.Indicator(

                    mode="gauge+number",

                    value=trust_score,

                    title={
                        "text":
                        "Trust Score"
                    },

                    gauge={

                        "axis": {
                            "range":
                            [0, 100]
                        },

                        "bar": {
                            "thickness":
                            0.3
                        },

                        "steps": [

                            {
                                "range":
                                [0, 40],

                                "color":
                                "red"
                            },

                            {
                                "range":
                                [40, 70],

                                "color":
                                "yellow"
                            },

                            {
                                "range":
                                [70, 100],

                                "color":
                                "green"
                            }
                        ]
                    }
                )
            )

            trust_gauge.update_layout(
                height=350
            )

            st.plotly_chart(
                trust_gauge,
                use_container_width=True
            )


            # AI RESULT

            st.subheader(
                "🤖 AI Prediction"
            )

            if ai_result == "Safe Website":

                st.success(
                    "✅ AI Verdict: Safe Website"
                )

            elif ai_result == "Suspicious Website":

                st.error(
                    "🚨 AI Verdict: Suspicious Website"
                )

            else:

                st.warning(
                    f"⚠️ AI Verdict: {ai_result}"
                )


        # -------------------------------------------------
        # WEBSITE INFO
        # -------------------------------------------------

        with tab2:

            if website_info:

                st.write(
                    "**🏢 Registrar:** "
                    f"{website_info.get('registrar', 'Unknown')}"
                )

                st.write(
                    "**📅 Creation Date:** "
                    f"{website_info.get('creation_date', 'Unknown')}"
                )

                st.write(
                    "**⏳ Expiration Date:** "
                    f"{website_info.get('expiration_date', 'Unknown')}"
                )

                st.write(
                    "**🌍 Name Servers:** "
                    f"{website_info.get('name_servers', 'Unknown')}"
                )

            else:

                st.warning(
                    "Could not fetch "
                    "website information."
                )


        # -------------------------------------------------
        # IP INFO
        # -------------------------------------------------

        with tab3:

            if ip_info:

                st.write(
                    "**🌐 IP Address:** "
                    f"{ip_info.get('ip', 'Unknown')}"
                )

                st.write(
                    "**🌎 Country:** "
                    f"{ip_info.get('country', 'Unknown')}"
                )

                st.write(
                    "**🏙️ City:** "
                    f"{ip_info.get('city', 'Unknown')}"
                )

                st.write(
                    "**🛰️ ISP:** "
                    f"{ip_info.get('isp', 'Unknown')}"
                )

            else:

                st.warning(
                    "⚠️ Could not fetch "
                    "IP information."
                )


        # -------------------------------------------------
        # BLACKLIST
        # -------------------------------------------------

        with tab4:

            if blacklist_status is True:

                st.error(
                    "🚨 Warning! This website "
                    "is listed as a phishing/"
                    "malicious website."
                )

            elif blacklist_status is False:

                st.success(
                    "✅ Website is not found "
                    "in the phishing blacklist."
                )

            else:

                st.warning(
                    "⚠️ Unable to verify "
                    "blacklist status."
                )


        # -------------------------------------------------
        # VIRUSTOTAL
        # -------------------------------------------------

        with tab5:

            st.subheader(
                "🦠 VirusTotal Scan"
            )

            if not isinstance(
                virustotal_result,
                dict
            ):

                st.warning(
                    "Unexpected VirusTotal response."
                )

            elif "error" in virustotal_result:

                st.error(
                    virustotal_result["error"]
                )

            else:

                vt_col1, vt_col2 = (
                    st.columns(2)
                )

                with vt_col1:

                    st.metric(
                        "🟢 Harmless",
                        virustotal_result.get(
                            "harmless",
                            0
                        )
                    )

                    st.metric(
                        "🟡 Suspicious",
                        virustotal_result.get(
                            "suspicious",
                            0
                        )
                    )

                with vt_col2:

                    st.metric(
                        "🔴 Malicious",
                        virustotal_result.get(
                            "malicious",
                            0
                        )
                    )

                    st.metric(
                        "⚪ Undetected",
                        virustotal_result.get(
                            "undetected",
                            0
                        )
                    )


        # -------------------------------------------------
        # REPORT AND SAVE BUTTON
        # -------------------------------------------------

        st.markdown("---")

        st.subheader(
            "📄 Website Analysis Report"
        )

        action_col1, action_col2 = (
            st.columns(2)
        )


        # DOWNLOAD REPORT

        with action_col1:

            if os.path.exists(
                "Website_Report.pdf"
            ):

                with open(
                    "Website_Report.pdf",
                    "rb"
                ) as pdf_file:

                    pdf_data = (
                        pdf_file.read()
                    )

                st.download_button(
                    label=
                    "📥 Download PDF Report",

                    data=pdf_data,

                    file_name=
                    "Website_Trust_Report.pdf",

                    mime=
                    "application/pdf",

                    use_container_width=True
                )

            else:

                st.warning(
                    "PDF report is not available."
                )


        # SAVE WEBSITE

        with action_col2:

            if st.button(
                "⭐ Save Website",
                use_container_width=True
            ):

                try:

                    if not st.session_state.authenticated or not st.session_state.user:
                        st.info(
                            "🔐 Please login to save websites to your account."
                        )

                    else:
                        user_id = st.session_state.user.get("id")

                        saved = save_website(
                            user_id,
                            url,
                            trust_score,
                            ai_result
                        )

                        if saved:

                            st.success(
                                "⭐ Website saved successfully!"
                            )

                        else:

                            st.info(
                                "This website is already saved."
                            )

                except Exception as e:

                    st.error(
                        "Could not save website: "
                        f"{e}"
                    )


# =========================================================
# HISTORY
# =========================================================

elif page == "📜 History":

    st.title(
        "📜 Scan History"
    )

    try:

        user_id = st.session_state.user["id"] if st.session_state.authenticated and st.session_state.user else None
        history = load_history(user_id)

        if history.empty:

            st.info(
                "No scan history available."
            )

        else:

            st.dataframe(
                history,
                use_container_width=True
            )

    except Exception as e:

        st.error(
            "Could not load scan history: "
            f"{e}"
        )


# =========================================================
# SAVED WEBSITES
# =========================================================

elif page == "⭐ Saved Websites":

    st.title(
        "⭐ Saved Websites"
    )

    try:

        if not st.session_state.authenticated or not st.session_state.user:
            saved_websites = pd.DataFrame(
                columns=[
                    "Website",
                    "Trust Score",
                    "AI Verdict",
                    "Saved Date"
                ]
            )
            st.info(
                "🔐 Please login to view your saved websites."
            )
        else:
            user_id = st.session_state.user.get("id")
            saved_websites = load_saved_websites(user_id)

        if saved_websites.empty:

            st.info(
                "No saved websites yet."
            )

        else:

            # DISPLAY SAVED WEBSITES
            # Reset the internal pandas index so the visible
            # numbering starts from 1 for this user's list.
            saved_websites = saved_websites.reset_index(drop=True)
            saved_websites.index = saved_websites.index + 1
            saved_websites.index.name = "No."

            st.dataframe(
                saved_websites,
                use_container_width=True
            )

            st.markdown("---")


            # ---------------------------------------------
            # DELETE SAVED WEBSITE
            # ---------------------------------------------

            st.subheader(
                "🗑️ Remove Saved Website"
            )

            website_to_delete = (
                st.selectbox(
                    "Select website to remove",
                    saved_websites[
                        "Website"
                    ].tolist()
                )
            )

            if st.button(
                "🗑️ Delete Website",
                type="secondary"
            ):

                user_id = st.session_state.user.get("id")

                deleted = (
                    delete_saved_website(
                        user_id,
                        website_to_delete
                    )
                )

                if deleted:

                    st.success(
                        "Website removed successfully!"
                    )

                    st.rerun()

                else:

                    st.error(
                        "Could not remove website."
                    )


    except Exception as e:

        st.error(
            "Could not load saved websites: "
            f"{e}"
        )



# =========================================================
# REVIEWS
# =========================================================

elif page == "💬 Reviews":

    st.title("💬 Website Reviews")
    st.write("Check reviews first, then share your own experience.")

    analyzed_url = ""
    if st.session_state.analysis_done and st.session_state.analysis_data is not None:
        analyzed_url = st.session_state.analysis_data.get("url", "")

    if "review_check_url" not in st.session_state:
        st.session_state.review_check_url = analyzed_url

    if analyzed_url and st.session_state.get("last_review_analysis_url") != analyzed_url:
        st.session_state.review_check_url = analyzed_url
        st.session_state.last_review_analysis_url = analyzed_url

    st.markdown("---")
    st.subheader("🔎 Check Website Reviews")

    if analyzed_url:
        st.success(f"Last analyzed website: {analyzed_url}")

    with st.form("check_reviews_form"):
        check_url = st.text_input(
            "Website URL",
            key="review_check_url",
            placeholder="https://www.amazon.in"
        )

        check_reviews_submitted = st.form_submit_button(
            "🔎 Check Reviews",
            type="primary",
            use_container_width=True
        )

    if check_reviews_submitted:
        if not check_url.strip():
            st.error("Analyze a website first or enter a website URL.")
        elif not validators.url(check_url.strip()):
            st.error("Please enter a valid complete URL.")
        else:
            st.session_state.checked_review_url = check_url.strip()

    checked_url = st.session_state.get("checked_review_url", "")

    if checked_url:
        st.markdown("---")
        st.subheader("👥 Customer Reviews")

        try:
            website_reviews = get_website_reviews(checked_url)

            if website_reviews.empty:
                st.info("No customer reviews yet. You can share the first review below.")
            else:
                average_rating = get_average_rating(checked_url)
                total_reviews = len(website_reviews)

                # ---------------------------------------------
                # OVERALL CUSTOMER OPINION
                # ---------------------------------------------

                experiences = (
                    website_reviews["Experience"]
                    .astype(str)
                    .str.strip()
                    .str.lower()
                )

                positive_count = int(
                    (experiences == "positive").sum()
                )

                negative_count = int(
                    (experiences == "negative").sum()
                )

                if total_reviews > 0:
                    positive_percentage = round(
                        (positive_count / total_reviews) * 100
                    )
                    negative_percentage = round(
                        (negative_count / total_reviews) * 100
                    )
                else:
                    positive_percentage = 0
                    negative_percentage = 0

                if positive_percentage >= 70:
                    overall_opinion = "Mostly Positive"
                    opinion_message = (
                        "Most customers reported a positive experience."
                    )
                elif negative_percentage >= 70:
                    overall_opinion = "Mostly Negative"
                    opinion_message = (
                        "Most customers reported a negative experience."
                    )
                else:
                    overall_opinion = "Mixed"
                    opinion_message = (
                        "Customer experiences are mixed."
                    )

                st.markdown("### 🌐 Overall Customer Opinion")

                opinion_col1, opinion_col2, opinion_col3 = st.columns(3)

                with opinion_col1:
                    st.metric(
                        "Overall Opinion",
                        overall_opinion
                    )

                with opinion_col2:
                    st.metric(
                        "😊 Positive",
                        f"{positive_percentage}%"
                    )

                with opinion_col3:
                    st.metric(
                        "😞 Negative",
                        f"{negative_percentage}%"
                    )

                st.info(
                    f"💬 {opinion_message}"
                )

                rating_col1, rating_col2 = st.columns(2)

                with rating_col1:
                    st.metric(
                        "⭐ Average Rating",
                        f"{average_rating}/5"
                    )

                with rating_col2:
                    st.metric(
                        "💬 Total Reviews",
                        total_reviews
                    )

                st.progress(
                    positive_percentage / 100
                )

                st.caption(
                    f"😊 Positive: {positive_percentage}%  •  "
                    f"😞 Negative: {negative_percentage}%"
                )

                st.markdown("### 🗣️ Customer Experiences")

                for _, review in website_reviews.iloc[::-1].iterrows():
                    try:
                        rating = int(float(review["Rating"]))
                    except (ValueError, TypeError):
                        rating = 0

                    stars = "⭐" * max(0, min(5, rating))
                    st.markdown(f"### {stars}")

                    experience = str(
                        review.get("Experience", "Not specified")
                    )

                    if experience.lower() == "positive":
                        st.success("😊 Positive Experience")
                    elif experience.lower() == "negative":
                        st.error("😞 Negative Experience")
                    else:
                        st.info(f"Overall Experience: {experience}")

                    st.write(f"**Category:** {review['Category']}")
                    st.write(review["Review"])
                    st.caption(f"Submitted: {review['Date']}")
                    st.markdown("---")

        except Exception as e:
            st.error(f"Could not load reviews: {e}")

        st.subheader("✍️ Share Your Experience")
        st.caption(f"Reviewing: {checked_url}")

        # -------------------------------------------------
        # POSITIVE / NEGATIVE EXPERIENCE
        # -------------------------------------------------

        st.write("### Overall Experience")

        review_experience = st.radio(
            "How was your overall experience?",
            ["😊 Positive", "😞 Negative"],
            horizontal=True,
            key="review_experience"
        )

        if review_experience == "😊 Positive":
            experience_value = "Positive"
        else:
            experience_value = "Negative"

        # -------------------------------------------------
        # STAR RATING
        # -------------------------------------------------

        review_rating = st.select_slider(
            "⭐ Your Rating",
            options=[1, 2, 3, 4, 5],
            value=5,
            key="review_rating"
        )

        # -------------------------------------------------
        # EXPERIENCE CATEGORY
        # -------------------------------------------------

        if experience_value == "Positive":
            review_categories = [
                "Great Experience",
                "Good Product Quality",
                "Fast Delivery",
                "Good Packaging",
                "Good Price / Value",
                "Smooth Payment Experience",
                "Helpful Customer Service",
                "Easy Return / Refund",
                "Easy Website Experience",
                "Trustworthy Experience",
                "Other"
            ]
        else:
            review_categories = [
                "Poor Experience",
                "Product Quality Issue",
                "Late Delivery",
                "Damaged / Poor Packaging",
                "High Price / Poor Value",
                "Payment Problem",
                "Poor Customer Service",
                "Return / Refund Problem",
                "Website Problem",
                "Trust / Safety Concern",
                "Other"
            ]

        review_category = st.selectbox(
            "What was your experience about?",
            review_categories,
            key="review_category"
        )

        # -------------------------------------------------
        # REVIEW MESSAGE
        # -------------------------------------------------

        review_text = st.text_area(
            "Tell us about your experience",
            placeholder=(
                "Tell other customers what you liked "
                "or what problem you experienced..."
            ),
            max_chars=1000,
            key="review_text"
        )

        # -------------------------------------------------
        # SUBMIT REVIEW
        # -------------------------------------------------

        if st.button("💬 Submit Review", use_container_width=True):

            if not st.session_state.authenticated or not st.session_state.user:
                st.info(
                    "🔐 Please login or create an account before submitting a review."
                )

            elif not review_text.strip():
                st.error("Please write your review before submitting.")

            else:
                try:
                    user_id = st.session_state.user.get("id")

                    saved = add_review(
                        checked_url,
                        experience_value,
                        review_rating,
                        review_category,
                        review_text.strip(),
                        user_id
                    )

                    if saved:
                        st.success(
                            "✅ Thank you! Your review has been submitted."
                        )
                    else:
                        st.error(
                            "Could not save review. Please make sure you are logged in."
                        )

                except Exception as e:
                    st.error(f"Could not save review: {e}")

    else:
        st.info("Click **Check Reviews** to see opinions and then share your experience.")


# =========================================================
# REPORTS
# =========================================================

elif page == "📄 Reports":

    st.title(
        "📄 Reports"
    )

    st.write(
        "Download the latest generated "
        "website security report."
    )

    if os.path.exists(
        "Website_Report.pdf"
    ):

        with open(
            "Website_Report.pdf",
            "rb"
        ) as pdf_file:

            report_data = (
                pdf_file.read()
            )

        st.download_button(
            label=
            "📥 Download Latest Report",

            data=report_data,

            file_name=
            "Website_Trust_Report.pdf",

            mime=
            "application/pdf"
        )

    else:

        st.info(
            "No report is available yet. "
            "Analyze a website first."
        )


# =========================================================
# SETTINGS
# =========================================================

elif page == "⚙️ Settings":

    st.title("⚙️ Settings")

    st.write(
        "Manage your TrustLens AI application data and current session."
    )

    st.markdown("---")

    # -----------------------------------------------------
    # RESET CURRENT ANALYSIS
    # -----------------------------------------------------

    st.subheader("🔄 Reset Current Analysis")

    st.write(
        "Remove the currently displayed website analysis "
        "from this session."
    )

    if st.button("🔄 Reset Analysis"):

        st.session_state.analysis_done = False
        st.session_state.analysis_data = None

        st.success("Current analysis has been reset successfully.")


    st.markdown("---")


    # -----------------------------------------------------
    # CLEAR SCAN HISTORY
    # -----------------------------------------------------

    st.subheader("🧹 Clear Scan History")

    st.warning(
        "This will permanently delete all website scan history."
    )

    confirm_history = st.checkbox(
        "I understand and want to clear scan history",
        key="confirm_history"
    )

    if st.button("🧹 Clear History"):

        if not confirm_history:

            st.error(
                "Please confirm before clearing scan history."
            )

        else:

            try:
                user_id = (
                    st.session_state.user["id"]
                    if st.session_state.authenticated and st.session_state.user
                    else None
                )

                cleared = clear_history(user_id)

                if cleared:
                    st.success(
                        "Scan history cleared successfully!"
                    )
                else:
                    st.info(
                        "There is no scan history to clear."
                    )

            except Exception as e:
                st.error(
                    f"Could not clear scan history: {e}"
                )


    st.markdown("---")


    # -----------------------------------------------------
    # CLEAR SAVED WEBSITES
    # -----------------------------------------------------

    st.subheader("🗑️ Clear Saved Websites")

    st.warning(
        "This will permanently remove all websites "
        "from your Saved Websites list."
    )

    confirm_saved = st.checkbox(
        "I understand and want to clear all saved websites",
        key="confirm_saved"
    )

    if st.button("🗑️ Clear All Saved Websites"):

        if not confirm_saved:

            st.error(
                "Please confirm before clearing saved websites."
            )

        else:

            try:
                user_id = (
                    st.session_state.user.get("id")
                    if st.session_state.authenticated and st.session_state.user
                    else None
                )

                if user_id is None:
                    cleared = False
                else:
                    cleared = clear_saved_websites(user_id)

                if cleared:
                    st.success(
                        "All saved websites removed successfully!"
                    )
                else:
                    st.info(
                        "There are no saved websites to clear."
                    )

            except Exception as e:
                st.error(
                    f"Could not clear saved websites: {e}"
                )


    st.markdown("---")

    st.subheader("ℹ️ Application")

    col1, col2 = st.columns(2)

    with col1:
        st.write("**Application:** TrustLens AI")
        st.write("**Version:** 1.0")

    with col2:
        st.write("**Framework:** Streamlit")
        st.write("**System:** AI Website Trust Analyzer")


# =========================================================
# ABOUT
# =========================================================

elif page == "ℹ️ About":

    st.title(
        "ℹ️ About TrustLens AI"
    )

    st.markdown(
        """
        **TrustLens AI** is an AI-powered
        website trust and security analysis system.

        ### Security Analysis

        TrustLens AI analyzes websites using:

        - SSL Certificate Validation
        - HTTPS Detection
        - Domain Age Analysis
        - Blacklist Detection
        - VirusTotal Security Analysis
        - IP and Hosting Information
        - Machine Learning Prediction
        - Website Trust Score

        ### Additional Features

        - Scan History
        - Saved Websites
        - Delete Saved Websites
        - Dashboard Analytics
        - Recent Scan Activity
        - PDF Security Reports
        """
    )

    st.markdown("---")

    st.info(
        "🛡️ TrustLens AI — Version 1.0"
    )