import streamlit as st
import validators

from modules.ssl_checker import check_ssl
from modules.domain_age import get_domain_age
from modules.https_checker import check_https
from modules.trust_score import calculate_trust_score
from modules.website_info import get_website_info
from modules.ip_info import get_ip_info
from modules.blacklist_checker import check_blacklist
from modules.predict import predict_website
from modules.virustotal_checker import check_virustotal

st.set_page_config(
    page_title="Website Trust Score Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Shopping Website Trust Score Analyzer")

st.markdown("### Check whether an online shopping website is safe or suspicious")

url = st.text_input("Enter Shopping Website URL")

if st.button("Analyze Website"):

    if url == "":
        st.error("Please enter a website URL.")

    elif not validators.url(url):
        st.error("Invalid Website URL")
    else: 
        st.success("Valid Website URL")

        ssl_status = check_ssl(url)
       
        domain_age=get_domain_age(url)
       
        https_status=check_https(url)
      
        trust_score = calculate_trust_score(
          ssl_status,
          https_status,
          domain_age
        )
        features = [
          1 if ssl_status else -1,
          1 if https_status else -1,
          domain_age if domain_age is not None else 0
        ]

        ai_result = predict_website(features)
        
        website_info = get_website_info(url)
        ip_info=get_ip_info(url)
        blacklist_status = check_blacklist(url)
        virustotal_result = check_virustotal(url)
        
        if ssl_status:
           st.success("🔒 SSL Certificate: Valid")
        else:
           st.error("❌ SSL Certificate: Invalid")
          
        if domain_age is not None:
           st.info(f"🌐 Domain Age: {domain_age} years")
        else:
           st.warning("⚠️ Could not determine domain age.")
        
        if https_status:
           st.success("🔒 HTTPS: Enabled")
        else:
           st.warning("⚠️ HTTPS: Not Enabled")

        st.markdown("---")
        st.subheader("🛡️ Trust Score")

        st.progress(trust_score / 100)

        st.success(f"Trust Score: {trust_score}/100")

        if trust_score >= 80:
           st.success("🟢 SAFE WEBSITE")
        elif trust_score >= 50:
           st.warning("🟡 MEDIUM RISK")
        else:
           st.error("🔴 HIGH RISK")
        st.markdown("---")
        st.subheader("🌐 Website Information")

        if website_info:
           st.write(f"**🏢 Registrar:** {website_info['registrar']}")
           st.write(f"**📅 Creation Date:** {website_info['creation_date']}")
           st.write(f"**⏳ Expiration Date:** {website_info['expiration_date']}")
           st.write(f"**🌍 Name Servers:** {website_info['name_servers']}")
        else:
           st.warning("Could not fetch website information.")
        st.markdown("---")
        st.subheader("🌍 IP & Hosting Information")

        if ip_info:
           st.write(f"**🌐 IP Address:** {ip_info['ip']}")
           st.write(f"**🌎 Country:** {ip_info['country']}")
           st.write(f"**🏙️ City:** {ip_info['city']}")
           st.write(f"**🛰️ ISP:** {ip_info['isp']}")
        else:
           st.warning("⚠️ Could not fetch IP information.")   
        st.markdown("---")
        st.subheader("🚫 Blacklist Check")

        if blacklist_status is True:
           st.error("🚨 Warning! This website is listed as a phishing/malicious website.")
        elif blacklist_status is False:
           st.success("✅ Website is not found in the phishing blacklist.")
        else:
           st.warning("⚠️ Unable to verify the blacklist status.")