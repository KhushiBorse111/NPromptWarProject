import os
import streamlit as st
import requests
from google import genai

# Page Configuration
st.set_page_config(
    page_title="CyberShield AI - Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ CyberShield AI")
st.caption("Automated Threat Intelligence & Gemini Defense Layer")
st.markdown("---")

# Sidebar Configuration & Quick Vectors
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Retrieve Gemini API Key from secrets or environment
    gemini_key = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY", ""))
    
    if gemini_key:
        st.success("🟢 Gemini API Key Detected")
    else:
        st.warning("⚠️ Gemini API Key Missing")
        gemini_key = st.text_input("Enter Gemini API Key:", type="password")

    st.markdown("---")
    st.markdown("### Quick Load Hackathon Vectors")
    quick_choice = st.radio(
        "Select Test Payload:",
        ("None", "Phishing URL", "SSRF Attack Test", "SQL Injection"),
        index=0
    )

# Pre-fill input based on selected quick vector
default_val = ""
if quick_choice == "Phishing URL":
    default_val = "https://paypal.com.verify-account-update.xyz/login"
elif quick_choice == "SSRF Attack Test":
    default_val = "http://168.254.169.254/latest/meta-data"
elif quick_choice == "SQL Injection":
    default_val = "' OR '1'='1"

# Main Inspection Interface
st.subheader("🔍 Security Payload Inspector")
user_input = st.text_area("Enter Target URL or Vector for Inspection:", value=default_val, height=120)

col1, _ = st.columns([1, 4])
with col1:
    analyze_btn = st.button("🚀 Analyze Vector", use_container_width=True)

# Analysis Logic
if analyze_btn:
    if not user_input.strip():
        st.error("Please enter a valid URL or payload string.")
    else:
        with st.spinner("Evaluating Threat Vector with Gemini Intelligence..."):
            
            # Local SSRF Protection Filter
            if "168.254.169.254" in user_input or "127.0.0.1" in user_input or "localhost" in user_input:
                st.error("🚫 **SSRF Threat Blocked!** Access to metadata service or local loopback IP detected (403 Forbidden).")
            
            # Gemini Model Evaluation
            elif gemini_key:
                try:
                    client = genai.Client(api_key=gemini_key)
                    prompt = f"""
                    You are a cybersecurity expert. Analyze the following target URL/vector for security threats:
                    Vector: '{user_input}'

                    Provide a short, structured evaluation:
                    1. Threat Risk Level (Low / Medium / High / Critical)
                    2. Vector Classification (Phishing, SSRF, Injection, Safe, etc.)
                    3. Recommended Action
                    """
                    
                    response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=prompt,
                    )
                    
                    st.success("Analysis Complete!")
                    st.markdown("### 📊 Threat Evaluation Report")
                    st.markdown(response.text)
                    
                except Exception as e:
                    st.error(f"Error executing Gemini API: {str(e)}")
            else:
                st.error("Gemini API key is required to perform threat evaluation.")
