
import streamlit as st
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# Page settings
st.set_page_config(
    page_title="Phishing Link Detection",
    page_icon="🔐",
    layout="wide"
)

# Simple styling
st.markdown("""
<style>
.stApp {
    background-color: #f0f6ff;
}
.title-box {
    background: linear-gradient(90deg, #073b7a, #168de0);
    padding: 25px;
    border-radius: 15px;
    text-align: center;
    color: white;
}
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image(
        "https://cdn-icons-png.flaticon.com/512/6195/6195699.png",
        width=130
    )

    st.title("🔐 Stay Safe Online!")
    st.markdown("---")

    st.subheader("About")
    st.write(
        "This application uses Machine Learning "
        "to predict whether a website URL may be suspicious."
    )

    st.markdown("---")

    st.subheader("How to Use")
    st.write("1. Enter a website URL.")
    st.write("2. Choose an example URL.")
    st.write("3. Click Check URL.")
    st.write("4. View the prediction.")

    st.markdown("---")
    st.caption("Browse Safe • Stay Secure 🔒")

# Main heading
st.markdown("""
<div class="title-box">
    <h1 style="color:white;">🔐 Web Page Phishing Detection</h1>
    <p>Check whether a website link may be suspicious</p>
</div>
""", unsafe_allow_html=True)

# Main image
st.image(
    "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
    width=90
)

# URL input
st.subheader("🔗 Enter Website URL")

url = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)

# Legitimate and phishing-style examples
examples = [
    "Choose an example",
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.apple.com",
    "http://192.168.1.1/login",
    "http://secure-login-example.com",
    "http://verify-account-example.test",
    "http://login-example.test/update"
]

selected_example = st.selectbox(
    "⭐ Try an example URL",
    examples
)

if selected_example != "Choose an example" and not url:
    url = selected_example

st.caption(
    "Examples are for demonstration. "
    "The trained model determines the prediction."
)

# Extract URL features
def extract_features(url, feature_names):
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path

    values = {
        "Have_IP": int(bool(
            re.match(r"^(\\d{1,3}\\.){3}\\d{1,3}$", hostname)
        )),
        "Have_At": int("@" in url),
        "URL_Length": len(url),
        "URL_Depth": path.count("/"),
        "Redirection": int(url.count("//") > 1),
        "https_Domain
