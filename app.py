

import streamlit as st
import pandas as pd
import joblib
import zipfile
import io
import re
import ipaddress

from urllib.parse import urlparse


# PAGE CONFIGURATION
st.set_page_config(
    page_title="Phishing Website Detection",
    page_icon="🛡️",
    layout="wide"
)


# LOAD MODEL
@st.cache_resource
def load_model():

    with zipfile.ZipFile("model.zip", "r") as zip_file:

        pkl_files = [
            file for file in zip_file.namelist()
            if file.endswith(".pkl")
        ]

        if not pkl_files:
            raise FileNotFoundError("No model file found inside model.zip")

        with zip_file.open(pkl_files[0]) as file:
            model_data = joblib.load(io.BytesIO(file.read()))

    return model_data["model"], model_data["features"]


try:
    model, features = load_model()
except Exception as e:
    st.error(f"Error loading model: {e}")
    st.stop()


# FEATURE EXTRACTION
def extract_features(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    try:
        ipaddress.ip_address(hostname)
        ip = 1
    except ValueError:
        ip = 0

    try:
        port = 1 if parsed.port is not None else 0
    except ValueError:
        port = 0

    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)

    data = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": ip,
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_tilde": url.count("~"),
        "nb_percent": url.count("%"),
        "nb_slash": url.count("/"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" "),
        "nb_www": url.lower().count("www"),
        "nb_com": url.lower().count(".com"),
        "nb_dslash": max(url.count("//") - 1, 0),
        "http_in_path": path.lower().count("http"),
        "https_token": int("https" in hostname.lower()),
        "ratio_digits_url": digits_url / len(url) if len(url) else 0,
        "ratio_digits_host": digits_host / len(hostname) if len(hostname) else 0,
        "punycode": int("xn--" in hostname.lower()),
        "port": port,
        "nb_subdomains": max(len(hostname.split(".")) - 2, 0),
        "prefix_suffix": int("-" in hostname),
        "path_extension": int(bool(re.search(
            r"\.(php|html|htm|asp|aspx|jsp|cgi)$",
            path.lower()
        )))
    }

    return pd.DataFrame([data])[features]


# SIDEBAR
with st.sidebar:

    st.image("sidebar_image.png", use_container_width=True)

    st.title("Phishing Detection")

    st.write("Protect yourself from suspicious and malicious websites.")

    st.divider()

    st.info("Enter a website URL to check whether it is legitimate or phishing.")


# MAIN PAGE
st.title("🛡️ Phishing Website Detection")

st.write(
    "This application uses Machine Learning to identify "
    "potential phishing websites."
)

st.divider()


# EXAMPLE WEBSITES
st.subheader("🌐 Try Example Websites")

examples = {
    "Google - Legitimate": "https://www.google.com",
    "Wikipedia - Legitimate": "https://www.wikipedia.org",
    "GitHub - Legitimate": "https://github.com",
    "Suspicious Login Example": "http://paypal-login-security.example.com/verify",
    "Suspicious Account Example": "http://account-update-confirm.example.com/login"
}


def update_example_url():

    selected = st.session_state.example_choice

    if selected != "Select an example":
        st.session_state.url_input = examples[selected]


st.selectbox(
    "Select an example website:",
    ["Select an example"] + list(examples.keys()),
    key="example_choice",
    on_change=update_example_url
)


# URL INPUT
url = st.text_input(
    "Enter Website URL:",
    placeholder="https://www.example.com",
    key="url_input"
)


# DETECT PHISHING
if st.button("🔍 Detect Phishing", use_container_width=True):

    if not url.strip():

        st.warning("Please enter a website URL.")

    else:

        try:

            with st.spinner("Analyzing website..."):

                input_features = extract_features(url)

                prediction = model.predict(input_features)[0]

            st.divider()

            st.subheader("Detection Result")

            if prediction == 1:

                st.error("⚠️ This website is predicted to be PHISHING!")

            else:

                st.success("✅ This website is predicted to be LEGITIMATE!")

        except Exception as e:

            st.error(f"An error occurred: {e}")


# FOOTER
st.divider()

st.caption("Phishing Website Detection System | Machine Learning Project")
