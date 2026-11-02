

import streamlit as st
import pandas as pd
import joblib
import zipfile
import io
import re
import ipaddress

from urllib.parse import urlparse
from pathlib import Path


# -----------------------------------------
# PAGE CONFIGURATION
# -----------------------------------------

st.set_page_config(
    page_title="Phishing Website Detection",
    page_icon="🛡️",
    layout="wide"
)


# -----------------------------------------
# LOAD MODEL FROM ZIP
# -----------------------------------------

@st.cache_resource
def load_model():

    zip_path = Path("model.zip")

    if not zip_path.exists():
        raise FileNotFoundError("model.zip not found!")

    with zipfile.ZipFile(zip_path, "r") as z:
        model_files = [
            name for name in z.namelist()
            if name.endswith(".pkl")
        ]

        if not model_files:
            raise ValueError("No model file found inside model.zip")

        model_bytes = z.read(model_files[0])

    model_data = joblib.load(io.BytesIO(model_bytes))

    return model_data["model"], model_data["features"]


model, features = load_model()


# -----------------------------------------
# FEATURE EXTRACTION
# -----------------------------------------

def extract_features(url):

    url = url.strip()

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    if not hostname:
        raise ValueError("Please enter a valid website URL.")

    try:
        ipaddress.ip_address(hostname)
        ip = 1
    except ValueError:
        ip = 0

    try:
        port = int(parsed.port is not None)
    except ValueError:
        raise ValueError("Invalid port in URL.")

    url_lower = url.lower()
    host_lower = hostname.lower()

    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)

    path_suffix = Path(path).suffix

    # Calculate all 32 features
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

        "nb_www": url_lower.count("www"),

        "nb_com": url_lower.count("com"),

        "nb_dslash": max(0, url.count("//") - 1),

        "http_in_path": path.lower().count("http"),

        "https_token": int("https" in host_lower),

        "ratio_digits_url": digits_url / len(url) if url else 0,

        "ratio_digits_host": digits_host / len(hostname) if hostname else 0,

        "punycode": int("xn--" in host_lower),

        "port": port,

        "nb_subdomains": hostname.count("."),

        "prefix_suffix": int("-" in hostname),

        "path_extension": int(bool(path_suffix))

    }

    return pd.DataFrame([data])[features]


# -----------------------------------------
# SIDEBAR
# -----------------------------------------

with st.sidebar:

    try:
        st.image("sidebar_image.png", use_container_width=True)
    except:
        st.info("Add sidebar_image.png to your project.")

    st.title("🛡️ Phishing Detector")

    st.write(
        "Protect yourself from suspicious "
        "and fraudulent websites using Machine Learning."
    )

    st.divider()

    st.subheader("About Project")

    st.write(
        "This application uses a Random Forest "
        "Classifier to detect phishing websites."
    )

    st.caption("Machine Learning Based Detection")


# -----------------------------------------
# MAIN PAGE
# -----------------------------------------

st.title("Website Phishing Detection")

st.write(
    "Enter a website URL below to check whether "
    "it is legitimate or potentially a phishing website."
)

st.divider()


# -----------------------------------------
# URL INPUT
# -----------------------------------------

st.subheader("🔗 Enter Website URL")

website_url = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)

st.caption(
    "Example: https://www.google.com"
)


# -----------------------------------------
# PREDICTION
# -----------------------------------------

if st.button("🔍 Detect Phishing", use_container_width=True):

    if not website_url.strip():

        st.warning("Please enter a website URL.")

    else:

        try:

            input_data = extract_features(website_url)

            prediction = model.predict(input_data)[0]

            probabilities = model.predict_proba(input_data)[0]

            classes = list(model.classes_)

            phishing_probability = probabilities[
                classes.index(1)
            ]

            legitimate_probability = probabilities[
                classes.index(0)
            ]

            st.divider()

            st.subheader("Prediction Result")

            if prediction == 1:

                st.error("⚠️ PHISHING WEBSITE DETECTED")

                st.write(
                    "This website has been classified "
                    "as potentially malicious."
                )

            else:

                st.success("✅ LEGITIMATE WEBSITE")

                st.write(
                    "This website has been classified "
                    "as legitimate by the model."
                )

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "Phishing Probability",
                    f"{phishing_probability * 100:.2f}%"
                )

            with col2:
                st.metric(
                    "Legitimate Probability",
                    f"{legitimate_probability * 100:.2f}%"
                )

            st.caption(
                "Predictions are based on URL characteristics "
                "and are not a guarantee of website safety."
            )

        except Exception as e:

            st.error(f"Prediction error: {e}")
