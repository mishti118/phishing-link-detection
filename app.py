

import streamlit as st
import pandas as pd
import joblib
import zipfile
import io
import re
import ipaddress
from urllib.parse import urlparse


# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="Phishing Website Detection",
    page_icon="🛡️",
    layout="wide"
)


# ---------------- LOAD TRAINED MODEL ----------------

@st.cache_resource
def load_model():

    with zipfile.ZipFile("model.zip", "r") as zip_file:

        pkl_file = [
            file for file in zip_file.namelist()
            if file.endswith(".pkl")
        ][0]

        model_bytes = zip_file.read(pkl_file)

        model_data = joblib.load(io.BytesIO(model_bytes))

    model = model_data["model"]
    features = model_data["features"]

    return model, features


model, features = load_model()


# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed_url = urlparse(url)

    hostname = parsed_url.netloc
    path = parsed_url.path

    try:
        ipaddress.ip_address(hostname.split(":")[0])
        ip = 1
    except ValueError:
        ip = 0

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
        "nb_dslash": url.count("//"),
        "http_in_path": int("http" in path.lower()),
        "https_token": int("https" in hostname.lower()),
        "ratio_digits_url": digits_url / len(url) if len(url) else 0,
        "ratio_digits_host": digits_host / len(hostname) if len(hostname) else 0,
        "punycode": int("xn--" in hostname.lower()),
        "port": int(parsed_url.port is not None) if parsed_url.port else 0,
        "nb_subdomains": max(0, hostname.count(".") - 1),
        "prefix_suffix": int("-" in hostname),
        "path_extension": int("." in path.split("/")[-1])
    }

    df = pd.DataFrame([data])

    return df[features]


# ---------------- SIDEBAR ----------------

with st.sidebar:

    st.image("sidebar_image.png", use_container_width=True)

    st.title("Phishing Detection")

    st.write(
        "This application checks website URLs "
        "and predicts whether they are phishing "
        "or legitimate."
    )

    st.divider()

    st.info(
        "Stay safe online. Always verify website "
        "addresses before entering personal information."
    )


# ---------------- MAIN PAGE ----------------

st.title("🛡️ Phishing Website Detection")

st.write(
    "Enter a website URL or select an example URL "
    "to check whether it is predicted to be phishing "
    "or legitimate."
)

st.divider()


# ---------------- EXAMPLE WEBSITE URLS ----------------

st.subheader("🌐 Try Example Websites")

examples = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://github.com",
    "http://paypal-login-security.example.com/verify",
    "http://account-update-confirm.example.com/login"
]

selected_example = st.selectbox(
    "Select an example website:",
    ["Select an example"] + examples
)


# ---------------- MANUAL URL INPUT ----------------

url = st.text_input(
    "Or enter your own Website URL:",
    placeholder="https://www.example.com"
)


# ---------------- DETECTION BUTTON ----------------

if st.button("🔍 Detect Phishing", use_container_width=True):

    # Use the manually entered URL if provided.
    # Otherwise, use the selected example URL.

    if url.strip():
        website_url = url.strip()

    elif selected_example != "Select an example":
        website_url = selected_example

    else:
        website_url = ""

    if not website_url:

        st.warning(
            "Please select an example or enter a website URL."
        )

    else:

        try:

            with st.spinner("Analyzing website..."):

                input_features = extract_features(website_url)

                prediction = model.predict(input_features)[0]

            st.divider()

            st.subheader("Detection Result")

            st.write("Website:", website_url)

            if prediction == 1:

                st.error(
                    "⚠️ This website is predicted to be PHISHING!"
                )

            else:

                st.success(
                    "✅ This website is predicted to be LEGITIMATE!"
                )

        except Exception as e:

            st.error(f"An error occurred: {e}")


# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "Phishing Website Detection System | "
    "Machine Learning Project"
)

st.caption(
    "Note: Predictions are based on URL features "
    "and are not a guarantee that a website is safe."
)
