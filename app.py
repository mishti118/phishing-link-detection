
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


# ---------------- LOAD MODEL ----------------

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

    model = model_data["model"]
    features = model_data["features"]

    return model, features


try:
    model, features = load_model()

except Exception as e:
    st.error(f"Error loading model: {e}")
    st.stop()


# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        ip = 1
    except ValueError:
        ip = 0

    # Extract port
    try:
        port = 1 if parsed.port is not None else 0
    except ValueError:
        port = 0

    # Count digits
    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)

    # Calculate digit ratios
    ratio_digits_url = digits_url / len(url) if len(url) else 0
    ratio_digits_host = digits_host / len(hostname) if len(hostname) else 0

    # Count URL features
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

        "ratio_digits_url": ratio_digits_url,

        "ratio_digits_host": ratio_digits_host,

        "punycode": int("xn--" in hostname.lower()),

        "port": port,

        "nb_subdomains": max(len(hostname.split(".")) - 2, 0),

        "prefix_suffix": int("-" in hostname),

        "path_extension": int(
            bool(re.search(
                r"\.(php|html|htm|asp|aspx|jsp|cgi)$",
                path.lower()
            ))
        )
    }

    # Arrange features in the exact order expected by the model
    feature_data = pd.DataFrame([data])

    return feature_data[features]


# ---------------- SIDEBAR ----------------

with st.sidebar:

    st.image(
        "sidebar_image.png",
        use_container_width=True
    )

    st.title("Phishing Detection")

    st.write(
        "Protect yourself from suspicious and malicious websites."
    )

    st.divider()

    st.info(
        "Enter a website URL or select an example to check it."
    )


# ---------------- MAIN PAGE ----------------

st.title("🛡️ Phishing Website Detection")

st.write(
    "This application uses Machine Learning to predict "
    "whether a website URL is legitimate or phishing."
)

st.divider()


# ---------------- EXAMPLE URLS ----------------

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
    "Choose an example website:",
    ["Select an example"] + list(examples.keys()),
    key="example_choice",
    on_change=update_example_url
)


# ---------------- URL INPUT ----------------

url = st.text_input(
    "Enter Website URL",
    placeholder="https://www.example.com",
    key="url_input"
)


# ---------------- PREDICTION ----------------

if st.button("🔍 Detect Phishing", use_container_width=True):

    if not url.strip():

        st.warning("Please enter a website URL.")

    else:

        try:

            with st.spinner("Analyzing website URL..."):

                input_features = extract_features(url)

                prediction = model.predict(input_features)[0]

                # Get prediction probabilities
                probabilities = model.predict_proba(input_features)[0]

                # Find probability corresponding to each class
                classes = list(model.classes_)

                phishing_probability = probabilities[classes.index(1)]
                legitimate_probability = probabilities[classes.index(0)]

            st.divider()

            st.subheader("📊 Detection Result")

            st.write("Website URL:", url)

            if prediction == 1:

                st.error(
                    "⚠️ This website is predicted to be PHISHING!"
                )

                st.metric(
                    "Phishing Confidence",
                    f"{phishing_probability * 100:.2f}%"
                )

            else:

                st.success(
                    "✅ This website is predicted to be LEGITIMATE!"
                )

                st.metric(
                    "Legitimate Confidence",
                    f"{legitimate_probability * 100:.2f}%"
                )

            st.subheader("Prediction Probabilities")

            col1, col2 = st.columns(2)

            with col1:

                st.metric(
                    "Legitimate",
                    f"{legitimate_probability * 100:.2f}%"
                )

            with col2:

                st.metric(
                    "Phishing",
                    f"{phishing_probability * 100:.2f}%"
                )

            st.caption(
                "Note: This is a machine-learning prediction, "
                "not a guarantee that a website is safe. "
                "The application analyzes URL features and does not "
                "verify the website's actual content."
            )

        except Exception as e:

            st.error(f"An error occurred: {e}")


# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "Phishing Website Detection System | Machine Learning Project"
)
