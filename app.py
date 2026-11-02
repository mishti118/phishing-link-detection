


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

# Sidebar with image and instructions
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
    st.write("2. Choose an example if you want.")
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

# Example URLs
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
        "https_Domain": int("https" in hostname),
        "TinyURL": int(any(
            x in hostname
            for x in ["bit.ly", "tinyurl", "t.co", "goo.gl"]
        )),
        "Prefix/Suffix": int("-" in hostname)
    }

    return pd.DataFrame(
        [[values.get(name, 0) for name in feature_names]],
        columns=feature_names
    )

# Check URL
if st.button("🔍 Check URL", use_container_width=True):

    if not url.strip() or url == "Choose an example":
        st.warning("Please enter or select a URL.")

    else:
        try:
            loaded = joblib.load("phishing_model.pkl")

            if isinstance(loaded, dict):
                model = loaded.get("model")
                feature_names = loaded.get("features")
            else:
                model = loaded
                feature_names = getattr(
                    model, "feature_names_in_", None
                )

            if model is None or feature_names is None:
                st.error(
                    "Model or feature names are missing. "
                    "Please check your saved model."
                )

            else:
                features = extract_features(
                    url.strip(),
                    list(feature_names)
                )

                prediction = model.predict(features)[0]
                label = str(prediction).strip().lower()

                suspicious = label in {
                    "1", "true", "phishing",
                    "malicious", "suspicious"
                }

                st.markdown("---")

                if suspicious:
                    st.error("🚨 Phishing Link Detected!")
                    st.write(
                        "The model predicts that this URL "
                        "may be suspicious. Browse carefully."
                    )
                else:
                    st.success("✅ URL Predicted as Likely Legitimate")
                    st.write(
                        "The model predicts that this URL "
                        "is likely legitimate."
                    )

                st.caption(
                    "A model prediction cannot guarantee "
                    "that a website is safe."
                )

        except FileNotFoundError:
            st.error(
                "phishing_model.pkl was not found. "
                "Add it to the same folder as app.py."
            )

        except Exception as error:
            st.error(f"Prediction error: {error}")

# Footer
st.markdown("---")
st.markdown(
    "<center>🔒 Browse Safe. Stay Secure.</center>",
    unsafe_allow_html=True
)


