import streamlit as st
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

st.set_page_config(page_title="Phishing URL Detector", page_icon="🔐", layout="centered")

st.markdown("""
<style>
.stApp {background: linear-gradient(135deg, #eef5ff, #f8faff);}
h1 {color: #173b70;}
.result {padding: 18px; border-radius: 12px; font-size: 20px; font-weight: 600;}
</style>
""", unsafe_allow_html=True)

st.title("🔐 Phishing URL Detector")
st.write("Enter a website URL to check whether it may be suspicious.")

@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")

def extract_features(url, feature_names):
    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed.netloc.lower()
    path = parsed.path
    values = {
        "Have_IP": int(bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname))),
        "Have_At": int("@" in url),
        "URL_Length": len(url),
        "URL_Depth": path.count("/"),
        "Redirection": int(url.count("//") > 1),
        "https_Domain": int("https" in hostname),
        "TinyURL": int(any(x in hostname for x in ["bit.ly", "tinyurl", "t.co", "goo.gl"])),
        "Prefix/Suffix": int("-" in hostname),
    }
    # Missing feature values are set to 0. Confirm this matches your training notebook.
    return pd.DataFrame([[values.get(name, 0) for name in feature_names]], columns=feature_names)

url = st.text_input("Website URL", placeholder="https://example.com")
sample = st.selectbox("Or try an example", ["Choose an example", "https://www.wikipedia.org", "http://192.168.1.1/login", "https://secure-login-example.com"])
if sample != "Choose an example" and not url:
    url = sample

if st.button("Check URL", type="primary", use_container_width=True):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        try:
            loaded = load_model()
            if isinstance(loaded, dict):
                model = loaded.get("model")
                feature_names = loaded.get("features")
            else:
                model = loaded
                feature_names = getattr(model, "feature_names_in_", None)

            if model is None or not feature_names:
                st.error("The model file must contain both a trained model and its feature names.")
            else:
                features = extract_features(url.strip(), list(feature_names))
                prediction = model.predict(features)[0]
                label = str(prediction).lower()
                is_suspicious = label in {"1", "true", "phishing", "malicious", "suspicious"}

                if is_suspicious:
                    st.error("⚠️ This URL is predicted to be suspicious.")
                else:
                    st.success("✅ This URL is predicted to be likely legitimate.")

                st.caption("This is a model prediction, not a guarantee that a website is safe.")
        except FileNotFoundError:
            st.error("Could not find phishing_model.pkl. Add it to the same GitHub folder as app.py.")
        except Exception as error:
            st.error(f"Could not check this URL: {error}")

