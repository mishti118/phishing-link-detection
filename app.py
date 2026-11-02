
import streamlit as st
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

st.set_page_config(
    page_title="Phishing Link Detection",
    page_icon="🔐",
    layout="wide"
)

# ---------- DESIGN ----------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #edf4ff, #ffffff);
}
h1, h2, h3 {
    color: #12376a;
}
.main-title {
    background: linear-gradient(100deg, #073b7a, #087ed4);
    color: white;
    padding: 28px;
    border-radius: 18px;
    text-align: center;
    margin-bottom: 25px;
}
.info-card {
    background: white;
    padding: 22px;
    border-radius: 15px;
    border: 1px solid #d9e6fa;
    margin-top: 15px;
}
.stButton > button {
    background: linear-gradient(90deg, #0866c6, #168de0);
    color: white;
    border-radius: 10px;
    border: none;
    padding: 10px 25px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ---------- SIDEBAR ----------
with st.sidebar:
    st.image(
        "https://cdn-icons-png.flaticon.com/512/6195/6195699.png",
        width=140
    )

    st.title("Stay Safe Online!")
    st.markdown("---")

    st.subheader("ℹ️ About")
    st.write(
        "This application uses Machine Learning "
        "to predict whether a website URL may be "
        "phishing or legitimate."
    )

    st.markdown("---")
    st.subheader("💡 How to Use")
    st.write("1. Enter a website URL.")
    st.write("2. Or choose an example.")
    st.write("3. Click Check URL.")
    st.write("4. View the model prediction.")

    st.markdown("---")
    st.caption("Browse Safe • Stay Secure 🔐")

# ---------- HEADER ----------
st.markdown("""
<div class="main-title">
    <h1 style="color:white;">🔐 Web Page Phishing Detection</h1>
    <p>Check whether a website link may be safe or suspicious</p>
</div>
""", unsafe_allow_html=True)

st.markdown(
    "### 🔗 Enter Website URL"
)

url = st.text_input(
    "Website URL",
    placeholder="https://example.com",
    label_visibility="collapsed"
)

# ---------- EXAMPLE URLS ----------
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
    "Example URLs are for demonstration. "
    "The trained model determines the prediction."
)

# ---------- FEATURE EXTRACTION ----------
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
            domain in hostname
            for domain in ["bit.ly", "tinyurl", "t.co", "goo.gl"]
        )),
        "Prefix/Suffix": int("-" in hostname)
    }

    return pd.DataFrame(
        [[values.get(name, 0) for name in feature_names]],
        columns=feature_names
    )

# ---------- PREDICTION ----------
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
                        "This URL is predicted to be suspicious. "
                        "Avoid entering personal information."
                    )
                else:
                    st.success("✅ URL Predicted as Likely Legitimate")
                    st.write(
                        "The model predicts that this URL is likely "
                        "legitimate. Always browse carefully."
                    )

                st.caption(
                    "This is a machine-learning prediction, "
                    "not a guarantee that a website is safe."
                )

        except FileNotFoundError:
            st.error(
                "phishing_model.pkl was not found. "
                "Add it to the same folder as app.py."
            )

        except Exception as error:
            st.error(f"Prediction error: {error}")

# ---------- FOOTER ----------
st.markdown("---")
st.markdown(
    "<center>🔒 Browse Safe. Stay Secure.</center>",
    unsafe_allow_html=True
)
```
