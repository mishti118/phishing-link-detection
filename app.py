
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

HERE = Path(__file__).parent

st.set_page_config(page_title="Phishing Website Detector", page_icon="🛡️")


@st.cache_resource
def load_model():
    data = joblib.load(HERE / "phishing_model.pkl")
    return data["model"], data["features"]


model, features = load_model()

# ---------------- Sidebar: enter the 10 features ----------------
st.sidebar.image(str(HERE / "logo.png"), width=120)
st.sidebar.title("Website features")

inputs = {
    "google_index": st.sidebar.selectbox(
        "Google index", [0, 1], format_func=lambda x: "Indexed" if x == 0 else "Not indexed"),
    "dns_record": st.sidebar.selectbox(
        "DNS record", [0, 1], format_func=lambda x: "Found" if x == 0 else "Not found"),
    "statistical_report": st.sidebar.selectbox(
        "In phishing statistics report", [0, 1], format_func=lambda x: "No" if x == 0 else "Yes"),
    "popup_window": st.sidebar.selectbox(
        "Popup window on page", [0, 1], format_func=lambda x: "No" if x == 0 else "Yes"),
    "domain_age": st.sidebar.number_input("Domain age (days, -1 = unknown)", min_value=-1, value=3000),
    "domain_registration_length": st.sidebar.number_input(
        "Days until domain expires", min_value=0, value=365),
    "ratio_intHyperlinks": st.sidebar.slider("Internal links ratio", 0.0, 1.0, 0.8, 0.01),
    "longest_word_host": st.sidebar.number_input("Longest word in hostname (letters)", min_value=0, value=8),
    "avg_word_path": st.sidebar.number_input("Average word length in URL path", min_value=0.0, value=5.0),
    "nb_space": st.sidebar.number_input("Number of spaces in URL", min_value=0, value=0),
}
predict = st.sidebar.button("Predict", type="primary")

# ---------------- Main page ----------------
st.title("🛡️ Phishing Website Detector")
st.write("Enter the website's features in the sidebar, then click **Predict**.")

if predict:
    row = pd.DataFrame([inputs])[features]
    proba = float(model.predict_proba(row)[0][1])

    if proba >= 0.5:
        st.image(str(HERE / "phishing.png"), width=200)
        st.error(f"⚠️ Phishing website  ({proba:.0%} probability)")
    else:
        st.image(str(HERE / "safe.png"), width=200)
        st.success(f"✅ Legitimate website  ({1 - proba:.0%} probability)")
