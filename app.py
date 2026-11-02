import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import joblib
import pandas as pd
import requests
import streamlit as st
import tldextract
import whois
from bs4 import BeautifulSoup

HERE = Path(__file__).parent
MODEL_FILE = HERE / "phishing_model.pkl"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"}
extract = tldextract.TLDExtract(suffix_list_urls=())  # works offline, no download

EXAMPLES = [
    "https://www.wikipedia.org",
    "https://github.com",
    "https://www.python.org",
    "http://paypal-secure-login.verify-account-update.xyz/signin",
    "http://amazon.account-verify-now.top/login/confirm",
]

st.set_page_config(page_title="Phishing Website Detector", page_icon="🛡️")


# ---------------- Model (with a clear message if the file is broken) ----------------
if not MODEL_FILE.exists() or MODEL_FILE.stat().st_size < 1_000_000:
    size = MODEL_FILE.stat().st_size if MODEL_FILE.exists() else 0
    st.error(
        f"phishing_model.pkl is missing or incomplete ({size:,} bytes, expected about 11,538,872). "
        "Re-upload the original file to your GitHub repo."
    )
    st.stop()


@st.cache_resource
def load_model():
    data = joblib.load(MODEL_FILE)
    return data["model"], data["features"]


model, FEATURES = load_model()


# ---------------- Feature extraction ----------------
def get_features(url):
    host = urlparse(url).hostname or ""
    warnings = []
    split = lambda s: [w for w in re.split(r"[-./?=@&%:_]", s) if w]
    host_w, path_w = split(host), split(urlparse(url).path)
    f = {
        "nb_space": url.count(" "),
        "longest_word_host": max(map(len, host_w), default=0),
        "avg_word_path": sum(map(len, path_w)) / len(path_w) if path_w else 0,
        "statistical_report": 0,
    }
    try:  # DNS: 0 = found, 1 = not found
        socket.gethostbyname(host)
        f["dns_record"] = 0
    except OSError:
        f["dns_record"] = 1
    try:  # WHOIS: domain age and days until expiry
        w = whois.whois(extract(host).registered_domain or host)
        c, e = [x[0] if isinstance(x, list) else x for x in (w.creation_date, w.expiration_date)]
        now = datetime.now(timezone.utc)
        f["domain_age"] = (now - c.replace(tzinfo=timezone.utc)).days
        f["domain_registration_length"] = max((e.replace(tzinfo=timezone.utc) - now).days, 0)
    except Exception:
        f["domain_age"], f["domain_registration_length"] = -1, 0
        warnings.append("WHOIS info not available for this domain.")
    try:  # Google index: 0 = indexed, 1 = not indexed
        r = requests.get("https://www.google.com/search", params={"q": f"site:{url}"},
                         headers=HEADERS, timeout=8)
        f["google_index"] = int("did not match any documents" in r.text.lower())
    except requests.RequestException:
        f["google_index"] = 0
        warnings.append("Could not check Google index (assumed indexed).")
    try:  # Page content: internal link ratio and popups
        r = requests.get(url, headers=HEADERS, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [t.get("href") or t.get("src") for t in soup.find_all(["a", "link", "img", "script"])]
        links = [l for l in links if l and not l.startswith(("#", "javascript:", "mailto:"))]
        internal = sum(urlparse(urljoin(url, l)).hostname == host for l in links)
        f["ratio_intHyperlinks"] = internal / len(links) if links else 0
        f["popup_window"] = int(bool(re.search(r"prompt\(|window\.open\(", r.text)))
    except requests.RequestException:
        f["ratio_intHyperlinks"], f["popup_window"] = 0, 0
        warnings.append("Could not load the page.")
    return f, warnings


# ---------------- Sidebar ----------------
st.sidebar.image(str(HERE / "logo.png"), width=120)
st.sidebar.title("About")
st.sidebar.write(
    "This app checks a website with a Random Forest model trained on the "
    "web page phishing detection dataset."
)
st.sidebar.subheader("Features checked")
st.sidebar.markdown(
    "- Google index\n- Domain age\n- Domain expiry\n- DNS record\n- Internal links ratio\n"
    "- Hostname / path word lengths\n- Popup window\n- Spaces in URL\n- Phishing statistics"
)
st.sidebar.caption("Educational project. Don't rely on it alone for security decisions.")


# ---------------- Main page ----------------
def use_example():
    if st.session_state.example != "Choose an example":
        st.session_state.url = st.session_state.example


st.title("🛡️ Phishing Website Detector")
st.text_input("Website URL", key="url", placeholder="https://example.com")
st.selectbox("⭐ Try an example URL", ["Choose an example"] + EXAMPLES,
             key="example", on_change=use_example)

if st.button("Analyze", type="primary"):
    url = st.session_state.url.strip()
    if not url:
        st.warning("Please enter a URL first.")
        st.stop()
    if "://" not in url:
        url = "http://" + url
    with st.spinner("Checking the website..."):
        feats, warnings = get_features(url)
    row = pd.DataFrame([feats])[FEATURES]
    proba = float(model.predict_proba(row)[0][1])

    if proba >= 0.5:
        st.image(str(HERE / "phishing.png"), width=200)
        st.error(f"⚠️ Phishing website  ({proba:.0%} probability)")
    else:
        st.image(str(HERE / "safe.png"), width=200)
        st.success(f"✅ Legitimate website  ({1 - proba:.0%} probability)")
    for w in warnings:
        st.warning(w)
    with st.expander("Show feature values"):
        st.dataframe(row.T.astype(str).rename(columns={0: "value"}))
