
import re, socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import joblib, pandas as pd, requests, streamlit as st, tldextract, whois
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"}
extract = tldextract.TLDExtract(suffix_list_urls=())  # offline, no download
model_data = joblib.load("phishing_model.pkl")
model, FEATURES = model_data["model"], model_data["features"]


def get_features(url):
    host = urlparse(url).hostname or ""
    split = lambda s: [w for w in re.split(r"[-./?=@&%:_]", s) if w]
    host_w, path_w = split(host), split(urlparse(url).path)
    f = {
        "nb_space": url.count(" "),
        "longest_word_host": max(map(len, host_w), default=0),
        "avg_word_path": sum(map(len, path_w)) / len(path_w) if path_w else 0,
        "statistical_report": 0,
    }
    try:  # DNS: 0 = found, 1 = missing
        socket.gethostbyname(host); f["dns_record"] = 0
    except OSError:
        f["dns_record"] = 1
    try:  # WHOIS: domain age / days until expiry
        w = whois.whois(extract(host).registered_domain or host)
        c, e = [x[0] if isinstance(x, list) else x for x in (w.creation_date, w.expiration_date)]
        now = datetime.now(timezone.utc)
        f["domain_age"] = (now - c.replace(tzinfo=timezone.utc)).days
        f["domain_registration_length"] = max((e.replace(tzinfo=timezone.utc) - now).days, 0)
    except Exception:
        f["domain_age"], f["domain_registration_length"] = -1, 0
    try:  # Google index: 0 = indexed, 1 = not indexed
        r = requests.get("https://www.google.com/search", params={"q": f"site:{url}"}, headers=HEADERS, timeout=8)
        f["google_index"] = int("did not match any documents" in r.text.lower())
    except requests.RequestException:
        f["google_index"] = 0
    try:  # Page: internal-link ratio and popup
        r = requests.get(url, headers=HEADERS, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [t.get("href") or t.get("src") for t in soup.find_all(["a", "link", "img", "script"])]
        links = [l for l in links if l and not l.startswith(("#", "javascript:", "mailto:"))]
        internal = sum(urlparse(urljoin(url, l)).hostname == host for l in links)
        f["ratio_intHyperlinks"] = internal / len(links) if links else 0
        f["popup_window"] = int(bool(re.search(r"prompt\(|window\.open\(", r.text)))
    except requests.RequestException:
        f["ratio_intHyperlinks"], f["popup_window"] = 0, 0
    return f


st.title("🛡️ Phishing Website Detector")
url = st.text_input("URL to check", placeholder="https://example.com/login").strip()

if st.button("Analyze", type="primary") and url:
    if "://" not in url:
        url = "http://" + url
    with st.spinner("Checking..."):
        feats = get_features(url)
    row = pd.DataFrame([feats])[FEATURES]
    p = model.predict_proba(row)[0][1]
    (st.error if p >= 0.5 else st.success)(
        f"{'⚠️ Likely PHISHING' if p >= 0.5 else '✅ Likely LEGITIMATE'} ({p:.0%} phishing probability)"
    )
    st.dataframe(row.T.astype(str).rename(columns={0: "value"}))
