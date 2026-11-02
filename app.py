    )
    st.info("For learning/demo use only. Do not rely on this result alone to decide whether a website is safe.")

# -------------------- Main header --------------------
st.markdown("""
<div class="hero">
    <h1>🛡️ PhishGuard</h1>
    <p>A clean, interactive phishing URL screening dashboard</p>
</div>
""", unsafe_allow_html=True)

m1, m2, m3 = st.columns(3)
with m1:
    st.markdown('<div class="info-card"><h3>🔎 URL Scan</h3><div class="small-muted">Check a URL using your trained ML model.</div></div>', unsafe_allow_html=True)
with m2:
    st.markdown('<div class="info-card"><h3>📊 Model Result</h3><div class="small-muted">See the predicted class and available confidence.</div></div>', unsafe_allow_html=True)
with m3:
    st.markdown('<div class="info-card"><h3>🧪 Demo Friendly</h3><div class="small-muted">Try a URL or use the example input.</div></div>', unsafe_allow_html=True)

st.write("")
left, right = st.columns([1.45, 1])

with left:
    st.subheader("🔗 Check a website URL")
    example = st.selectbox(
        "Choose an example (optional)",
        ["— Choose an example —", "https://www.wikipedia.org", "http://example.com", "https://accounts.google.com"],
    )
    default_url = "" if example == "— Choose an example —" else example
    url = st.text_input(
        "Website URL",
        value=default_url,
        placeholder="e.g. https://www.example.com",
        help="Enter the full URL, including the domain name.",
    )
    scan = st.button("🔍 Check URL", type="primary", use_container_width=True)

with right:
    st.subheader("💡 URL tips")
    st.markdown("""
    <div class="info-card">
    <b>Before opening a link</b><br><br>
    • Check the domain spelling.<br>
    • Be careful with unexpected login/payment links.<br>
    • HTTPS alone does not guarantee a website is legitimate.<br>
    • Never enter passwords on a page you do not trust.
    </div>
    """, unsafe_allow_html=True)

if scan:
    if not url.strip():
        st.warning("Please enter a URL first.")
    elif "." not in urlparse(url if "://" in url else "http://" + url).netloc:
        st.warning("Please enter a valid-looking domain, such as https://example.com.")
    elif not os.path.exists(MODEL_PATH):
        st.error(f"Could not find `{MODEL_PATH}`. Upload your trained model to the same GitHub repository as `app.py`.")
    else:
        try:
            with st.spinner("Analyzing URL with your model..."):
                saved = load_model(MODEL_PATH)
                if isinstance(saved, dict) and "model" in saved:
                    model = saved["model"]
                    features = saved.get("features", [])
                else:
                    model = saved
                    features = list(getattr(model, "feature_names_in_", []))

                if not features:
                    st.error(
                        "Feature names were not found in the saved model. Save the model together "
                        "with the exact training feature names, then try again."
                    )
                else:
                    X = prepare_input(url.strip(), features)
                    pred = model.predict(X)[0]
                    label = normalize_prediction(pred)

                    st.markdown("### Scan result")
                    if label == "Phishing / Suspicious":
                        st.markdown(
                            '<div class="result-risk"><h3>⚠️ Phishing / Suspicious</h3>'
                            '<p>The model classified this URL as suspicious. Avoid entering sensitive information.</p></div>',
                            unsafe_allow_html=True,
                        )
                    elif label == "Likely Legitimate":
                        st.markdown(
                            '<div class="result-safe"><h3>✅ Likely Legitimate</h3>'
                            '<p>The model did not flag this URL as phishing. This is not a guarantee of safety.</p></div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            f'<div class="result-unknown"><h3>Prediction: {label}</h3>'
                            '<p>Check your dataset label encoding to ensure the result is interpreted correctly.</p></div>',
                            unsafe_allow_html=True,
                        )

                    if hasattr(model, "predict_proba"):
                        try:
                            probabilities = model.predict_proba(X)[0]
                            confidence = float(max(probabilities)) * 100
                            st.metric("Model confidence (for predicted class)", f"{confidence:.1f}%")
                            st.caption("Confidence is not a guarantee that the prediction is correct.")
                        except Exception:
                            pass

                    with st.expander("Show technical details"):
                        st.write("Input URL:", url.strip())
                        st.write("Features passed to model:", features)
                        st.write("Raw model output:", str(pred))
                        st.dataframe(X, use_container_width=True)
        except Exception as exc:
            st.error("The model could not process this input.")
            st.code(f"{type(exc).__name__}: {exc}")
            st.info(
                "The most common cause is that the input features do not exactly match "
                "the features used to train the model. The feature extraction code must match your notebook."
            )

st.divider()
st.caption("PhishGuard • Educational project prototype • Always verify suspicious links independently.")





