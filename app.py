        "Redirection": int(url.count("//") > 1),
        "https_Domain": int("https" in hostname),
        "TinyURL": int(any(x in hostname for x in ["bit.ly", "tinyurl", "t.co", "goo.gl"])),
        "Prefix/Suffix": int("-" in hostname),
    }
    # Missing feature values are set to 0. Confirm this matches your training notebook.
    return pd.DataFrame([[values.get(name, 0) for name in feature_names]], columns=feature_names)

url = st.text_input("Website URL", placeholder="https://example.com")

examples = {
    "Choose an example": "",
    "Likely legitimate — https://www.wikipedia.org": "https://www.wikipedia.org",
    "Likely legitimate — https://www.google.com": "https://www.google.com",
    "Likely legitimate — https://www.microsoft.com": "https://www.microsoft.com",
    "Likely legitimate — https://www.amazon.com": "https://www.amazon.com",
    "Suspicious-style example — http://192.168.1.1/login": "http://192.168.1.1/login",
    "Suspicious-style example — http://secure-login-example.com": "http://secure-login-example.com",
    "Suspicious-style example — http://verify-account-example.test": "http://verify-account-example.test",
    "Suspicious-style example — http://login-example.test/update": "http://login-example.test/update",
}

selected_example = st.selectbox("⭐ Try an example URL", list(examples.keys()))
st.caption("Examples are for demonstration only; the model decides the result and may not classify them as expected.")

if selected_example != "Choose an example" and not url:
    url = examples[selected_example]

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


