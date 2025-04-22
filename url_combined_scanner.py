
import joblib
import pickle
import pandas as pd
import numpy as np
import re
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# 🧠 MUST BE DEFINED BEFORE joblib.load
def extract_custom_features(urls):
    features = pd.DataFrame()
    features['url_length'] = urls.apply(len)
    features['num_dots'] = urls.apply(lambda x: x.count('.'))
    features['has_https'] = urls.apply(lambda x: int('https' in x.lower()))
    features['has_ip'] = urls.apply(lambda x: int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', x))))
    features['has_at'] = urls.apply(lambda x: int('@' in x))
    features['num_digits'] = urls.apply(lambda x: sum(c.isdigit() for c in x))
    keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'confirm', 'signin']
    features['has_suspicious_word'] = urls.apply(lambda x: int(any(k in x.lower() for k in keywords)))
    return features

# === Load Models ===
xgb_model = joblib.load("hybrid_url_detector.pkl")
dl_model = load_model("url_deep_model.h5")
with open("url_tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

# === Constants ===
SUSPICIOUS_TLDS = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf']
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'verify', 'update', 'account', 'bank', 'paypal']
TRUSTED_DOMAINS = ['google.com', 'youtube.com', 'facebook.com', 'microsoft.com']

def is_flagged_suspicious(url):
    url = url.lower()
    if any(url.endswith(tld) for tld in SUSPICIOUS_TLDS): return True
    if 'http://' in url: return True
    if any(word in url for word in SUSPICIOUS_KEYWORDS): return True
    return False

def is_trusted_domain(url):
    return any(domain in url for domain in TRUSTED_DOMAINS)

# === Combined Prediction ===
def predict_url_combined(url):
    xgb_pred = xgb_model.predict(pd.Series([url]))[0]
    xgb_conf = xgb_model.predict_proba(pd.Series([url]))[0][1]  # 1 = bad class prob

    seq = tokenizer.texts_to_sequences([url])
    padded = pad_sequences(seq, maxlen=200)
    dl_conf = dl_model.predict(padded)[0][0]  # 1 = bad
    dl_pred = dl_conf > 0.5

    avg_conf = (xgb_conf + dl_conf) / 2

    # Override if post-rules
    if is_trusted_domain(url):
        return "✅ Good (trusted domain)", "Good", max(xgb_conf, dl_conf)*100
    if is_flagged_suspicious(url) and avg_conf < 0.5:
        return "❌ Bad (post-check override)", "Bad", avg_conf*100

    return ("❌ Bad" if avg_conf > 0.5 else "✅ Good"), ("Bad" if avg_conf > 0.5 else "Good"), avg_conf * 100

# === CLI with Feedback Logging ===
print("[INFO] Real-time URL Classifier with Feedback Logging")

while True:
    test_url = input("\nEnter a URL to scan (or type 'exit'): ").strip()
    if test_url.lower() == "exit":
        print("[INFO] Exiting scanner.")
        break

    label, pred_class, confidence = predict_url_combined(test_url)
    print(f"{label} (Confidence: {confidence:.2f}%)")

    feedback = input("Was this prediction correct? (y/n): ").strip().lower()
    if feedback in ['y', 'n']:
        with open("url_feedback.csv", "a") as f:
            f.write(f"{test_url},{pred_class},{feedback}\n")
        print("[INFO] Feedback logged.")
    else:
        print("[INFO] Feedback skipped.")
