from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
import joblib
import pickle
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from datetime import datetime
import re
from urllib.parse import urlparse

app = Flask(__name__)

# === MongoDB Configuration ===
app.config["MONGO_URI"] = "mongodb://localhost:27017/urlscanner"
mongo = PyMongo(app)

# === URL Cleaner ===
def clean_url(raw_url):
    parsed = urlparse(raw_url)
    netloc = parsed.netloc.lower().replace("www.", "")
    path = parsed.path.split("/")[1] if parsed.path.count("/") > 1 else ""
    return f"{netloc}/{path}" if path else netloc

# === Feature Extractor ===
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

SUSPICIOUS_TLDS = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf']
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'verify', 'update', 'account', 'bank', 'paypal']
TRUSTED_DOMAINS = ['google.com', 'youtube.com', 'facebook.com', 'microsoft.com']

def is_flagged_suspicious(url):
    url = url.lower()
    return any(url.endswith(tld) for tld in SUSPICIOUS_TLDS) or 'http://' in url or any(word in url for word in SUSPICIOUS_KEYWORDS)

def is_trusted_domain(url):
    return any(domain in url for domain in TRUSTED_DOMAINS)

def predict_url_combined(url):
    xgb_conf = xgb_model.predict_proba(pd.Series([url]))[0][1]
    seq = tokenizer.texts_to_sequences([url])
    padded = pad_sequences(seq, maxlen=200)
    dl_conf = dl_model.predict(padded)[0][0]
    avg_conf = (xgb_conf + dl_conf) / 2

    if is_trusted_domain(url):
        return "Good", "trusted", float(max(xgb_conf, dl_conf) * 100)
    if is_flagged_suspicious(url) and avg_conf < 0.5:
        return "Bad", "post-check override", float(avg_conf * 100)

    return ("Bad" if avg_conf > 0.5 else "Good"), "ml", float(avg_conf * 100)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    raw_url = data.get("url", "")
    url = clean_url(raw_url)
    user_id = data.get("user_id", "anonymous")

    verdict, reason, confidence = predict_url_combined(url)

    # Save to MongoDB
    log_entry = {
        "url": raw_url,  # keep original for reference
        "user_id": user_id,
        "verdict": verdict,
        "reason": reason,
        "confidence": float(confidence),
        "timestamp": datetime.utcnow()
    }
    mongo.db.logs.insert_one(log_entry)

    return jsonify({
        "url": raw_url,
        "verdict": verdict,
        "reason": reason,
        "confidence": confidence
    })

if __name__ == "__main__":
    app.run(port=5001)
