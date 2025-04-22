
import pandas as pd
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.preprocessing import FunctionTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import numpy as np

# === Feature Engineering Functions ===

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

# === Load Datasets ===

print("[INFO] Loading datasets...")

# 1. phishing_site_urls.csv
phish1 = pd.read_csv("phishing_site_urls.csv")
phish1 = phish1[phish1['Label'].str.lower() == 'bad']
phish1 = phish1[['URL']].rename(columns={'URL': 'url'})
phish1['label'] = 1

# 2. malicious_phish.csv
phish2 = pd.read_csv("malicious_phish.csv")
phish2_mal = phish2[phish2['type'].isin(['phishing', 'defacement', 'malware'])]
phish2_good = phish2[phish2['type'] == 'benign']
phish2_mal = phish2_mal[['url']]; phish2_mal['label'] = 1
phish2_good = phish2_good[['url']]; phish2_good['label'] = 0

# 3. top-1m.csv
top1m = pd.read_csv("top-1m.csv", header=None, names=["rank", "domain"])
top1m['url'] = 'http://' + top1m['domain']
top1m = top1m[['url']]
top1m['label'] = 0

# Combine and shuffle
df = pd.concat([phish1, phish2_mal, phish2_good, top1m], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"[INFO] Final dataset shape: {df.shape}")

# === Split Data ===

X = df['url']
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

# === Build Hybrid Pipeline ===

custom_feature_pipe = Pipeline([
    ('extract', FunctionTransformer(func=extract_custom_features, validate=False))
])

text_feature_pipe = Pipeline([
    ('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=2000))
])

preprocessor = FeatureUnion([
    ('custom_features', custom_feature_pipe),
    ('text_features', text_feature_pipe)
])

model = Pipeline([
    ('features', preprocessor),
    ('xgb', XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, use_label_encoder=False, eval_metric='logloss'))
])

# === Train ===

print("[INFO] Training hybrid model...")
model.fit(X_train, y_train)

# === Evaluate ===

y_pred = model.predict(X_test)
print("[INFO] Model Evaluation:")
print(classification_report(y_test, y_pred, target_names=["Good", "Bad"]))

# === Save Model ===

joblib.dump(model, "hybrid_url_detector.pkl")
print("[INFO] Model saved as hybrid_url_detector.pkl")

# === CLI Predictor ===

SUSPICIOUS_TLDS = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf']
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'verify', 'update', 'account', 'bank', 'paypal']
TRUSTED_DOMAINS = ['google.com', 'youtube.com', 'facebook.com', 'microsoft.com']

def is_flagged_suspicious(url):
    url = url.lower()
    if any(url.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return True
    if 'http://' in url:
        return True
    if any(keyword in url for keyword in SUSPICIOUS_KEYWORDS):
        return True
    return False

def is_trusted_domain(url):
    return any(domain in url for domain in TRUSTED_DOMAINS)

print("\n[INFO] Ready to classify URLs securely.")

while True:
    test_url = input("\nEnter a URL to check (or type 'exit'): ").strip()
    if test_url.lower() == "exit":
        print("[INFO] Exiting CLI.")
        break

    # Core ML prediction
    pred_input = pd.Series([test_url])
    result = model.predict(pred_input)[0]
    proba = model.predict_proba(pred_input)[0]
    confidence = max(proba) * 100

    # Apply post-checks
    if is_trusted_domain(test_url):
        label = "✅ Good (trusted domain)"
    elif is_flagged_suspicious(test_url) and result == 0:
        label = "❌ Bad (overruled by post-checks)"
    else:
        label = "✅ Good" if result == 0 else "❌ Bad"

    print(f"{label} (Confidence: {confidence:.2f}%)")
