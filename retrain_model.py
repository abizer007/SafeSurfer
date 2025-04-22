
import pandas as pd
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.preprocessing import FunctionTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier
from sklearn.pipeline import Pipeline
from datetime import datetime
import os

# === Define custom feature extraction ===
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

# === Load original training data ===
def load_original_data():
    phish1 = pd.read_csv("phishing_site_urls.csv")
    phish1 = phish1[phish1['Label'].str.lower() == 'bad']
    phish1 = phish1[['URL']].rename(columns={'URL': 'url'})
    phish1['label'] = 1

    phish2 = pd.read_csv("malicious_phish.csv")
    phish2_mal = phish2[phish2['type'].isin(['phishing', 'defacement', 'malware'])][['url']]
    phish2_mal['label'] = 1
    phish2_good = phish2[phish2['type'] == 'benign'][['url']]
    phish2_good['label'] = 0

    top1m = pd.read_csv("top-1m.csv", header=None, names=['rank', 'domain'])
    top1m['url'] = 'http://' + top1m['domain']
    top1m = top1m[['url']]
    top1m['label'] = 0

    df = pd.concat([phish1, phish2_mal, phish2_good, top1m], ignore_index=True)
    return df

# === Load feedback data if available ===
def load_feedback_data():
    if os.path.exists("url_feedback.csv"):
        feedback_df = pd.read_csv("url_feedback.csv", names=['url', 'predicted', 'correct'])
        feedback_df['correct'] = feedback_df['correct'].str.lower().map({'y': 1, 'n': 0})
        feedback_df = feedback_df[['url', 'correct']].rename(columns={'correct': 'label'})
        return feedback_df
    return pd.DataFrame(columns=['url', 'label'])

# === Train new model ===
def train_and_save_model(df):
    df = df.dropna()
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    X = df['url']
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)

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
    model.fit(X_train, y_train)
    joblib.dump(model, "hybrid_url_detector.pkl")

    print("[INFO] Model retrained and saved at hybrid_url_detector.pkl")
    with open("last_update.log", "w") as log:
        log.write(f"Last update: {datetime.now()}")
    return model

# === Main routine ===
if __name__ == "__main__":
    print("[INFO] Loading original + feedback data...")
    base_df = load_original_data()
    feedback_df = load_feedback_data()

    combined_df = pd.concat([base_df[['url', 'label']], feedback_df], ignore_index=True)
    print(f"[INFO] Total records used for training: {combined_df.shape[0]}")

    train_and_save_model(combined_df)
