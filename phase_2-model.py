import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from tensorflow.keras.preprocessing.text import Tokenizer
from keras.utils import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout

# === Load Data ===
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
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# === Tokenization ===
urls = df['url'].astype(str).values
labels = df['label'].values

tokenizer = Tokenizer(char_level=True, lower=True)
tokenizer.fit_on_texts(urls)
sequences = tokenizer.texts_to_sequences(urls)
maxlen = 200
X = pad_sequences(sequences, maxlen=maxlen)
y = np.array(labels)

# === Split ===
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)

# === Model ===
vocab_size = len(tokenizer.word_index) + 1

model = Sequential([
    Embedding(input_dim=vocab_size, output_dim=32, input_length=maxlen),
    Conv1D(64, 5, activation='relu'),
    GlobalMaxPooling1D(),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dropout(0.3),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.summary()

# === Train ===
model.fit(X_train, y_train, validation_split=0.1, batch_size=128, epochs=5)

# === Evaluate ===
y_pred = (model.predict(X_test) > 0.5).astype("int32")
print(classification_report(y_test, y_pred))

# === Save Model + Tokenizer ===
model.save("url_deep_model.h5")
import pickle
with open("url_tokenizer.pkl", "wb") as f:
    pickle.dump(tokenizer, f)
