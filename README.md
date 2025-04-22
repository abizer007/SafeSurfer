# 🌐 SafeSurfer: AI-Powered Web Safety Chrome Extension

> ⚠️ **Under Active Development** | 🛡️ Real-time Website Scanning | 🧠 Hybrid AI Detection | 📊 MongoDB Logging

---

## 🚀 Overview

**SafeSurfer** is a smart browser security companion that **analyzes every website you visit in real-time**, determines if it's safe or malicious, and alerts you **instantly** — all using a combination of AI models, domain intelligence, and user feedback.

---

## 🧠 Features

- ✅ **Real-Time URL Scanning** as you browse
- ⚡ **XGBoost + Deep Learning Hybrid Model** for phishing/malicious URL detection
- 🔐 **Post-check Rules** for trusted or suspicious domains
- 🧩 **Chrome Extension Integration**
- 📦 **Flask API Backend** for ML inference
- ☁️ **MongoDB Logging** of visited URLs & verdicts
- 📈 Future-ready for feedback-based retraining and dashboard integration

---

## 🧩 System Architecture

```
[Chrome Extension] → [Flask API] → [ML Models] → [MongoDB Storage]
         ↑               ↓
     Real-time alerts   Logs & Feedback
```

---

## ⚙️ Current Stack

| Layer        | Tech                            |
|-------------|----------------------------------|
| Frontend     | HTML/CSS/JS (Chrome extension)   |
| Backend API | Flask (Python)                   |
| ML Models   | XGBoost + TensorFlow              |
| Storage     | MongoDB (Localhost)              |
| UI          | Extension Popup + Badge Alerts    |

---

## 🔄 Flow

1. User visits a site
2. Chrome Extension captures URL
3. Sends URL to local Flask API (`http://127.0.0.1:5001/predict`)
4. Flask API:
   - Preprocesses URL (cleans domain, removes query)
   - Runs XGBoost + Deep Learning predictions
   - Applies rule-based overrides (e.g. whitelist)
   - Saves verdict to MongoDB
5. Verdict is shown in popup

---

## 🛠️ To Run Locally

1. Clone this repo
2. Start MongoDB
3. Train or load models (`train_url_model.py`, `phase_2-model.py`)
4. Run the API server:
   ```bash
   python url_scanner_api.py
   ```
5. Load the extension from `/SafeSurfer_Chrome_Extension` in Chrome (Developer Mode)
6. Visit websites and check the extension popup verdict

---

## 🧪 Dev Notes

- This is a **development-phase project** and accuracy may vary
- Model is currently trained on basic phishing and top-1M domains — needs fine-tuning for complex real-world traffic
- Feedback logging is enabled for future retraining

---

## 📌 Coming Soon

- 🌍 Web dashboard for browsing history analytics
- ✍️ User feedback on verdicts (used for active retraining)
- 📈 Improved model with feature engineering and full URL handling
- 🔒 OAuth-secured access and user-based dashboards

---

## 🤝 Contributors

Made with 💙 by [@abizer007](#) and [@aliasgarsogiawala](#)

---

