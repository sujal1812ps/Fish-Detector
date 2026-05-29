# PhishDetector: Phishing URL Detection & Prevention System

PhishDetector is an advanced web application designed to identify and classify phishing URLs using a hybrid approach that combines Machine Learning classification with real-time Security API threat intelligence.

![Phishing Detector Banner](https://github.com/asrith-reddy/Phishing-detector/assets/76733972/da226de9-dfe6-4f0c-a8bc-b92d4cc08e53)

---

## 🌟 Key Features

1. **Hybrid Threat Detection**:
   - **Machine Learning**: Predicts phishing probability using a pre-trained **Gradient Boosting Classifier** (`newmodel.pkl`) based on 30 distinct content, domain, and HTML-based features.
   - **Threat Intelligence**: Integrates with the **VirusTotal API (v3)** to check URLs against over 70 security vendor engines dynamically.
2. **Robust URL Validation**:
   - Performs a quick DNS resolving check using socket lookup before processing to verify if the domain actively exists.
3. **Advanced Redirection & Shortlink Inspector**:
   - Analyzes URLs for shortening services (like `bit.ly`, `tinyurl.com`, `t.co`, etc.) and alerts users with conditional redirect actions.
4. **Optimized Local Caching**:
   - Implements a local caching mechanism (`cache.json`) to store scan results, minimizing redundant external API queries and accelerating repeat scans.
5. **Interactive Security Center**:
   - Dynamic user dashboard with vendor detection reports, educational FAQs, and direct links to Google Safe Browsing and Phishing quizzes.
   - Downloadable guide: *Phishing Website Identification PDF*.

---

## 🛠️ Technologies & Libraries Used

* **Backend Framework**: Flask (Python)
* **Production Web Server**: Gunicorn
* **Machine Learning & Data Science**:
  - Scikit-learn
  - NumPy
  - Pandas
  - BeautifulSoup4 (for DOM parsing)
  - Python-whois (for WHOIS registry data extraction)
* **Frontend**: Bootstrap 4, Boxicons, AOS (Animate on Scroll), jQuery

---

## 📂 Project Structure

```text
├── DataFiles/               # Datasets for model training and URL reference lists
├── static/                  # Static assets (CSS, JS, images, downloadable PDF guide)
├── templates/               # Flask Jinja2 templates (index.html, usecases.html)
├── app.py                   # Main Flask backend application script
├── feature.py               # FeatureExtraction module extracting 30 features from URLs
├── convert.py               # Utility to check shortlinks and handle redirection logic
├── newmodel.pkl             # Serialized Gradient Boosting Classifier model
├── requirements.txt         # Package dependencies
├── Procfile                 # Production WSGI server config (for Gunicorn deployment)
├── cache.json               # Local scan results cache
└── Phishingproject.ipynb    # Jupyter Notebook containing model training and evaluation
```

---

## 🧠 Machine Learning Performance

The underlying model is trained on a comprehensive phishing dataset. Multiple models were compared during development (refer to `Phishingproject.ipynb` for complete implementation details):

| Model | Accuracy | F1 Score | Recall | Precision |
| :--- | :---: | :---: | :---: | :---: |
| **CatBoost Classifier** | **0.951** | **0.950** | **0.997** | **0.997** |
| Random Forest | 0.945 | 0.951 | 0.995 | 0.998 |
| Gradient Boosting Classifier (Used in App) | 0.941 | 0.940 | 0.991 | 0.991 |
| Decision Tree | 0.933 | 0.940 | 1.000 | 1.000 |
| Multi-layer Perceptron | 0.883 | 0.883 | 0.880 | 0.880 |
| Logistic Regression | 0.880 | 0.893 | 0.900 | 0.890 |
| Naive Bayes Classifier | 0.818 | 0.814 | 0.711 | 0.950 |
| K-Nearest Neighbors | 0.630 | 0.655 | 1.000 | 1.000 |

*Key Takeaways:*
- The **CatBoost Classifier** achieved the highest accuracy of **95.1%** during model evaluation in the Jupyter notebook.
- The **Gradient Boosting Classifier** (94.1% accuracy) is loaded in production via `newmodel.pkl` for real-time predictions.
- Important features used to identify phishing attempts include `HTTPS`, `AnchorURL` percentage, and `WebsiteTraffic` patterns.

---

## 🚀 Installation & Setup

Follow these steps to run PhishDetector locally:

### 1. Clone the Repository
```bash
git clone https://github.com/sujal1812ps/Fish-Detector.git
cd Fish-Detector
```

### 2. Set Up a Virtual Environment
```bash
# Create a virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure VirusTotal API (Optional but Recommended)
Open `app.py` and configure your API key for VirusTotal lookup (v3):
```python
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

### 5. Run the Application
```bash
python app.py
```
Open your browser and navigate to `http://127.0.0.1:5000` to start scanning URLs.

---

## 🚢 Deployment

The project is production-ready and includes a `Procfile` configured for deployment on cloud platforms (e.g., Heroku, Render, AWS Elastic Beanstalk):
```yaml
web: gunicorn app:app
```
