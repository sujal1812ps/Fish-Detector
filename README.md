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
| **Gradient Boosting Classifier (Used)** | **0.974** | **0.977** | **0.994** | **0.986** |
| CatBoost Classifier | 0.972 | 0.975 | 0.994 | 0.989 |
| Multi-layer Perceptron | 0.969 | 0.973 | 0.995 | 0.981 |
| Random Forest | 0.967 | 0.971 | 0.993 | 0.990 |
| Support Vector Machine | 0.964 | 0.968 | 0.980 | 0.965 |
| Decision Tree | 0.960 | 0.964 | 0.991 | 0.993 |
| K-Nearest Neighbors | 0.956 | 0.961 | 0.991 | 0.989 |
| Logistic Regression | 0.934 | 0.941 | 0.943 | 0.927 |
| Naive Bayes Classifier | 0.605 | 0.454 | 0.292 | 0.997 |

*Key Takeaways:*
- The **Gradient Boosting Classifier** yields the highest accuracy of **97.4%** and is selected for active predictions in production.
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
