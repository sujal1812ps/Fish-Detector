#importing required libraries
import json
import os
from unittest import result
from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
import requests
import time
from convert import convertion
warnings.filterwarnings('ignore')
from feature import FeatureExtraction
from urllib.parse import urlparse

file = open("newmodel.pkl","rb")
gbc = pickle.load(file)
file.close()

app = Flask(__name__)

def load_cache():
    if not os.path.exists("cache.json"):
        return {}
    with open("cache.json", "r") as f:
        return json.load(f)
    
#from flask import Flask, render_template, request
import requests

def check_website_exists(url):
    import socket
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        if not domain or "." not in domain:
            return False

        domain = domain.split(":")[0]

        socket.gethostbyname(domain)

        return True

    except:
        return False

API_KEY = "2ba24872ec460adbdb65a0f834fc0d6d739dfe1f052e9f4c8f6d9b2375f526a5"

def check_virustotal(url):
    try:
        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": API_KEY}
        data = {"url": url}

        # Submit URL
        response = requests.post(submit_url, headers=headers, data=data)
        result = response.json()

        analysis_id = result['data']['id']

        # Get report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        time.sleep(15)

        report = requests.get(report_url, headers=headers)
        report_data = report.json()

        stats = report_data['data']['attributes']['stats']
        malicious = stats['malicious']

        # 🔥 Extract vendor results
        results = report_data['data']['attributes']['results']

        vendors = []

        for vendor, value in results.items():
            category = value.get("category")

            # only show important ones
            if category in ["malicious", "suspicious"]:
                vendors.append({
                    "vendor": vendor,
                    "result": value.get("result"),
                    "category": category
                })

        # Limit to top 10 vendors
        vendors = vendors[:10]

        return (malicious > 0), vendors

    except Exception as e:
        print("VT Error:", e)
        return False, []
@app.route("/")
def home():
    return render_template("index.html")

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if request.method == "POST":

        url = request.form["name"].strip()

        cache = load_cache()
        normalized_url = url.strip().lower()

        if normalized_url in cache:
            cached = cache[normalized_url]

            return render_template(
                "index.html",
                name=cached["name"],
                url=url,
                button_text=cached["button_text"],
                is_safe=cached["is_safe"],
                vendors=cached.get("vendors", [])   
            )

            # ✅ STEP 0: Normalize URL
        if not url.startswith("http"):
                url = "http://" + url

            # ✅ STEP 1: Check existence
        if not check_website_exists(url):
                return render_template(
                    "index.html",
                    name="❌ Website does not exist",
                    confidence=0
                )

        # ✅ STEP 2: Feature extraction
        parsed = urlparse(url)
        clean_url = parsed.netloc + parsed.path

        obj = FeatureExtraction(clean_url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        # ✅ STEP 3: ML prediction
        model_pred = gbc.predict(x)[0]

        # ✅ STEP 4: VirusTotal check
        is_phishing_api, vendors = check_virustotal(url)

        # ✅ STEP 5: Final decision
        if is_phishing_api or model_pred == -1:
            y_pred = -1
        else:
            y_pred = 1

        # ✅ STEP 6: Confidence
        prob = gbc.predict_proba(x)[0]

        phishing_prob = prob[0]
        safe_prob = prob[1]

        # ✅ STEP 7: Safe output handling
        try:
            result = convertion(url, int(y_pred))

            url_display = result[0]
            status = result[1]
            button_text = result[2]
            flag = result[3]

        except:
            url_display = url
            status = "Safe" if y_pred == 1 else "Phishing"
            button_text = "Continue"
            flag = '1' if y_pred == 1 else '0'

        # ✅ STEP 8: Final message
        if y_pred == 1:
            name = "✅ Safe Website"
        else:
            name = "⚠️ Phishing Website"

        # ✅ STEP 13: Store in cache
        cache[normalized_url] = {
            "name": name,
            "is_safe": (flag == '1'),
            "button_text": button_text,
            "vendors": vendors  # You can also store vendor info if needed
        }
        save_cache(cache)

        return render_template(
            "index.html",
            name=name,
            url=url_display,
            button_text=button_text,
            is_safe=(flag == '1'),
            vendors=vendors  # Pass vendor info to template if needed
        )

def save_cache(cache):
    with open("cache.json", "w") as f:
        json.dump(cache, f, indent=4)
        
@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    return render_template('usecases.html')
if __name__ == "__main__":
    app.run(debug=True)
