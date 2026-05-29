import re
import ipaddress
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import date
import whois

class FeatureExtraction:

    def __init__(self, url):
        self.url = url
        self.features = []
        self.domain = ""
        self.response = None
        self.soup = None
        self.urlparse = None
        self.whois_response = None

        # Clean URL parsing
        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        # Request page
        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            self.response = None
            self.soup = None

        # WHOIS
        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        # Feature list (keep count = 30)
        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.HttpsWeak(),   # FIXED HTTPS
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]

    # 1
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif len(self.url) <= 75:
            return 0
        return -1

    # 3
    def shortUrl(self):
        if re.search(r'bit\.ly|tinyurl|goo\.gl|ow\.ly', self.url):
            return -1
        return 1

    # 4
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5
    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6
    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    # 7
    def SubDomains(self):
        dots = self.url.count('.')
        if dots <= 2:
            return 1
        elif dots == 3:
            return 0
        return -1

    # 🔥 FIXED HTTPS (WEAK SIGNAL)
    def HttpsWeak(self):
        return 1 if "https" in self.url else 0

    # 9
    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            create = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(create, list): create = create[0]

            age = (exp.year - create.year) * 12
            return 1 if age >= 12 else -1
        except:
            return -1

    # 10
    def Favicon(self):
        if not self.soup:
            return -1
        for link in self.soup.find_all('link', href=True):
            if self.domain in link['href']:
                return 1
        return -1

    # 11
    def NonStdPort(self):
        return -1 if ":" in self.domain else 1

    # 12
    def HTTPSDomainURL(self):
        return -1 if "https" in self.domain else 1

    # 13
    def RequestURL(self):
        if not self.soup:
            return -1
        total = 0
        success = 0

        for tag in self.soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True):
            total += 1
            if self.domain in tag['src']:
                success += 1

        if total == 0:
            return 1

        percent = (success / total) * 100
        if percent < 22:
            return 1
        elif percent < 61:
            return 0
        return -1

    # 14
    def AnchorURL(self):
        if not self.soup:
            return -1

        total = 0
        unsafe = 0

        for a in self.soup.find_all('a', href=True):
            total += 1
            if "#" in a['href'] or "javascript" in a['href'].lower():
                unsafe += 1

        if total == 0:
            return 1

        percent = (unsafe / total) * 100
        if percent < 31:
            return 1
        elif percent < 67:
            return 0
        return -1

    # 15
    def LinksInScriptTags(self):
        return 1 if self.soup else -1

    # 16
    def ServerFormHandler(self):
        if not self.soup:
            return -1
        forms = self.soup.find_all('form', action=True)
        if len(forms) == 0:
            return 1
        for form in forms:
            if form['action'] == "" or "about:blank" in form['action']:
                return -1
        return 1

    # 17
    def InfoEmail(self):
        try:
            return -1 if re.search("mailto:", self.response.text) else 1
        except:
            return -1

    # 18
    def AbnormalURL(self):
        return -1

    # 19
    def WebsiteForwarding(self):
        try:
            return 1 if len(self.response.history) <= 1 else -1
        except:
            return -1

    # 20
    def StatusBarCust(self):
        return -1

    # 21
    def DisableRightClick(self):
        return -1

    # 22
    def UsingPopupWindow(self):
        return -1

    # 23
    def IframeRedirection(self):
        try:
            return -1 if "<iframe" in self.response.text else 1
        except:
            return -1

    # 24
    def AgeofDomain(self):
        try:
            create = self.whois_response.creation_date
            if isinstance(create, list): create = create[0]
            age = (date.today().year - create.year) * 12
            return 1 if age >= 6 else -1
        except:
            return -1

    # 25
    def DNSRecording(self):
        return 1

    # 26
    def WebsiteTraffic(self):
        return 0  # removed unreliable alexa

    # 27
    def PageRank(self):
        return 0  # removed unreliable API

    # 28
    def GoogleIndex(self):
        return 1

    # 29
    def LinksPointingToPage(self):
        try:
            count = self.response.text.count("<a href")
            if count == 0:
                return 1
            elif count <= 2:
                return 0
            return -1
        except:
            return -1

    # 30
    def StatsReport(self):
        return 1

    def getFeaturesList(self):
        return self.features