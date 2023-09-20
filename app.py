import re
import whois
from datetime import date
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, render_template
import pickle
import numpy as np


def getDomain(url):
    if "//" in url:
        url = url.split("//")[1]
    if "www." in url: 
        url = url.split("www.")[1]
    if "/" in url:
        url = url.split("/")[0]
    return url

def isIp(url):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    result = 0
    members = url.split("/")
    for member in members:
        if re.match(ip_pattern,member):
            result = 1
    return result

def isValid(url):
   # w = whois.whois(getDomain(url))
   # expiry_date = ""
   # for line in w.text.split('\n'):
   #     if "Registry Expiry Date" in line:
   #         expiry_date = line.split(": ")[1]
   #         expiry_date = expiry_date.split("T0")[0]
   #         break
   # return int(expiry_date > str(date.today()))
   domain_info = whois.whois(getDomain(url))
   #print(domain_info)
   if isinstance(domain_info.expiration_date,list):
       expiry =  domain_info.expiration_date[0]
   else:
    expiry = domain_info.expiration_date
   current = datetime.now()
   if(current<expiry): return 1
   else: return 0

def activeDuration(url):
    domain_info = whois.whois(url)
    start = domain_info.creation_date
    current = datetime.now()
    duration = current-start
    return duration.days

def getSubdomains(url):
    # Parse the URL
    parsed_url = urlparse(url)
    
    # Extract the domain
    domain = parsed_url.netloc
    
    # Split the domain into subdomains
    subdomains = domain.split('.')
    
    # Count the subdomains
    num_subdomains = len(subdomains) - 1
    
    return num_subdomains

#returns domain length 
def domainLen(url):
    return len(getDomain(url))

#returns true if "//" are present in the url
def isRedirect(url):
    # response = requests.get(url)
    # if response.status_code == 301 or response.status_code == 302:
    #     return 1
    # return 0
    return "//" in url[8:]
        
#returns true if "-" or "@" are present in the url
def haveDash(url):
    return int('-' in url)

def isAt(url):
    return int('@' in url)

def urlLen(url):
    return len(url)
    


def FeatureExtraction(url):
    features = []
    features.append(isIp(url))
    features.append(isValid(url))
    features.append(activeDuration(url))
    features.append(urlLen(url))
    features.append(isAt(url))
    features.append(isRedirect(url))
    features.append(haveDash(url))
    features.append(domainLen(url))
    features.append(getSubdomains(url))
    return features


file = open("rf-200-10-4.pkl","rb")
rf = pickle.load(file)
file.close()
# 
stored_results = ['']
app = Flask(__name__)
#
#
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj).reshape(1,9) 
        y_pred = rf.predict(x)[0]
        
        if y_pred == 1:
            result = "PHISHING"
        else:
            result = "LEGIT"
        stored_results.append(result)
        
        
    return render_template("index.html",message = stored_results[-1])
stored_results[0] = ''

@app.route("/",methods = ["GET","POST"])
def index1():
    if request.method == "GET":
        return render_template("index.html",message="PHISHING")

if __name__ == "__main__":
    app.run(debug=True)