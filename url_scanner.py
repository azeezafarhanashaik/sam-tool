import requests
import socket
import re
from urllib.parse import urlparse

print("\n=== URL Malware Scanner ===\n")

url = input("Enter URL: ")

# Add https if missing
if not url.startswith("http://") and not url.startswith("https://"):
    url = "https://" + url

print("\nChecking URL...\n")

try:
    response = requests.get(url, timeout=5)
    print("[+] URL Exists")
except:
    print("[!!] URL Does Not Exist")
    print("Risk Level : HIGH")
    exit()

# Extract Domain
parsed = urlparse(url)
domain = parsed.netloc

print("\n==============================")
print("      DOMAIN INFORMATION")
print("\n")

print(f"Domain : {domain}")

# Get IP Address
try:
    ip = socket.gethostbyname(domain)
    print(f"IP Address : {ip}")
except:
    print("IP Address : Unable to resolve")

print("\n==============================")
print("      URL ANALYSIS")
print("\n")

score = 0

# Suspicious file extensions
suspicious_ext = [
".exe",
".zip",
".rar",
".bat",
".scr",
".ps1",
".cmd"
]

for ext in suspicious_ext:
    if ext in url.lower():
        print(f"Suspicious File Extension : {ext}")
        score += 1


# Suspicious keywords
suspicious_keywords = [
"malware",
"payload",
"trojan",
"virus",
"hack",
"phishing",
"backdoor"
]

for keyword in suspicious_keywords:
    if keyword in url.lower():
        print(f"Suspicious Keyword Found : {keyword}")
        score += 1


# Check redirect
if len(response.history) > 0:
    print("Multiple Redirects Detected")
    score += 1


# Long URL detection
if len(url) > 75:
    print("Long Suspicious URL Detected")
    score += 1


# IP based URL detection
ip_pattern = r'http[s]?://\d+\.\d+\.\d+\.\d+'
if re.match(ip_pattern, url):
    print("IP Based URL Detected")
    score += 1


print("\n==============================")
print("      RISK ANALYSIS")
print("\n")

if score == 0:
    print("[+] SAFE")

elif score <= 2:
    print("[!] LOW RISK")

else:
    print("[!!] HIGH RISK")

print("\nScan Completed\n")
