import os
import subprocess
import hashlib
import re

print("\n=== File Malware Scanner ===\n")

home = os.path.expanduser("~")

# Show only visible directories
directories = [
d for d in os.listdir(home)
if os.path.isdir(os.path.join(home, d)) and not d.startswith(".")
]

print("Select Directory:\n")

for i, directory in enumerate(directories):
    print(f"{i+1}. {directory}")

choice = int(input("\nSelect Directory: "))

selected_directory = os.path.join(home, directories[choice-1])

# Show only files
files = [
f for f in os.listdir(selected_directory)
if os.path.isfile(os.path.join(selected_directory, f))
]

print("\nFiles:\n")

for i, file in enumerate(files):
    print(f"{i+1}. {file}")

file_choice = int(input("\nSelect File: "))

file_path = os.path.join(selected_directory, files[file_choice-1])

print("\n==============================")
print("      FILE METADATA")
print("\n")

# File metadata
file_size = os.path.getsize(file_path)
print(f"File Name : {os.path.basename(file_path)}")
print(f"File Size : {file_size} bytes")

# Hash calculation
with open(file_path,"rb") as f:
    data = f.read()
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()

print(f"MD5 Hash : {md5_hash}")
print(f"SHA256   : {sha256_hash}")

print("\n==============================")
print("      FILE TYPE")
print("\n")

# File type detection
file_type = subprocess.getoutput(f"file {file_path}")
print(file_type)

print("\n==============================")
print("      STRING ANALYSIS")
print("\n")

suspicious_strings = [
"powershell",
"cmd.exe",
"base64",
"eval",
"exec",
"socket",
"payload",
"malware",
"trojan",
"virus",
"keylogger",
"backdoor"
]

score = 0

try:
    content = data.decode(errors="ignore")

    for word in suspicious_strings:
        if word in content.lower():
            print(f"Suspicious String Found : {word}")
            score += 1

except:
    print("Cannot decode file")

print("\n==============================")
print("      YARA SCAN")
print("\n")

# YARA Scan
yara_result = subprocess.getoutput(f"yara malware_rules.yar {file_path}")

if yara_result:
    print("YARA Match Found:")
    print(yara_result)
    score += 2
else:
    print("No YARA Matches")

print("\n==============================")
print("      IMPORT ANALYSIS")
print("\n")

imports = subprocess.getoutput(f"strings {file_path}")

suspicious_imports = [
"CreateRemoteThread",
"VirtualAlloc",
"WriteProcessMemory",
"LoadLibrary",
"GetAsyncKeyState",
"socket",
"connect",
"exec",
"system",
"WinExec"
]

found_import = False

for imp in suspicious_imports:
    if imp.lower() in imports.lower():
        print(f"Suspicious Import Found : {imp}")
        score += 1
        found_import = True

if not found_import:
    print("No Suspicious Imports Found")

print("\n==============================")
print("      OBFUSCATION DETECTION")
print("\n")

# detect long encoded strings
long_strings = re.findall(r"[A-Za-z0-9+/=]{20,}", imports)

if len(long_strings) > 5:
    print("Possible Obfuscation Detected")
    score += 1
else:
    print("No Obfuscation Detected")

print("\n==============================")
print("      RISK ANALYSIS)
print(=\n")

if score == 0:
    print("[+] SAFE")

elif score <=3:
    print("[!] LOW RISK")

else:
    print("[!!] HIGH RISK")

print("\nAnalysis Completed\n")
