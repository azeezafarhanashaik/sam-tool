# 🔐 SAM Tool – Static Malware Analysis Engine

A Django-based cybersecurity tool developed to analyze **files, URLs, and images** using static analysis techniques to detect potential threats without executing them.

---

## 👩‍💻 SAM Team – CryptoClash Hackathon

- Shaik Azeeza Farhana  
- Cherukuri Sumiya  
- Kunapareddy Divya Sai Sri  
- Chakka Pavani  
- Battula Samhitha  

---

## 🧠 Problem Statement

Traditional malware detection systems rely on execution, which is risky and inefficient.

This project provides a **Static Malware Analysis Engine** that:
- Detects threats without execution  
- Reduces system risk  
- Improves analysis speed  
- Handles zero-day attacks  

---

## 🚀 Features

### 🧾 File Analysis
- Detects MZ signatures (PE files)
- Extracts suspicious strings
- Identifies packed/encrypted files using entropy

### 🌐 URL Analysis
- Detects phishing and malicious patterns
- Risk scoring system for URLs

### 🖼️ Image Analysis (Steganography)
- Detects hidden data using entropy
- LSB (Least Significant Bit) analysis

### 📊 Risk Scoring System
- Weighted scoring (0–100)
- Indicators:
  - MZ Signature → High Risk  
  - Suspicious APIs → Strong  
  - Embedded Executables → Moderate-Strong  
  - Steganography Payload → Very Strong  

---

## 🛠️ Tech Stack

- **Backend:** Django, Python  
- **Frontend:** HTML, CSS  
- **Security Techniques:**
  - Entropy Analysis  
  - String Extraction  
  - Metadata Analysis  
  - Steganography Detection  

---

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository
```bash
git clone https://github.com/azeezafarhanashaik/sam-tool.git
cd sam-tool
```
### 2️⃣ Create Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate
```
### 3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```
### 4️⃣ Run Server
```bash
python manage.py runserver
```
### 5️⃣ Open in Browser
```bash
http://127.0.0.1:8000/
```
---

## 🔮 Future Scope

- Integration with Machine Learning for advanced threat detection  
- API integration with VirusTotal and threat intelligence platforms  
- Real-time monitoring and alert system  
- Support for additional file formats and deeper analysis  
- Deployment as a scalable web service  

---

## ⚠️ Disclaimer

This project is intended for **educational and research purposes only**.  
Any misuse of this tool for malicious or unauthorized activities is strictly discouraged.

---

## 🤝 Contributing

Contributions are welcome!  
If you'd like to improve this project:

1. Fork the repository  
2. Create a new branch  
3. Make your changes  
4. Submit a pull request  

---

## 👩‍💻 Author

**Shaik Azeeza Farhana**  
Cybersecurity Enthusiast 🔐  

---

## 🌟 Acknowledgment

This project was developed as part of a cybersecurity hackathon, focusing on building a **safe, efficient, and scalable malware analysis system**.

---

## ⭐ Support

If you found this project useful:

- ⭐ Star this repository  
- 🍴 Fork and contribute  
- 📢 Share with others  

---

> “Security is not a product, but a process.” 🔐

