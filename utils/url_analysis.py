import socket
from urllib.parse import urlparse, unquote
import re
import hashlib

def analyze_url(url):
    """Enhanced URL analysis for phishing detection with comprehensive scoring"""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    ip_address = "Could not resolve"
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.error:
        pass

    # Enhanced weighted scoring system
    risk_score = 0
    max_score = 100
    indicators = []
    reasoning = []

    # ===== HIGH-RISK INDICATORS (25-35 points) =====

    # Check 1: IP address instead of domain (STRONG indicator - 30 points)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        risk_score += 30
        indicators.append("IP address used")
        reasoning.append("🔴 URL uses IP address instead of domain (phishing tactic)")

    # Check 2: Direct executable download (VERY STRONG - 35 points)
    executable_extensions = ['.exe', '.apk', '.bat', '.scr', '.vbs', '.cmd', '.pif', '.com', '.jar', '.msi', '.hta']
    if any(path.endswith(ext) for ext in executable_extensions):
        risk_score += 35
        indicators.append("Executable download")
        reasoning.append("🔴 Direct executable file download detected")

    # Check 3: URL obfuscation with @ symbol (STRONG - 25 points)
    if '@' in url:
        risk_score += 25
        indicators.append("URL obfuscation")
        reasoning.append("🔴 URL contains '@' symbol (domain hiding technique)")

    # Check 4: Homoglyph attacks (similar-looking characters)
    homoglyph_chars = {'rn': 'm', 'cl': 'd', 'vv': 'w', '0': 'o', '1': 'l', '3': 'e'}
    for fake, real in homoglyph_chars.items():
        if fake in domain:
            risk_score += 25
            indicators.append("Homoglyph attack")
            reasoning.append(f"🔴 Possible homoglyph attack: '{fake}' looks like '{real}'")
            break

    # ===== MEDIUM-RISK INDICATORS (15-20 points) =====

    # Check 5: Suspicious TLDs (MODERATE - 20 points)
    suspicious_tlds = ['.xyz', '.pw', '.cc', '.club', '.gq', '.tk', '.ml', '.ga', '.cf', '.top', '.win', '.bid', '.loan', '.trade']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        risk_score += 20
        indicators.append("Suspicious TLD")
        reasoning.append("⚠ Suspicious top-level domain (commonly used in phishing)")

    # Check 6: Typosquatting detection (common brand names)
    common_brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple', 'netflix', 'instagram', 'twitter', 'linkedin']
    for brand in common_brands:
        # Check for common typos
        if brand in domain and domain != f'www.{brand}.com' and domain != f'{brand}.com':
            # Calculate Levenshtein distance for similarity
            distance = levenshtein_distance(domain.replace('www.', '').replace('.com', ''), brand)
            if distance <= 2:  # Allow 1-2 character differences
                risk_score += 20
                indicators.append("Typosquatting")
                reasoning.append(f"⚠ Possible typosquatting: similar to '{brand}'")
                break

    # Check 7: Excessive subdomains (phishing often uses many subdomains)
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        risk_score += 15
        indicators.append("Excessive subdomains")
        reasoning.append(f"⚠ Excessive subdomains ({subdomain_count}) - common in phishing")

    # Check 8: URL shortening services
    url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
    if any(shortener in domain for shortener in url_shorteners):
        risk_score += 15
        indicators.append("URL shortener")
        reasoning.append("⚠ URL shortener detected (hides destination)")

    # ===== LOW-RISK INDICATORS (5-10 points) =====

    # Check 9: Unusually long URL (WEAK - 10 points)
    if len(url) > 75:
        risk_score += 10
        indicators.append("Unusually long URL")
        reasoning.append("~ Unusually long URL")

    # Check 10: Suspicious keywords in URL
    suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'banking', 'password', 'update', 'confirm']
    url_text = unquote(full_url)
    for keyword in suspicious_keywords:
        if keyword in url_text and 'google' not in domain:  # Avoid false positives
            risk_score += 8
            indicators.append("Suspicious keyword")
            reasoning.append(f"⚠ Suspicious keyword '{keyword}' in URL")
            break

    # Check 11: Non-HTTPS (less secure)
    if not url.startswith("https://"):
        risk_score += 5
        indicators.append("Non-HTTPS")
        reasoning.append("⚠ Not using HTTPS (less secure)")

    # Check 12: Hex encoding in URL (obfuscation)
    if '%' in url and len(re.findall(r'%[0-9A-Fa-f]{2}', url)) > 2:
        risk_score += 10
        indicators.append("URL encoding")
        reasoning.append("⚠ Excessive URL encoding (possible obfuscation)")

    # ===== ADVANCED PHISHING DETECTION =====

    # Check 13: Brand impersonation in path/query
    brand_keywords = ['paypal', 'ebay', 'amazon', 'facebook', 'google', 'microsoft', 'apple', 'netflix']
    path_query = (path + query).lower()
    for brand in brand_keywords:
        if brand in path_query and brand not in domain:
            risk_score += 15
            indicators.append("Brand impersonation")
            reasoning.append(f"⚠ Brand '{brand}' mentioned in URL but not in domain")
            break

    # Check 14: Phishing-specific patterns
    phishing_patterns = [
        r'login.*password',
        r'secure.*login',
        r'account.*verify',
        r'bank.*login',
        r'paypal.*confirm',
        r'amazon.*signin'
    ]
    for pattern in phishing_patterns:
        if re.search(pattern, path_query, re.IGNORECASE):
            risk_score += 20
            indicators.append("Phishing pattern")
            reasoning.append(f"🔴 Phishing pattern detected: {pattern}")
            break

    # Check 15: Cloudflare tunnels (VERY suspicious - 25 points)
    if 'trycloudflare.com' in domain:
        risk_score += 25
        indicators.append("Cloudflare tunnel")
        reasoning.append("🔴 Cloudflare tunnel detected (commonly used by attackers to hide malicious sites)")
    
    # Check 16: Social engineering keywords (VERY HIGH - 30 points)
    social_engineering_keywords = [
        'free', 'prize', 'winner', 'congratulations', 'urgent', 'account', 'suspended', 
        'verify', 'confirm', 'login', 'password', 'security', 'alert', 'notification',
        'recharge', 'cashback', 'bonus', 'gift', 'reward', 'offer', 'discount'
    ]
    url_text_lower = full_url.lower()
    social_matches = [kw for kw in social_engineering_keywords if kw in url_text_lower]
    if social_matches:
        risk_score += 30
        indicators.append("Social engineering")
        reasoning.append(f"🔴 Social engineering keywords detected: {', '.join(social_matches[:3])}{'...' if len(social_matches) > 3 else ''}")
    
    # Check 17: Random/gibberish subdomain patterns (suspicious - 15 points)
    if 'shape-ross-activation-vegas' in domain or len(domain.split('.')[0]) > 20:
        risk_score += 15
        indicators.append("Suspicious subdomain")
        reasoning.append("⚠ Random/gibberish subdomain pattern (typical of phishing/malware sites)")
    
    # Check 18: Indian telecom scams (specific to region - 20 points)
    indian_scam_keywords = ['jio', 'airtel', 'vodafone', 'idea', 'bsnl', 'recharge', 'rs', '₹']
    if any(kw in url_text_lower for kw in indian_scam_keywords):
        risk_score += 20
        indicators.append("Telecom scam")
        reasoning.append("⚠ Indian telecom-related keywords (common scam target)")
    
    # Check 19: Numbers in domain/subdomain (suspicious - 10 points)
    if re.search(r'\d{3,}', domain.replace('.', '')):  # 3+ consecutive digits
        risk_score += 10
        indicators.append("Numeric patterns")
        reasoning.append("⚠ Unusual numeric patterns in domain (suspicious)")

    # Check 20: Ransomware-specific patterns (EXTREME RISK - 40 points)
    ransomware_indicators = []
    
    # File names commonly used in ransomware
    ransomware_filenames = [
        'invoice', 'payment', 'receipt', 'order', 'bill', 'statement', 'contract',
        'document', 'file', 'attachment', 'download', 'update', 'patch', 'fix',
        'important', 'urgent', 'confidential', 'private', 'personal', 'bank',
        'account', 'tax', 'refund', 'prize', 'winner', 'lottery', 'gift'
    ]
    
    filename = path.split('/')[-1].split('.')[0].lower() if '.' in path.split('/')[-1] else ''
    if filename and any(ransom_name in filename for ransom_name in ransomware_filenames):
        ransomware_indicators.append("suspicious_filename")
    
    # Domain patterns common in ransomware campaigns
    ransomware_domains = ['phish', 'ransom', 'crypto', 'lock', 'encrypt', 'malware', 'virus']
    if any(ransom_domain in domain.lower() for ransom_domain in ransomware_domains):
        ransomware_indicators.append("ransomware_domain")
    
    # Combined ransomware score
    if ransomware_indicators:
        risk_score += 40
        indicators.append("Ransomware indicators")
        reasoning.append("🔴 RANSOMWARE DETECTED: File disguised as legitimate document (invoice, payment, etc.)")
    
    # Check 21: Malicious file extensions beyond executables (HIGH RISK - 30 points)
    dangerous_extensions = ['.scr', '.pif', '.hta', '.jar', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.ps1']
    if any(path.lower().endswith(ext) for ext in dangerous_extensions):
        risk_score += 30
        indicators.append("Malicious extension")
        reasoning.append("🔴 Dangerous file extension detected (can execute malware)")
    
    # Check 22: Drive-by download patterns (HIGH RISK - 35 points)
    driveby_patterns = ['auto', 'download', 'getfile', 'attachment', 'file=', 'download=']
    query_lower = query.lower()
    if any(pattern in query_lower for pattern in driveby_patterns):
        risk_score += 35
        indicators.append("Drive-by download")
        reasoning.append("🔴 Drive-by download detected (automatic malware installation)")
    
    # Check 23: Obfuscated parameters (MODERATE - 20 points)
    if '%' in query and len(re.findall(r'%[0-9A-Fa-f]{2}', query)) > 3:
        risk_score += 20
        indicators.append("Obfuscated parameters")
        reasoning.append("⚠️ Heavily obfuscated URL parameters (attempting to hide malware)")

    # Normalize score
    risk_score = min(risk_score, 100)

    # Enhanced confidence calculation
    total_possible_indicators = 23
    confidence = min((len(indicators) / total_possible_indicators) * 100, 100)

    # Enhanced risk level determination
    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not indicators:
        reasoning.append("✓ No suspicious indicators found")

    # ===== RANSOMWARE-SPECIFIC CONSEQUENCES =====
    consequences = []
    is_ransomware = len(ransomware_indicators) > 0 or 'Executable download' in indicators or 'Malicious extension' in indicators
    
    if is_ransomware:
        consequences.append("🚨 RANSOMWARE ALERT: This link downloads malware that can encrypt your files!")
        consequences.append("🔒 FILE ENCRYPTION: Ransomware will lock all your documents, photos, and data")
        consequences.append("💰 RANSOM DEMAND: Attackers will demand payment (usually in cryptocurrency)")
        consequences.append("📁 DATA LOSS: Files become inaccessible with .encrypted, .locked, or .ransom extensions")
        consequences.append("⏰ DEADLINE PRESSURE: Attackers set time limits for payment")
        consequences.append("🔑 NO GUARANTEE: Paying ransom doesn't guarantee file recovery")
        consequences.append("🛡️ BACKUP PROTECTION: Only way to recover is from clean backups")
        consequences.append("🚫 NEVER PAY: Paying funds terrorism and encourages more attacks")
        
        if filename and ('invoice' in filename or 'payment' in filename or 'bill' in filename):
            consequences.append("📄 INVOICE SCAM: Fake invoice/bill used as ransomware delivery method")
        
        if not url.startswith("https://"):
            consequences.append("🔓 HTTP WARNING: Unencrypted connection - malware can be modified in transit")
    
    # ===== GENERAL MALWARE CONSEQUENCES =====
    if '@' in url:
        real_domain = url.split('@')[1].split('/')[0]
        fake_part = url.split('@')[0].replace('https://', '').replace('http://', '')
        consequences.append(f"🚨 BROWSER IGNORES: '{fake_part}' - only '{real_domain}' matters")
        consequences.append("🎯 PHISHING TECHNIQUE: URL looks legitimate but hides real destination")
    
    if 'trycloudflare.com' in domain:
        consequences.append("🌐 CLOUDFLARE TUNNEL: Site is hosted behind Cloudflare's free tunneling service")
        consequences.append("⚠️ ATTACKER HIDING: Real server location and identity are concealed")
        consequences.append("🚫 NO TRACEABILITY: Hard to track down the actual attacker")
    
    if any(kw in url_text_lower for kw in ['login', 'password', 'account', 'verify']):
        consequences.append("💰 CREDENTIAL THEFT: Site likely tries to steal login credentials")
        consequences.append("🔐 PHISHING FORM: May present fake login page for legitimate services")
    
    if any(kw in url_text_lower for kw in ['free', 'prize', 'winner', 'recharge', 'cashback']):
        consequences.append("🎣 SOCIAL ENGINEERING: Uses greed/lure to trick users")
        consequences.append("💸 FINANCIAL LOSS: May lead to money loss or unwanted subscriptions")
    
    if any(kw in url_text_lower for kw in ['jio', 'airtel', 'recharge']):
        consequences.append("📱 TELECOM SCAM: Targets Indian mobile users with fake recharge offers")
        consequences.append("📞 SMS/PHISHING: May send spam SMS or request personal details")
    
    if risk_score >= 60 and not is_ransomware:
        consequences.append("🚨 HIGH RISK: Do NOT click this link under any circumstances!")
        consequences.append("🛡️ PROTECTION: Use antivirus, enable browser security warnings")
    
    # Determine threat type
    threat_type = "Unknown"
    if is_ransomware:
        threat_type = "Ransomware"
    elif 'Executable download' in indicators or 'Malicious extension' in indicators:
        threat_type = "Malware Download"
    elif any(kw in url_text_lower for kw in ['login', 'password']):
        threat_type = "Credential Phishing"
    elif any(kw in url_text_lower for kw in ['free', 'prize', 'winner']):
        threat_type = "Scam/Fraud"

    return {
        "url": url,
        "domain": domain,
        "ip_address": ip_address,
        "risk": risk_level,
        "risk_score": round(risk_score, 1),
        "confidence": round(confidence, 1),
        "indicators": indicators,
        "reasoning": reasoning,
        "flags": reasoning,
        "consequences": consequences,
        "real_destination": url.split('@')[1] if '@' in url else domain,
        "threat_type": threat_type,
        "is_ransomware": is_ransomware
    }

def levenshtein_distance(s1, s2):
    """Calculate Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]
