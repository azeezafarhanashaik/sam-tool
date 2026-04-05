"""
Advanced Risk Scoring Engine with Weighted Factors and Confidence Scores
Reduces false positives by using multi-factor decision logic
"""

class RiskScorer:
    """Weighted risk scoring system for malware detection"""
    
    # Risk factor weights (0-100)
    WEIGHTS = {
        'mz_signature': 35,           # Executable signature - very strong indicator
        'suspicious_apis': 30,         # High-risk API imports - strong indicator
        'embedded_mz_count': 25,       # Embedded executables - moderate-strong
        'suspicious_strings': 20,      # Malicious command strings - moderate
        'packing': 15,                 # Packed/encrypted code - weak-moderate
        'entropy': 10,                 # Entropy alone - weak indicator
        'lsb_steganography': 20,       # LSB hiding in images - moderate
        'steganography_payload': 35,   # Actual hidden executable - very strong
    }
    
    # File type default risk levels
    FILE_TYPE_BASE_RISK = {
        'image': 5,      # Images are low risk by default
        'document': 10,  # Documents slightly higher
        'archive': 15,   # Archives require scrutiny
        'executable': 40, # Executables are high scrutiny
        'script': 25,    # Scripts are moderate risk
        'unknown': 20,   # Unknown files - moderate
    }
    
    def __init__(self):
        self.indicators = {}
        self.confidence = 0
        self.reasoning = []
    
    def get_file_type_category(self, extension):
        """Categorize file by extension to apply base risk level"""
        ext = extension.lower() if extension else 'unknown'
        
        image_exts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg']
        document_exts = ['pdf', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'txt']
        archive_exts = ['zip', 'rar', '7z', 'tar', 'gz']
        executable_exts = ['exe', 'dll', 'sys', 'scr', 'msi', 'com']
        script_exts = ['bat', 'cmd', 'ps1', 'vbs', 'js', 'jse', 'py', 'rb']
        
        if ext in image_exts:
            return 'image'
        elif ext in document_exts:
            return 'document'
        elif ext in archive_exts:
            return 'archive'
        elif ext in executable_exts:
            return 'executable'
        elif ext in script_exts:
            return 'script'
        else:
            return 'unknown'
    
    def add_indicator(self, indicator_name, present, severity_multiplier=1.0):
        """Add a risk indicator"""
        if present:
            weight = self.WEIGHTS.get(indicator_name, 0)
            self.indicators[indicator_name] = weight * severity_multiplier
    
    def calculate_score(self, file_type='unknown'):
        """Calculate final risk score (0-100) based on weighted indicators"""
        if not self.indicators:
            return 0
        
        total_weight = sum(self.indicators.values())
        # Maximum possible score with all indicators
        max_possible = sum(self.WEIGHTS.values())
        
        # Normalize to 0-100
        score = (total_weight / max_possible * 100) if max_possible > 0 else 0
        return min(100, max(0, score))
    
    def calculate_confidence(self):
        """Calculate confidence level (0-100) based on number and strength of indicators"""
        if not self.indicators:
            return 0
        
        num_indicators = len(self.indicators)
        total_weight = sum(self.indicators.values())
        max_weight = sum(self.WEIGHTS.values())
        
        # More indicators and stronger indicators = higher confidence
        indicator_confidence = (num_indicators / len(self.WEIGHTS)) * 50
        weight_confidence = (total_weight / max_weight) * 50
        
        confidence = indicator_confidence + weight_confidence
        return min(100, max(0, confidence))
    
    def get_risk_level(self, score, file_type='unknown'):
        """Convert score to risk level with file type awareness"""
        file_category = self.get_file_type_category(file_type)
        
        # For images, apply stricter thresholds
        if file_category == 'image':
            if score < 30:
                return 'Low'
            elif score < 60:
                return 'Medium'
            else:
                return 'High'
        
        # For executables, lower threshold for Medium
        elif file_category == 'executable':
            if score < 25:
                return 'Low'
            elif score < 60:
                return 'Medium'
            else:
                return 'High'
        
        # Default thresholds
        else:
            if score < 30:
                return 'Low'
            elif score < 65:
                return 'Medium'
            else:
                return 'High'
    
    def analyze_file(self, file_analysis_data):
        """
        Analyze file data and return risk assessment
        file_analysis_data should contain:
        - metadata (with extension)
        - pe_info (with is_pe, suspicious_apis_found, etc.)
        - strings
        - mz_count
        """
        self.indicators = {}
        self.reasoning = []
        
        metadata = file_analysis_data.get('metadata', {})
        pe_info = file_analysis_data.get('pe_info', {})
        strings = file_analysis_data.get('strings', [])
        mz_count = file_analysis_data.get('mz_count', 0)
        extension = metadata.get('extension', 'unknown')
        file_category = self.get_file_type_category(extension)
        
        # === MULTI-FACTOR DECISION LOGIC ===
        
        # Factor 1: MZ Signature (PE executable)
        if pe_info.get('is_pe'):
            self.add_indicator('mz_signature', True)
            self.reasoning.append("✓ Valid PE executable detected")
        
        # Factor 2: Suspicious API Imports
        suspicious_apis = pe_info.get('suspicious_apis_found', [])
        if suspicious_apis:
            severity = min(len(suspicious_apis) / 3, 1.5)  # More APIs = higher severity
            self.add_indicator('suspicious_apis', True, severity)
            self.reasoning.append(f"⚠ Found {len(suspicious_apis)} suspicious API(s)")
        
        # Factor 3: Embedded MZ headers
        if mz_count > 1:
            # Multiple MZ headers is more suspicious
            severity = min(mz_count / 3, 1.5)
            self.add_indicator('embedded_mz_count', True, severity)
            self.reasoning.append(f"⚠ Found {mz_count} embedded MZ headers (possible dropper)")
        
        # Factor 4: Suspicious Strings (WEIGHTED by importance)
        suspicious_keywords = {
            'command_execution': ['cmd.exe', 'powershell', 'wscript.shell', '/c ', '/e:vbscript'],
            'process_injection': ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'],
            'registry_access': ['HKEY_', 'RegOpenKey', 'RegSetValue'],
            'system_modification': ['winreg', 'services', 'drivers'],
        }
        
        high_risk_strings_found = []
        for category, keywords in suspicious_keywords.items():
            for kw in keywords:
                if any(kw.lower() in s.lower() for s in strings):
                    high_risk_strings_found.append(kw)
        
        if high_risk_strings_found:
            severity = min(len(high_risk_strings_found) / 4, 1.5)
            self.add_indicator('suspicious_strings', True, severity)
            self.reasoning.append(f"⚠ Found {len(set(high_risk_strings_found))} suspicious string(s)")
        
        # Factor 5: Packing
        if pe_info.get('is_packed'):
            self.add_indicator('packing', True)
            self.reasoning.append("⚠ File appears packed or encrypted")
        
        # Factor 6: Entropy (weak indicator alone)
        entropy = pe_info.get('entropy', 0)
        if entropy > 7.0:
            # Only add if other indicators present
            if len(self.indicators) > 0:
                self.add_indicator('entropy', True, 0.5)
                self.reasoning.append(f"~ High entropy ({entropy:.2f})")
        
        # === CALCULATE RISK ===
        risk_score = self.calculate_score(file_category)
        confidence = self.calculate_confidence()
        risk_level = self.get_risk_level(risk_score, extension)
        
        # === SPECIAL CASE: Images with no hidden executables ===
        if file_category == 'image' and not pe_info.get('embedded_executable'):
            if risk_score < 50:  # No strong indicators
                risk_level = 'Low'
                self.reasoning = ["✓ Image file analyzed", "✓ No embedded executables detected", "✓ No strong malware indicators"]
        
        # === FINAL LOGIC: HIGH RISK only if multiple strong factors ===
        strong_indicators = [ind for ind, weight in self.indicators.items() 
                           if weight >= 25]  # Strong indicators have weight >= 25
        
        if risk_level == 'High' and len(strong_indicators) < 2:
            # If only one strong indicator, downgrade to Medium
            risk_level = 'Medium'
            self.reasoning.append("Downgraded from High to Medium: Only one strong indicator")
        
        return {
            'risk_level': risk_level,
            'risk_score': round(risk_score, 1),
            'confidence': round(confidence, 1),
            'indicators': self.indicators,
            'reasoning': self.reasoning,
            'file_category': file_category
        }
    
    def analyze_image(self, image_data):
        """
        Analyze image data
        image_data should contain:
        - file_extension
        - entropy
        - embedded_mz
        - lsb_suspicious
        """
        self.indicators = {}
        self.reasoning = []
        
        extension = image_data.get('extension', 'jpg')
        entropy = image_data.get('entropy', 0)
        embedded_mz = image_data.get('embedded_mz', False)
        lsb_suspicious = image_data.get('lsb_suspicious', False)
        
        # Factor 1: Embedded Executable (VERY STRONG)
        if embedded_mz:
            self.add_indicator('steganography_payload', True)
            self.reasoning.append("🔴 CRITICAL: Embedded executable detected in image!")
        
        # Factor 2: LSB Steganography (MODERATE)
        if lsb_suspicious:
            self.add_indicator('lsb_steganography', True)
            self.reasoning.append("⚠ LSB steganography patterns detected")
        
        # Factor 3: High Entropy (WEAK for images - images naturally have high entropy)
        if entropy > 7.5:
            # For images, very high entropy is more suspicious when combined with other factors
            if len(self.indicators) > 0:
                self.add_indicator('entropy', True, 0.3)
        
        # === IMAGE-SPECIFIC LOGIC ===
        risk_score = self.calculate_score('image')
        confidence = self.calculate_confidence()
        
        # Images need VERY strong indicators to be HIGH risk
        if embedded_mz:
            risk_level = 'High'
            self.reasoning.append("Risk Level: HIGH - Embedded payload detected")
        elif lsb_suspicious:
            risk_level = 'Medium'
            self.reasoning.append("Risk Level: MEDIUM - Possible steganography")
        else:
            risk_level = 'Low'
            self.reasoning.append("✓ Risk Level: LOW - No hidden payloads detected")
        
        return {
            'risk_level': risk_level,
            'risk_score': round(risk_score, 1),
            'confidence': round(confidence, 1),
            'indicators': self.indicators,
            'reasoning': self.reasoning,
            'file_category': 'image'
        }
