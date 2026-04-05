import os
from PIL import Image
import math
from .risk_scoring import RiskScorer

def calculate_entropy(data):
    """Calculate Shannon entropy of data block."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_image(file_path):
    if not os.path.exists(file_path):
        return {"error": "File not found"}
        
    analysis_data = {
        "filename": os.path.basename(file_path),
        "format": "Unknown",
        "size": (0, 0),
        "mode": "Unknown",
        "entropy": 0.0,
        "extension": os.path.splitext(file_path)[1].lstrip('.').lower(),
    }
    
    try:
        # Check basic image properties
        with Image.open(file_path) as img:
            analysis_data["format"] = img.format
            analysis_data["size"] = img.size
            analysis_data["mode"] = img.mode
            
            # Very basic LSB check: extract LSB of first 1000 pixels
            pixels = list(img.getdata())[:1000]
            lsb_suspicious = False
            
            # Depends on image mode, if RGB/RGBA:
            if img.mode in ['RGB', 'RGBA'] and isinstance(pixels[0], tuple):
                try:
                    lsb_data = [p[0] & 1 for p in pixels]  # Check Red channel LSB
                    # Check ratio of 1s and 0s. A perfectly random LSB (often encrypted/hidden data) is ~0.5
                    ratio = sum(lsb_data) / max(1, len(lsb_data))
                    if 0.45 < ratio < 0.55:
                        lsb_suspicious = True
                except (TypeError, IndexError):
                    pass
            
        # Check overall file entropy
        with open(file_path, "rb") as f:
            data = f.read()
            entropy = calculate_entropy(data)
            analysis_data["entropy"] = round(entropy, 2)
        
        # Check for embedded EXEs (MZ header)
        embedded_mz = b'MZ' in data
        
        # === NEW: Use Advanced Risk Scoring Engine for Images ===
        scorer = RiskScorer()
        
        image_assessment_data = {
            'extension': analysis_data['extension'],
            'entropy': entropy,
            'embedded_mz': embedded_mz,
            'lsb_suspicious': lsb_suspicious,
        }
        
        risk_assessment = scorer.analyze_image(image_assessment_data)
        
        return {
            "filename": analysis_data["filename"],
            "format": analysis_data["format"],
            "size": analysis_data["size"],
            "mode": analysis_data["mode"],
            "entropy": analysis_data["entropy"],
            "lsb_suspicious": lsb_suspicious,
            "embedded_executable": embedded_mz,
            "risk": risk_assessment['risk_level'],
            "risk_score": risk_assessment['risk_score'],
            "confidence": risk_assessment['confidence'],
            "reasoning": risk_assessment['reasoning'],
            "flags": risk_assessment['reasoning'],
        }

    except Exception as e:
        return {
            "error": str(e),
            "risk": "Unknown",
            "confidence": 0,
            "reasoning": ["Error during analysis"]
        }
