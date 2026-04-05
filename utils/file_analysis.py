import os
import pefile
import math
import re
from .hashing import get_file_hash
from .metadata import extract_metadata
from .risk_scoring import RiskScorer

def calculate_entropy(data):
    """Calculate Shannon entropy of data block."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_strings(file_path, min_length=4):
    """Extract printable strings from file."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            regexp = b'[ -~]{%d,}' % min_length
            patterns = re.findall(regexp, data)
            return [str(p.decode('utf-8', errors='ignore')) for p in patterns[:100]] # Limit to 100
    except Exception:
        return []

def get_mz_count(file_path):
    """Count MZ headers (detect embedded executables)."""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            return content.count(b'MZ')
    except Exception:
        return 0

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = []
        suspicious_apis = ["LoadLibrary", "GetProcAddress", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
        found_suspicious_apis = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', 'ignore')
                        imports.append(api_name)
                        for susp in suspicious_apis:
                            if susp.lower() in api_name.lower():
                                found_suspicious_apis.append(api_name)
                                
        # Calculate overall entropy
        with open(file_path, 'rb') as f:
            entropy = calculate_entropy(f.read())
            
        is_packed = False
        packed_sections = []
        for section in pe.sections:
            section_entropy = section.get_entropy()
            if section_entropy > 7.0: # High entropy implies packed/encrypted
                is_packed = True
                packed_sections.append(section.Name.decode('utf-8', 'ignore').strip('\x00'))
                
        return {
            "is_pe": True,
            "entropy": round(entropy, 2),
            "imports": imports[:20], # First 20
            "suspicious_apis_found": list(set(found_suspicious_apis)),
            "is_packed": is_packed,
            "packed_sections": packed_sections
        }
    except pefile.PEFormatError:
        return {"is_pe": False, "error": "Not a valid PE file"}
    except Exception as e:
        return {"is_pe": False, "error": str(e)}

def analyze_file(file_path):
    metadata = extract_metadata(file_path)
    if "error" in metadata:
        return {"error": metadata["error"]}
        
    file_hash = get_file_hash(file_path)
    strings = extract_strings(file_path)
    mz_count = get_mz_count(file_path)
    
    pe_info = {}
    if metadata.get('extension') in ['exe', 'dll', 'sys']:
        pe_info = analyze_pe(file_path)
    
    # === NEW: Use Advanced Risk Scoring Engine ===
    scorer = RiskScorer()
    
    analysis_data = {
        'metadata': metadata,
        'pe_info': pe_info,
        'strings': strings,
        'mz_count': mz_count
    }
    
    risk_assessment = scorer.analyze_file(analysis_data)
    
    return {
        "metadata": metadata,
        "hash": file_hash,
        "strings": strings,
        "pe_info": pe_info,
        "risk": risk_assessment['risk_level'],
        "risk_score": risk_assessment['risk_score'],
        "confidence": risk_assessment['confidence'],
        "reasoning": risk_assessment['reasoning'],
        "file_category": risk_assessment['file_category'],
        "flags": risk_assessment['reasoning']
    }
