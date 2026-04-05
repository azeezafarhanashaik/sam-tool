from analyzer.ml.predict import predict_malware
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import FileUploadForm, UrlScanForm, ImageUploadForm
from .models import FileAnalysis as FileModel, UrlAnalysis as UrlModel, ImageAnalysis as ImageModel, ScanResult
from utils.file_analysis import analyze_file
from utils.url_analysis import analyze_url
from utils.steganography import analyze_image
import os

def home_view(request):
    return render(request, 'home.html')

def dashboard_view(request):
    file_form = FileUploadForm()
    url_form = UrlScanForm()
    image_form = ImageUploadForm()
    results = None
    show_result = False
    results_tab = None

    # Active tab based on query parameter (default to file)
    active_tab = request.GET.get('tab', 'file')

    # Reset results when switching tabs (GET request without POST)
    if request.method == "GET":
        results = None
        show_result = False

    if request.method == "POST":
        # Store the original tab for results display
        results_tab = None
        
        if 'file_upload' in request.POST:
            results_tab = "file"
            active_tab = "file"
            file_form = FileUploadForm(request.POST, request.FILES)
            if file_form.is_valid():
                uploaded_file = request.FILES['file']
                # Create a model instance to handle the upload
                analysis_obj = FileModel(
                    filename=uploaded_file.name,
                    file=uploaded_file,
                    created_by=request.user if request.user.is_authenticated else None
                )
                analysis_obj.save()
                
                # Run analysis
                analysis_data = analyze_file(analysis_obj.file.path)
                
                if "error" not in analysis_data:
                    # Extract features for ML
                    entropy = analysis_data.get('pe_info', {}).get('entropy', 0)
                    string_count = len(analysis_data.get('strings', []))
                    suspicious_count = len(analysis_data.get('pe_info', {}).get('suspicious_apis_found', []))
                    file_size = analysis_data.get('metadata', {}).get('size_bytes', 0)
                    mz_flag = 1 if analysis_data.get('mz_count', 0) > 0 else 0
                    
                    features = [entropy, string_count, suspicious_count, file_size, mz_flag]
                    
                    # ML Prediction with enhanced confidence
                    try:
                        prediction, ml_confidence = predict_malware(features)
                        ml_result = "Malicious" if prediction == 1 else "Benign"
                        ml_confidence_pct = round(ml_confidence * 100, 2)
                    except Exception as e:
                        # Fallback if ML fails
                        ml_result = "Unable to determine"
                        ml_confidence_pct = 0.0
                        print(f"ML Prediction error: {e}")
                    
                    # ===== STRONG STATIC DETECTION RULES =====
                    reasons = analysis_data.get("reasoning", [])
                    forced_malicious = False
                    
                    # Combine all extracted strings for analysis
                    extracted_strings = " ".join(analysis_data.get("strings", [])).lower()
                    
                    # Detect suspicious commands
                    if "powershell" in extracted_strings:
                        reasons.append("🚨 PowerShell command detected (execution risk)")
                        forced_malicious = True
                    
                    if "cmd.exe" in extracted_strings or "cmd /c" in extracted_strings:
                        reasons.append("🚨 Command prompt execution detected (shell risk)")
                        forced_malicious = True
                    
                    # Detect persistence behavior (registry)
                    if "currentversion\\run" in extracted_strings:
                        reasons.append("🚨 Registry persistence detected (autorun)")
                        forced_malicious = True
                    
                    if "hkey_local_machine" in extracted_strings and ("run" in extracted_strings or "startup" in extracted_strings):
                        reasons.append("🚨 Registry startup behavior detected")
                        forced_malicious = True
                    
                    # Detect packing/obfuscation
                    if "upx" in extracted_strings:
                        reasons.append("🚨 Packed executable (UPX detected)")
                        forced_malicious = True
                    
                    if "themida" in extracted_strings or "securom" in extracted_strings:
                        reasons.append("🚨 Anti-analysis protection detected (packer)")
                        forced_malicious = True
                    
                    # Detect fake sections/obfuscation
                    if ".fake" in extracted_strings or "fakesection" in extracted_strings:
                        reasons.append("🚨 Fake sections detected (obfuscation)")
                        forced_malicious = True
                    
                    # Detect network/C&C behavior
                    if "winsock" in extracted_strings or "wsasocket" in extracted_strings:
                        reasons.append("⚠️ Network socket operations detected")
                    
                    if "http://" in extracted_strings or "https://" in extracted_strings:
                        reasons.append("⚠️ Network communication detected")
                    
                    # Detect process injection
                    if "writeprocessmemory" in extracted_strings or "createremotethread" in extracted_strings:
                        reasons.append("🚨 Process injection detected (malware technique)")
                        forced_malicious = True
                    
                    # Override ML if strong static indicators found
                    if forced_malicious:
                        ml_result = "Malicious"
                        ml_confidence_pct = max(ml_confidence_pct, 85.0)
                    
                    # Combine scores: 70% static analysis, 30% ML
                    rule_score = analysis_data.get("risk_score", 0)
                    final_score = (rule_score * 0.7) + (ml_confidence_pct * 0.3)
                    
                    # Ensure high threat indicators boost final score
                    if forced_malicious:
                        final_score = max(final_score, 75)
                    
                    # Final risk classification
                    if final_score >= 70:
                        final_risk = "High"
                    elif final_score >= 40:
                        final_risk = "Medium"
                    else:
                        final_risk = "Low"
                    
                    analysis_obj.sha256_hash = analysis_data.get("hash", "")
                    analysis_obj.risk_score = final_risk
                    analysis_obj.confidence = ml_confidence_pct
                    analysis_obj.details = analysis_data
                    analysis_obj.save()
                    
                    # Save to unified ScanResult
                    ScanResult.objects.create(
                        scan_type="file",
                        input_data=uploaded_file.name,
                        result=ml_result,
                        confidence=ml_confidence_pct,
                        risk=final_risk,
                        reasons=", ".join(reasons),
                        created_by=request.user if request.user.is_authenticated else None
                    )
                    
                    results = {
                        "type": "file", 
                        "data": analysis_data, 
                        "risk": final_risk,
                        "confidence": ml_confidence_pct,
                        "reasoning": reasons,
                        "risk_score": analysis_data.get("risk_score", 0),
                        "ml_result": ml_result,
                        "final_score": round(final_score, 2),
                        "forced_malicious": forced_malicious,
                        "created_by": request.user if request.user.is_authenticated else type('User', (), {'username': 'SAM Tool'})()
                    }
                    show_result = True
                else:
                    messages.error(request, f"Analysis error: {analysis_data['error']}")
        
        elif 'url_scan' in request.POST:
            results_tab = "url"
            active_tab = "url"
            url_form = UrlScanForm(request.POST)
            if url_form.is_valid():
                target_url = url_form.cleaned_data['url']
                analysis_data = analyze_url(target_url)
                
                analysis_obj = UrlModel(
                    url=target_url, 
                    ip_address=analysis_data.get("ip_address", ""), 
                    risk_score=analysis_data.get("risk", "Unknown"),
                    confidence=analysis_data.get("confidence", 0),
                    details=analysis_data
                )
                analysis_obj.save()
                
                # Determine result based on risk
                url_result = "Suspicious" if analysis_obj.risk_score in ["High", "Medium"] else "Clean"
                
                # Save to unified ScanResult
                ScanResult.objects.create(
                    scan_type="url",
                    input_data=target_url,
                    result=url_result,
                    confidence=analysis_obj.confidence,
                    risk=analysis_obj.risk_score,
                    reasons=", ".join(analysis_data.get("reasoning", [])),
                    created_by=request.user if request.user.is_authenticated else None
                )
                
                results = {
                    "type": "url", 
                    "data": analysis_data, 
                    "risk": analysis_obj.risk_score,
                    "confidence": analysis_obj.confidence,
                    "reasoning": analysis_data.get("reasoning", []),
                    "created_by": request.user if request.user.is_authenticated else type('User', (), {'username': 'SAM Tool'})()
                }
                show_result = True
                
        elif 'image_upload' in request.POST:
            results_tab = "image"
            active_tab = "image"
            image_form = ImageUploadForm(request.POST, request.FILES)
            if image_form.is_valid():
                uploaded_image = request.FILES['image']
                
                analysis_obj = ImageModel(filename=uploaded_image.name, file=uploaded_image)
                analysis_obj.save()
                
                analysis_data = analyze_image(analysis_obj.file.path)
                
                if "error" not in analysis_data:
                    analysis_obj.risk_score = analysis_data.get("risk", "Unknown")
                    analysis_obj.confidence = analysis_data.get("confidence", 0)
                    analysis_obj.details = analysis_data
                    analysis_obj.save()
                    
                    # Determine result based on risk
                    image_result = "Suspicious" if analysis_obj.risk_score in ["High", "Medium"] else "Clean"
                    
                    # Save to unified ScanResult
                    ScanResult.objects.create(
                        scan_type="image",
                        input_data=uploaded_image.name,
                        result=image_result,
                        confidence=analysis_obj.confidence,
                        risk=analysis_obj.risk_score,
                        reasons=", ".join(analysis_data.get("reasoning", [])),
                        created_by=request.user if request.user.is_authenticated else None
                    )
                    
                    results = {
                        "type": "image", 
                        "data": analysis_data, 
                        "risk": analysis_obj.risk_score,
                        "confidence": analysis_obj.confidence,
                        "reasoning": analysis_data.get("reasoning", []),
                        "risk_score": analysis_data.get("risk_score", 0),
                        "created_by": request.user if request.user.is_authenticated else type('User', (), {'username': 'SAM Tool'})()
                    }
                    show_result = True
                else:
                    messages.error(request, f"Analysis error: {analysis_data['error']}")

    # Get recent history
    recent_files = FileModel.objects.all().order_by('-timestamp')[:5]
    recent_urls = UrlModel.objects.all().order_by('-timestamp')[:5]
    recent_images = ImageModel.objects.all().order_by('-timestamp')[:5]
    history = ScanResult.objects.order_by('-created_at')[:10]

    context = {
        'file_form': file_form,
        'url_form': url_form,
        'image_form': image_form,
        'results': results,
        'show_result': show_result,
        'recent_files': recent_files,
        'recent_urls': recent_urls,
        'recent_images': recent_images,
        'history': history,
        'active_tab': active_tab
    }
    return render(request, 'dashboard.html', context)

def contact_view(request):
    return render(request, 'contact.html')
