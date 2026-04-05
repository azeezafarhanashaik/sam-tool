from django.db import models

from django.contrib.auth import get_user_model

User = get_user_model()

class FileAnalysis(models.Model):
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/files/')
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='file_analyses')
    sha256_hash = models.CharField(max_length=64, blank=True)
    risk_score = models.CharField(max_length=20, default="Unknown")
    confidence = models.FloatField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict)

    def __str__(self):
        return f"{self.filename} - {self.risk_score} ({self.confidence}%)"

class UrlAnalysis(models.Model):
    url = models.URLField(max_length=500)
    ip_address = models.CharField(max_length=45, blank=True)
    risk_score = models.CharField(max_length=20, default="Unknown")
    confidence = models.FloatField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict)

    def __str__(self):
        return f"{self.url} - {self.risk_score} ({self.confidence}%)"

class ImageAnalysis(models.Model):
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/images/')
    risk_score = models.CharField(max_length=20, default="Unknown")
    confidence = models.FloatField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict)

    def __str__(self):
        return f"{self.filename} - {self.risk_score} ({self.confidence}%)"

class ScanResult(models.Model):
    scan_type = models.CharField(max_length=20)  # file / url / image
    input_data = models.TextField()
    result = models.CharField(max_length=20)
    confidence = models.FloatField()
    risk = models.CharField(max_length=20)
    reasons = models.TextField(blank=True)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='scan_results')
    created_at = models.DateTimeField(auto_now_add=True)
