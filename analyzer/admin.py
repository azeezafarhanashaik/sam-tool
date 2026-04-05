from django.contrib import admin
from .models import FileAnalysis, UrlAnalysis, ImageAnalysis

admin.site.register(FileAnalysis)
admin.site.register(UrlAnalysis)
admin.site.register(ImageAnalysis)
