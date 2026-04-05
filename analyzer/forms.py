from django import forms

class FileUploadForm(forms.Form):
    file = forms.FileField()

class UrlScanForm(forms.Form):
    url = forms.URLField()

class ImageUploadForm(forms.Form):
    image = forms.ImageField()
