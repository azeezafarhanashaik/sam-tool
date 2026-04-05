import pandas as pd
from predict import predict_malware

# Load dataset
df = pd.read_csv("analyzer/ml/dataset.csv")

# Map to runtime feature names for consistency with training
sample = df.iloc[0]
entropy = sample.get("entropy", sample.get("E_text", 0))
string_count = sample.get("string_count", sample.get("E_data", 0))
suspicious_count = sample.get("suspicious_count", sample.get("sus_sections", 0))
file_size = sample.get("file_size", sample.get("filesize", 0))
mz_flag = sample.get("mz_flag", 1 if sample.get("NumberOfSections", 0) > 0 else 0)

features = [entropy, string_count, suspicious_count, file_size, mz_flag]

# Predict
prediction, confidence = predict_malware(sample)

print("Prediction:", "Malicious" if prediction == 1 else "Benign")
print("Confidence:", round(confidence * 100, 2), "%")