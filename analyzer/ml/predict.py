import joblib
import pandas as pd
import os

# Load model and feature schema
model_dir = os.path.dirname(__file__)
model_path = os.path.join(model_dir, 'model.pkl')
columns_path = os.path.join(model_dir, 'feature_columns.pkl')

try:
    model = joblib.load(model_path)
    feature_columns = joblib.load(columns_path)
except FileNotFoundError as e:
    raise FileNotFoundError(f"Model not trained. Please run: python analyzer/ml/train_model.py | Error: {e}")


def predict_malware(features):
    """
    Predict malware classification and confidence.
    
    Args:
        features (list): [entropy, string_count, suspicious_count, file_size, mz_flag]
    
    Returns:
        tuple: (prediction, confidence)
               - prediction: 1 for Malicious, 0 for Benign
               - confidence: probability 0.0-1.0
    """
    # Create DataFrame with proper column names
    input_df = pd.DataFrame([features], columns=feature_columns)
    
    # Predict
    prediction = model.predict(input_df)[0]
    
    # Get probability for the positive class
    probabilities = model.predict_proba(input_df)[0]
    # Probability of malicious (class 1)
    confidence = probabilities[1] if len(probabilities) > 1 else probabilities[0]
    
    # Ensure confidence is always the max probability (best prediction certainty)
    confidence = max(confidence, 1 - confidence)
    
    return prediction, confidence