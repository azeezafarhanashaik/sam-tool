import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score
import joblib
import os

# Load dataset
dataset_path = os.path.join(os.path.dirname(__file__), 'dataset.csv')
df = pd.read_csv(dataset_path)

print(f"Dataset loaded: {len(df)} samples")

# Define features and labels
X = df[["entropy", "string_count", "suspicious_count", "file_size", "mz_flag"]]
y = df["label"]

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")

# Improved Random Forest Model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    random_state=42,
    n_jobs=-1
)

# Train model
model.fit(X_train, y_train)
print("Model training completed.")

# Evaluate on test set
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)

print(f"\n=== Model Performance ===")
print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")

# Save model + schema
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
columns_path = os.path.join(os.path.dirname(__file__), 'feature_columns.pkl')

joblib.dump(model, model_path)
joblib.dump(["entropy", "string_count", "suspicious_count", "file_size", "mz_flag"], columns_path)

print(f"\nModel saved to {model_path}")
print("Training complete!")