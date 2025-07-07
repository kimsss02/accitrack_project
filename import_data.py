import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# Load and clean data
df = pd.read_csv(r"C:\Users\keith\Downloads\ACCITRACK_csv\Combined.csv")
df.columns = df.columns.str.strip()

df = df.rename(columns={
    'Date Reported': 'date',
    'Time Committed': 'time',
    'Weather Conditions': 'weather',
    'Barangay/Location': 'location',
    'Type of Place': 'type_of_place',
    'VTA Category': 'vta_category',
    'Victim Killed': 'victim_killed',
    'Victim Injured': 'victim_injured',
    'Victim Unharmed': 'victim_unharmed',
    'Main Cause (e.g. Human, Vehicle, Infrastructure, Environmental)': 'cause',
    'Details of Main Cause (e.g.  Human-Intoxication)': 'cause_details',
    'Case Status': 'case_status',
    'Road Conditions': 'road_conditions'
})

# Drop rows with missing values in key fields
df = df.dropna(subset=['weather', 'road_conditions', 'time', 'location', 'date'])

# Map Yes/No to 1/0
yes_no_map = {'Yes': 1, 'No': 0}
for col in ['victim_killed', 'victim_injured', 'victim_unharmed']:
    df[col] = df[col].map(yes_no_map).fillna(0).astype(int)

# Time features
df['hour'] = pd.to_datetime(df['time'], format='%H:%M', errors='coerce').dt.hour.fillna(0).astype(int)
df['day_of_week'] = pd.to_datetime(df['date'], errors='coerce').dt.weekday.fillna(0).astype(int)
df['rush_hour'] = df['hour'].apply(lambda x: 1 if 7 <= x <= 9 or 16 <= x <= 18 else 0)

df['time'] = df['hour'].apply(lambda x: str(x).zfill(2))
# 👇 Ensure all 24-hour values are seen by the encoder
all_hours = set([str(i).zfill(2) for i in range(24)])
existing_hours = set(df['time'].unique())
missing_hours = list(all_hours - existing_hours)

# Add dummy rows for missing hours (only for encoder training)
for hour_str in missing_hours:
    dummy_row = df.iloc[0].copy()  # copy any existing row
    dummy_row['time'] = hour_str
    df = pd.concat([df, pd.DataFrame([dummy_row])], ignore_index=True)

# ✅ Only encode necessary categorical fields
label_cols = ['weather', 'road_conditions', 'location', 'time']
label_encoders = {}

for col in label_cols:
    le = LabelEncoder()
    df[col] = df[col].astype(str).str.strip().str.lower()
    le.fit(df[col])
    df[col] = le.transform(df[col])
    label_encoders[col] = le
    joblib.dump(le, f"{col}_encoder.pkl")

# Define features and target
features = [
    'weather', 'road_conditions', 'hour', 'location', 'day_of_week',
    'time', 'victim_unharmed'  
]
X = df[features]
y = df['victim_injured']

# Handle imbalance
scale_weight = (len(y) - y.sum()) / y.sum()

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = XGBClassifier(
    eval_metric='logloss',
    use_label_encoder=False,
    scale_pos_weight=scale_weight
)
model.fit(X_train, y_train)

# Evaluate
print(f"Accuracy: {accuracy_score(y_test, model.predict(X_test)):.2f}")
print(classification_report(y_test, model.predict(X_test)))

# Save model and encoders
joblib.dump(model, "accident_prediction_model.pkl")
for col, enc in label_encoders.items():
    joblib.dump(enc, f"{col}_encoder.pkl")

print("Model and encoders saved successfully.")
