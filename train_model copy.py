import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os

print("Loading dataset...")

# ================= COLUMNS =================
column_names = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment',
    'urgent','hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label'
]

# ================= LOAD DATA =================
data_path = os.path.join("data", "KDDTrain+.csv")

df = pd.read_csv(data_path, header=None, names=column_names)

print("Dataset loaded")

# ================= CLEAN LABEL =================
df['label'] = df['label'].astype(str).str.replace('.', '', regex=False)

# ================= ENCODE CATEGORICAL =================
encoders = {}

for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    encoders[col] = le

# ================= BINARY TARGET =================
df['binary_label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

X = df.drop(['label', 'binary_label'], axis=1)
y = df['binary_label']

# ================= SCALE =================
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ================= TRAIN / TEST =================
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# ================= EVALUATE =================
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"🎯 Model Accuracy: {acc:.4f}")

# ================= SAVE MODEL =================
joblib.dump(model, "model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(encoders, "encoders.pkl")
joblib.dump(list(X.columns), "feature_order.pkl")

print("✅ Model trained & saved successfully")