# ================= IMPORT LIBRARIES =================
import pandas as pd
import joblib

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, classification_report


# ================= LOAD DATASET =================
print("Loading NSL-KDD dataset...")

df = pd.read_csv("data/KDDTrain+.csv", header=None)

columns = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root",
"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login","count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate",
"label","difficulty"
]

df.columns = columns


# ================= ENCODE CATEGORICAL FEATURES =================
print("Encoding categorical features...")

for col in ["protocol_type", "service", "flag"]:
    encoder = LabelEncoder()
    df[col] = encoder.fit_transform(df[col])


# ================= ATTACK CLASS MAPPING =================
attack_map = {

"normal":0,

# DoS
"neptune":1,"smurf":1,"back":1,"teardrop":1,

# Probe
"satan":2,"ipsweep":2,"nmap":2,"portsweep":2,

# R2L
"guess_passwd":3,"ftp_write":3,"imap":3,

# U2R
"buffer_overflow":4,"rootkit":4,"loadmodule":4
}

df["Label"] = df["label"].map(attack_map)

df.dropna(inplace=True)
df["Label"] = df["Label"].astype(int)


# ================= FEATURE / TARGET SPLIT =================
X = df.drop(["label","difficulty","Label"], axis=1)
y = df["Label"]


# ================= FEATURE SCALING =================
print("Scaling features...")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


# ================= TRAIN TEST SPLIT =================
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.2,
    random_state=42
)


# ================= RANDOM FOREST TRAINING =================
print("Training Random Forest model...")

rf_model = RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced",
    random_state=42
)

rf_model.fit(X_train, y_train)

rf_pred = rf_model.predict(X_test)

print("\nRandom Forest Accuracy:", accuracy_score(y_test, rf_pred))
print("\nClassification Report:\n", classification_report(y_test, rf_pred))


# ================= ISOLATION FOREST TRAINING =================
print("\nTraining Isolation Forest model...")

iso_model = IsolationForest(
    n_estimators=200,
    contamination=0.1,
    random_state=42
)

iso_model.fit(X_scaled)


# ================= SAVE MODELS =================
print("\nSaving models...")

joblib.dump(rf_model, "rf_model.pkl")
joblib.dump(iso_model, "iso_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("✅ Models saved successfully!")