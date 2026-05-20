from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO
import pandas as pd
import numpy as np
import mysql.connector
import random
import datetime
import joblib

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest


# ================= APP =================

app = Flask(__name__)
app.secret_key = "secretkey"

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)


# ================= DATABASE =================

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="yuvaraj",
    database="cyberdb",
    autocommit=True
)


# ================= DATASET =================

print("Loading Dataset...")

df = pd.read_csv(
    "data/KDDTrain+.csv",
    header=None
)

columns=[

"duration","protocol_type","service","flag",
"src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot",
"num_failed_logins","logged_in",
"num_compromised","root_shell",
"su_attempted","num_root",
"num_file_creations","num_shells",
"num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login",
"count","srv_count",
"serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate",
"same_srv_rate","diff_srv_rate",
"srv_diff_host_rate",
"dst_host_count",
"dst_host_srv_count",
"dst_host_same_srv_rate",
"dst_host_diff_srv_rate",
"dst_host_same_src_port_rate",
"dst_host_srv_diff_host_rate",
"dst_host_serror_rate",
"dst_host_srv_serror_rate",
"dst_host_rerror_rate",
"dst_host_srv_rerror_rate",
"label",
"difficulty"

]

df.columns=columns


# ================= ENCODING =================

for col in ["protocol_type","service","flag"]:

    encoder=LabelEncoder()

    df[col]=encoder.fit_transform(
        df[col]
    )


# ================= ATTACK MAP =================

attack_map={

"normal":0,

"neptune":1,
"smurf":1,
"back":1,
"teardrop":1,

"satan":2,
"ipsweep":2,
"nmap":2,

"guess_passwd":3,

"buffer_overflow":4,
"rootkit":4

}

df["Label"]=df["label"].map(
    attack_map
)

df.dropna(inplace=True)

X=df.drop(
["label","difficulty","Label"],
axis=1
)

y=df["Label"]


# ================= MODEL =================

try:

    rf_model=joblib.load(
    "rf_model.pkl"
    )

    iso_model=joblib.load(
    "iso_model.pkl"
    )

    scaler=joblib.load(
    "scaler.pkl"
    )

    print("Models Loaded")

except:

    scaler=StandardScaler()

    X_scaled=scaler.fit_transform(X)

    X_train,X_test,y_train,y_test=(
    train_test_split(
    X_scaled,
    y,
    test_size=0.2,
    random_state=42
    )
    )

    rf_model=RandomForestClassifier(
    n_estimators=200
    )

    rf_model.fit(
    X_train,
    y_train
    )

    iso_model=IsolationForest(
    contamination=0.1
    )

    iso_model.fit(
    X_scaled
    )

    joblib.dump(
    rf_model,
    "rf_model.pkl"
    )

    joblib.dump(
    iso_model,
    "iso_model.pkl"
    )

    joblib.dump(
    scaler,
    "scaler.pkl"
    )


attack_names={

0:"Normal",
1:"DoS",
2:"Probe",
3:"R2L",
4:"U2R"

}


# ================= DETECT =================

def detect(sample):

    X_sample=sample.drop(
    ["label","difficulty","Label"],
    axis=1
    )

    X_scaled=scaler.transform(
    X_sample
    )

    rf_pred=rf_model.predict(
    X_scaled
    )[0]

    iso_pred=iso_model.predict(
    X_scaled
    )[0]

    anomaly=True if iso_pred==-1 else False

    return rf_pred,anomaly


# ================= LOGIN =================

@app.route("/")
def login_page():

    return render_template(
    "login.html"
    )


@app.route(
"/login",
methods=["POST"]
)
def login():

    cursor=db.cursor(
    dictionary=True
    )

    cursor.execute(
    """
    SELECT *
    FROM users
    WHERE username=%s
    AND password=%s
    AND role=%s
    """,

    (
    request.form["username"],
    request.form["password"],
    request.form["role"]
    )
    )

    user=cursor.fetchone()

    if user:

        session["user"]=user["username"]
        session["role"]=user["role"]

        if user["role"]=="admin":
            return redirect("/admin")

        return redirect("/dashboard")

    return "Invalid Login"


# ================= REGISTER =================

@app.route("/register_page")
def register_page():

    return render_template(
    "register.html"
    )


@app.route(
"/register",
methods=["POST"]
)
def register():

    cursor=db.cursor()

    cursor.execute(
    """
    INSERT INTO users
    (name,username,password,role)
    VALUES(%s,%s,%s,%s)
    """,

    (
    request.form["username"],
    request.form["username"],
    request.form["password"],
    request.form["role"]
    )
    )

    return redirect("/")


# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    return render_template(
    "index.html"
    )


# ================= MANUAL ATTACK =================

@app.route("/manual_attack")
def manual_attack():

    if "user" not in session:
        return redirect("/")

    return render_template(
    "manual_attack.html"
    )


@app.route(
"/predict_attack",
methods=["POST"]
)
def predict_attack():

    features=[]

    features.append(
    float(request.form.get(
    "duration",0))
    )

    features.append(
    float(request.form.get(
    "protocol_type",0))
    )

    features.append(
    float(request.form.get(
    "service",0))
    )

    features.append(
    float(request.form.get(
    "flag",0))
    )

    features.append(
    float(request.form.get(
    "src_bytes",0))
    )

    features.append(
    float(request.form.get(
    "dst_bytes",0))
    )

    while len(features)<41:
        features.append(0)

    sample=np.array([features])

    X_scaled=scaler.transform(
    sample
    )

    rf_pred=rf_model.predict(
    X_scaled
    )[0]

    iso_pred=iso_model.predict(
    X_scaled
    )[0]

    attack_type=attack_names.get(
    rf_pred,
    "Unknown"
    )

    if rf_pred!=0 or iso_pred==-1:
        result=f"⚠ Attack : {attack_type}"
    else:
        result="✅ Normal"

    return render_template(
    "manual_attack.html",
    result=result
    )


# ================= ADMIN =================

@app.route("/admin")
def admin():

    cursor=db.cursor(
    dictionary=True
    )

    cursor.execute(
    "SELECT * FROM users"
    )

    users=cursor.fetchall()

    return render_template(
    "admin.html",
    users=users
    )


# ================= REPORTS =================

@app.route("/reports")
def reports():

    cursor=db.cursor(
    dictionary=True
    )

    cursor.execute(
    """
    SELECT *
    FROM attack_logs
    ORDER BY id DESC
    """
    )

    logs=cursor.fetchall()

    return render_template(
    "reports.html",
    logs=logs
    )


# ================= REALTIME =================

thread=False

def stream():

    while True:

        sample=df.sample(1)

        pred,anomaly=detect(
        sample
        )

        attack=(
        pred!=0 or anomaly
        )

        data={

        "attack":int(attack),

        "status":
        "Attack"
        if attack
        else "Normal",

        "attack_type":
        attack_names[pred],

        "lat":
        random.uniform(-40,40),

        "lon":
        random.uniform(-120,120),

        "time":
        datetime.datetime.now().strftime(
        "%H:%M:%S"
        )
        }

        socketio.emit(
        "new_attack",
        data
        )

        socketio.sleep(5)


@socketio.on("connect")
def connect():

    global thread

    if not thread:

        socketio.start_background_task(
        stream
        )

        thread=True


# ================= LOGOUT =================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ================= RUN =================

app = app

if __name__ == "__main__":
    socketio.run(app, debug=True)