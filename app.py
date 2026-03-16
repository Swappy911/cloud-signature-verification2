from flask import Flask, render_template, request, redirect, url_for, session
import os
import json
import datetime
import cv2
import numpy as np

app = Flask(__name__)
app.secret_key = "integrity_cloud_vault_2026"

# File paths for SaaS persistence
UPLOAD_FOLDER = "uploads"
USER_DATA_FILE = "users.json"
HISTORY_DATA_FILE = "history.json"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# --- SAAS PERSISTENCE HELPERS ---
def load_data(file_path, default_value):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                return json.load(f)
            except:
                return default_value
    return default_value


def save_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)


# Initialize global databases
USER_DB = load_data(USER_DATA_FILE, {
    "admin@example.com": {"username": "admin", "password": "admin123", "role": "admin"}
})
history = load_data(HISTORY_DATA_FILE, [])


# --- SIGNATURE COMPARISON ENGINE ---
def compare_signatures(sig1_path, sig2_path):
    img1 = cv2.imread(sig1_path, 0)
    img2 = cv2.imread(sig2_path, 0)
    if img1 is None or img2 is None: return 0

    img1 = cv2.resize(img1, (300, 300))
    img2 = cv2.resize(img2, (300, 300))

    res = cv2.matchTemplate(img1, img2, cv2.TM_CCOEFF_NORMED)
    _, max_val, _, _ = cv2.minMaxLoc(res)
    return round(max(0, max_val * 100), 2)


# --- AUTHENTICATION ROUTES ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("username")
        password = request.form.get("password")
        for email, data in USER_DB.items():
            if (email == identifier or data['username'] == identifier) and data['password'] == password:
                session["logged_in"] = True
                session["user"] = data['username']
                session["role"] = data["role"]
                session["login_time"] = datetime.datetime.now().strftime("%H:%M:%S")
                return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        if email not in USER_DB:
            USER_DB[email] = {"username": username, "password": password, "role": "user"}
            save_data(USER_DATA_FILE, USER_DB)
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- CORE FUNCTIONALITY ---
@app.route("/")
def home():
    if not session.get("logged_in"): return redirect(url_for("login"))
    return render_template("index.html", result=None)


@app.route("/verify", methods=["POST"])
def verify():
    if not session.get("logged_in"): return redirect(url_for("login"))

    doc = request.files.get("document")
    sig = request.files.get("signature")
    if not doc or not sig: return redirect(url_for("home"))

    doc_path = os.path.join(app.config["UPLOAD_FOLDER"], doc.filename)
    sig_path = os.path.join(app.config["UPLOAD_FOLDER"], sig.filename)
    doc.save(doc_path)
    sig.save(sig_path)

    # SAAS METRIC: Track Storage Used (File Sizes in KB)
    storage_kb = round((os.path.getsize(doc_path) + os.path.getsize(sig_path)) / 1024, 2)
    similarity = compare_signatures(doc_path, sig_path)

    # Threshold: 60% accommodates human signing variance
    result = "valid" if similarity >= 60 else "invalid"

    history.append({
        "user": session.get("user"),
        "document": doc.filename,
        "result": result,
        "similarity": f"{similarity}%",
        "storage": f"{storage_kb} KB",
        "session_start": session.get("login_time", "N/A"),
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    save_data(HISTORY_DATA_FILE, history)
    return render_template("index.html", result=result, similarity=similarity)


# --- USER DASHBOARD ---
@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"): return redirect(url_for("login"))

    role = session.get("role")

    # Filter history based on role
    if role == "admin":
        display_history = history[::-1]
    else:
        display_history = [h for h in history if h.get("user") == session.get("user")][::-1]

    # Calculate storage and stats
    u_storage_kb = sum([float(h.get('storage', '0 KB').split()[0]) for h in display_history])

    stats = {
        "storage_mb": round(u_storage_kb / 1024, 2),
        "total_files": len(display_history),
        "valid": len([h for h in display_history if h.get("result") == "valid"]),
        "uptime": "99.99%"
    }
    return render_template("dashboard.html", stats=stats, history=display_history)


# --- FLAGSHIP ADMIN CONTROL PANEL ---
@app.route("/admin_panel")
def admin_panel():
    if not session.get("logged_in") or session.get("role") != "admin":
        return redirect(url_for("login"))

    # Global Analytics
    total_kb = sum([float(h.get('storage', '0 KB').split()[0]) for h in history])
    total_mb = round(total_kb / 1024, 2)

    # Process Tenant Database with Billing estimates
    tenants = []
    for email, data in USER_DB.items():
        user_storage_kb = sum(
            [float(h.get('storage', '0 KB').split()[0]) for h in history if h.get('user') == data['username']])
        est_bill = round(5.00 + (user_storage_kb * 0.05), 2)
        tenants.append({
            "email": email,
            "username": data['username'],
            "role": data['role'],
            "bill": f"${est_bill}"
        })

    stats = {
        "storage_mb": total_mb,
        "storage_pct": min(100, round((total_mb / 512) * 100, 1)),  # Goal: 512MB
        "cpu_usage": 34,  # Simulated
        "ram_usage": 61,
        "total_users": len(USER_DB),
        "global_hashes": len(history),
        "tamper_alerts": len([h for h in history if h.get('result') == 'invalid'])
    }

    return render_template("admin_panel.html", stats=stats, tenants=tenants)


if __name__ == "__main__":
    app.run(debug=True)