import os
import cv2
import sqlite3
import hashlib
from datetime import datetime
from ultralytics import YOLO
from flask import Flask, request, jsonify, render_template, send_from_directory, session
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "pothole.db")
USERS_DB_PATH = os.path.join(BASE_DIR, "users.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

app = Flask(__name__)
app.secret_key = "secret123"
CORS(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

model = YOLO(os.path.join(BASE_DIR, "best.pt"))


# ----------------------------
# Create Detection Database Table
# ----------------------------
def init_detection_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        pothole_count INTEGER,
        severity TEXT,
        avg_area REAL,
        max_area REAL,
        severity_score REAL,
        latitude REAL,
        longitude REAL,
        detected_at TEXT,
        status TEXT DEFAULT 'Active'
    )
    """)

    # ✅ FIXED: now inside function
    cursor.execute("PRAGMA table_info(detections)")
    columns = [col[1] for col in cursor.fetchall()]

    if "latitude" not in columns:
        cursor.execute("ALTER TABLE detections ADD COLUMN latitude REAL")

    if "longitude" not in columns:
        cursor.execute("ALTER TABLE detections ADD COLUMN longitude REAL")

    if "status" not in columns:
        cursor.execute("ALTER TABLE detections ADD COLUMN status TEXT DEFAULT 'Active'")

    if "avg_area" not in columns:
        cursor.execute("ALTER TABLE detections ADD COLUMN avg_area REAL")

    if "max_area" not in columns:
        cursor.execute("ALTER TABLE detections ADD COLUMN max_area REAL")

    if "severity_score" not in columns:
        cursor.execute("ALTER TABLE detections ADD COLUMN severity_score REAL")

    conn.commit()
    conn.close()

# ----------------------------
# Create Settings Table
# ----------------------------
def init_settings_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            theme TEXT DEFAULT 'Dark Mode',
            show_severe_alerts INTEGER DEFAULT 1,
            auto_refresh INTEGER DEFAULT 1
        )
    """)

    cursor.execute("SELECT COUNT(*) FROM settings")
    count = cursor.fetchone()[0]

    if count == 0:
        cursor.execute("""
            INSERT INTO settings (theme, show_severe_alerts, auto_refresh)
            VALUES ('Dark Mode', 1, 1)
        """)

    conn.commit()
    conn.close()


# ----------------------------
# Create Users Database Table
# ----------------------------
def init_users_db():
    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    conn.commit()
    conn.close()


init_detection_db()
init_settings_db()
init_users_db()


# ----------------------------
# Home Page
# ----------------------------
@app.route("/")
def home():
    return render_template("home.html")


# ----------------------------
# Signup Page
# ----------------------------
@app.route("/signup-page")
def signup_page():
    return render_template("signup.html")


# ----------------------------
# Signup API
# ----------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."})

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        conn = sqlite3.connect(USERS_DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, hashed_password)
        )

        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Signup successful."})

    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Email already exists."})
    except Exception:
        return jsonify({"success": False, "message": "Signup failed."})


# ----------------------------
# Login Page
# ----------------------------
@app.route("/login")
def login_page():
    return render_template("login.html")


# ----------------------------
# Login API
# ----------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."})

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email=? AND password=?",
        (email, hashed_password)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        session["user"] = user[1]
        session["email"] = user[2]
        return jsonify({"success": True, "message": "Login successful."})
    else:
        return jsonify({"success": False, "message": "Invalid email or password."})


# ----------------------------
# Logout
# ----------------------------
@app.route("/logout")
def logout():
    session.clear()
    return render_template("login.html")


# ----------------------------
# Forgot Password Page
# ----------------------------
@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")


# ----------------------------
# Forgot Password API
# ----------------------------
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")

    if not email:
        return jsonify({"success": False, "message": "Email is required."})

    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    conn.close()

    if user:
        return jsonify({
            "success": True,
            "redirect": f"/reset-password/{email}"
        })
    else:
        return jsonify({
            "success": False,
            "message": "Email not found."
        })


# ----------------------------
# Reset Password Page
# ----------------------------
@app.route("/reset-password/<email>")
def reset_password_page(email):
    return render_template("reset_password.html", email=email)


# ----------------------------
# Reset Password API
# ----------------------------
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."})

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, email))
    conn.commit()

    if cursor.rowcount > 0:
        conn.close()
        return jsonify({"success": True, "message": "Password updated successfully."})
    else:
        conn.close()
        return jsonify({"success": False, "message": "Email not found."})


# ----------------------------
# Upload Page
# ----------------------------
@app.route("/upload")
def upload_page():
    return render_template(
        "upload.html",
        user=session.get("user"),
        email=session.get("email")
    )


# ----------------------------
# Analytics Page
# ----------------------------
@app.route("/analytics")
def analytics():
    return render_template(
        "analytics.html",
        user=session.get("user"),
        email=session.get("email")
    )


# ----------------------------
# Dashboard Page
# ----------------------------
@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT SUM(pothole_count) FROM detections WHERE status='Active'")
    total = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM detections WHERE severity='High' AND status='Active'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT pothole_count, avg_area, severity_score FROM detections WHERE status='Active'")
    rows = cursor.fetchall()

    total_reports = len(rows)

    if total_reports > 0:
        avg_severity_score = sum((r[2] or 0) for r in rows) / total_reports
        avg_area = sum((r[1] or 0) for r in rows) / total_reports
        pothole_density = total / total_reports
        unresolved_ratio = 1.0
    else:
        avg_severity_score = 0
        avg_area = 0
        pothole_density = 0
        unresolved_ratio = 0

    road_health, health_status = calculate_rhi(total, avg_severity_score, avg_area, unresolved_ratio)

    accident_score, accident_risk = calculate_accident_risk(
        critical, avg_severity_score, pothole_density, unresolved_ratio, road_health
    )

    cursor.execute("""
        SELECT id, filename, pothole_count, severity, latitude, longitude, detected_at, status
        FROM detections
        WHERE status='Active'
        ORDER BY id DESC
        LIMIT 5
    """)
    recent = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        critical=critical,
        road_health=road_health,
        health_status=health_status,
        accident_risk=accident_risk,
        accident_risk_score=accident_score,
        show_severe_alerts=True,
        recent=recent,
        user=session.get("user"),
        email=session.get("email")
    )
# ----------------------------
# Reports Page
# ----------------------------
@app.route("/reports")
def reports():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, filename, pothole_count, severity, latitude, longitude, detected_at, status
        FROM detections
        ORDER BY detected_at DESC
    """)
    report_data = cursor.fetchall()

    total_reports = len(report_data)
    total_potholes = sum(int(row[2]) for row in report_data) if report_data else 0
    avg_potholes = round(total_potholes / total_reports, 2) if total_reports > 0 else 0

    severity_counts = {"Low": 0, "Medium": 0, "High": 0}
    for row in report_data:
        if row[3] in severity_counts:
            severity_counts[row[3]] += 1

    common_severity = "N/A"
    if total_reports > 0:
        common_severity = max(severity_counts, key=severity_counts.get)

    conn.close()

    return render_template(
        "reports.html",
        report_data=report_data,
        total_reports=total_reports,
        avg_potholes=avg_potholes,
        common_severity=common_severity,
        user=session.get("user"),
        email=session.get("email")
    )


# ----------------------------
# Generate Report Page
# ----------------------------
@app.route("/generate-report")
def generate_report():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, filename, pothole_count, severity, latitude, longitude, detected_at, status
        FROM detections
        ORDER BY detected_at DESC
    """)
    report_data = cursor.fetchall()

    total_reports = len(report_data)
    total_potholes = sum(int(row[2]) for row in report_data) if report_data else 0
    avg_potholes = round(total_potholes / total_reports, 2) if total_reports > 0 else 0

    severity_counts = {"Low": 0, "Medium": 0, "High": 0}
    for row in report_data:
        if row[3] in severity_counts:
            severity_counts[row[3]] += 1

    common_severity = "N/A"
    if total_reports > 0:
        common_severity = max(severity_counts, key=severity_counts.get)

    conn.close()

    return render_template(
        "reports.html",
        report_data=report_data,
        total_reports=total_reports,
        avg_potholes=avg_potholes,
        common_severity=common_severity,
        user=session.get("user"),
        email=session.get("email")
    )


# ----------------------------
# Resolve Single Pothole
# ----------------------------
@app.route("/resolve-pothole/<int:report_id>", methods=["POST"])
def resolve_pothole(report_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE detections
            SET status='Resolved'
            WHERE id=?
        """, (report_id,))

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Pothole marked as resolved."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        })


# ----------------------------
# Map Page
# ----------------------------
@app.route("/map")
def map_page():
    return render_template("map.html")


# ----------------------------
# Settings Page
# ----------------------------
@app.route("/settings")
def settings():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT theme, show_severe_alerts, auto_refresh
        FROM settings
        ORDER BY id DESC
        LIMIT 1
    """)
    row = cursor.fetchone()
    conn.close()

    settings_data = {
        "theme": row[0] if row else "Dark Mode",
        "show_severe_alerts": bool(row[1]) if row else True,
        "auto_refresh": bool(row[2]) if row else True
    }

    return render_template(
        "settings.html",
        settings=settings_data,
        user=session.get("user"),
        email=session.get("email")
    )
# ----------------------------
# Alert
# ----------------------------
@app.route("/alerts")
def alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, filename, pothole_count, severity, latitude, longitude, detected_at, status
        FROM detections
        WHERE severity='High' AND status='Active'
        ORDER BY detected_at DESC
    """)
    alert_data = cursor.fetchall()

    conn.close()

    return render_template(
        "alerts.html",
        alert_data=alert_data,
        user=session.get("user"),
        email=session.get("email")
    )
# ----------------------------
# Save Settings API
# ----------------------------
@app.route("/save-settings", methods=["POST"])
def save_settings():
    data = request.get_json()

    theme = data.get("theme", "Dark Mode")
    show_severe_alerts = 1 if data.get("show_severe_alerts", True) else 0
    auto_refresh = 1 if data.get("auto_refresh", True) else 0

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE settings
            SET theme=?, show_severe_alerts=?, auto_refresh=?
            WHERE id = (SELECT id FROM settings ORDER BY id DESC LIMIT 1)
        """, (theme, show_severe_alerts, auto_refresh))

        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Settings saved successfully."})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


# ----------------------------
# Reset Dashboard Data API
# ----------------------------
@app.route("/reset-dashboard-data", methods=["POST"])
def reset_dashboard_data():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM detections")

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Dashboard data reset successfully."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        })




# ----------------------------
# Preprocessing
# ----------------------------

def preprocess_image(input_path, output_path):
    img = cv2.imread(input_path)

    if img is None:
        return False

    # Optional resize for very large images
    height, width = img.shape[:2]
    max_width = 1280

    if width > max_width:
        scale = max_width / width
        new_width = int(width * scale)
        new_height = int(height * scale)
        img = cv2.resize(img, (new_width, new_height))

    # Convert to LAB color space for CLAHE
    lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
    l, a, b = cv2.split(lab)

    # Apply CLAHE on lightness channel
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    l = clahe.apply(l)

    # Merge channels back
    enhanced_lab = cv2.merge((l, a, b))
    enhanced_img = cv2.cvtColor(enhanced_lab, cv2.COLOR_LAB2BGR)

    # Slight noise reduction
    final_img = cv2.GaussianBlur(enhanced_img, (3, 3), 0)

    cv2.imwrite(output_path, final_img)
    print("Preprocessing completed. Saved to:", output_path)
    return True





# ================== RHI CALCULATIONS ==================

def calculate_rhi(total_potholes, avg_severity_score, avg_area, unresolved_ratio):
    norm_count = min(total_potholes / 20, 1.0)
    norm_severity = min(avg_severity_score / 1.0, 1.0)
    norm_area = min(avg_area / 20000, 1.0)
    norm_unresolved = min(unresolved_ratio, 1.0)

    damage_score = (
        0.30 * norm_count +
        0.35 * norm_severity +
        0.20 * norm_area +
        0.15 * norm_unresolved
    )

    rhi = max(0, 100 - (damage_score * 100))

    if rhi >= 75:
        status = "Good"
    elif rhi >= 50:
        status = "Moderate"
    else:
        status = "Poor"

    return round(rhi, 2), status


# ================== ACCIDENT RISK CALCULATIONS ==================

def calculate_accident_risk(high_count, avg_severity_score, pothole_density, unresolved_ratio, rhi):
    norm_high = min(high_count / 10, 1.0)
    norm_severity = min(avg_severity_score / 1.0, 1.0)
    norm_density = min(pothole_density / 15, 1.0)
    norm_unresolved = min(unresolved_ratio, 1.0)
    norm_rhi_inverse = 1 - min(rhi / 100, 1.0)

    risk_score = (
        0.30 * norm_high +
        0.25 * norm_severity +
        0.20 * norm_density +
        0.15 * norm_unresolved +
        0.10 * norm_rhi_inverse
    )

    if risk_score < 0.35:
        risk_level = "Low"
    elif risk_score < 0.65:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return round(risk_score, 3), risk_level











# ----------------------------
# Detection API
# ----------------------------
@app.route("/detect", methods=["POST"])
def detect():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file uploaded."})

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"success": False, "message": "No selected file."})

    latitude = request.form.get("latitude")
    longitude = request.form.get("longitude")

    latitude = float(latitude) if latitude else None
    longitude = float(longitude) if longitude else None

    # Save original uploaded file
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Preprocess image
    preprocessed_filename = "pre_" + file.filename
    preprocessed_path = os.path.join(UPLOAD_FOLDER, preprocessed_filename)

    preprocessing_success = preprocess_image(filepath, preprocessed_path)

    if not preprocessing_success:
        return jsonify({"success": False, "message": "Image preprocessing failed."})

    # Run YOLO on preprocessed image
    results = model(preprocessed_path)

    boxes = results[0].boxes
    areas = []

    for box in boxes:
        x1, y1, x2, y2 = box.xyxy[0].tolist()
        width = max(0, x2 - x1)
        height = max(0, y2 - y1)
        area = width * height
        areas.append(area)

    count = len(areas)


    if count == 0:
        severity = "None"
        severity_score = 0
        avg_area = 0
        max_area = 0
    else:
        avg_area = sum(areas) / count
        max_area = max(areas)

        norm_count = min(count / 8, 1.0)
        norm_avg = min(avg_area / 18000, 1.0)
        norm_max = min(max_area / 25000, 1.0)

        severity_score = (0.5 * norm_count) + (0.2 * norm_avg) + (0.3 * norm_max)

    if severity_score < 0.45:
        severity = "Low"
    elif severity_score < 0.75:
        severity = "Medium"
    else:
        severity = "High"


    # Save annotated result image
    annotated = results[0].plot()
    result_filename = "result_" + file.filename
    result_path = os.path.join(UPLOAD_FOLDER, result_filename)
    cv2.imwrite(result_path, annotated)

   

    # Save detection data to database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO detections (
        filename, pothole_count, severity,
        avg_area, max_area, severity_score,
        latitude, longitude, detected_at, status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    file.filename,
    count,
    severity,
    avg_area,
    max_area,
    severity_score,
    latitude,
    longitude,
    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "Active"
))

    conn.commit()
    conn.close()

    return jsonify({
    "success": True,
    "potholes": count,
    "severity": severity,
    "severity_score": round(severity_score, 3),
    "avg_area": int(avg_area),
    "max_area": int(max_area),
    "image": "uploads/" + result_filename,
    "original_image": "uploads/" + file.filename,
    "preprocessed_image": "uploads/" + preprocessed_filename,
    "latitude": latitude,
    "longitude": longitude,
    "status": "Active"
})


# ----------------------------
# Single Report Details API
# ----------------------------
@app.route("/report/<int:report_id>")
def get_report(report_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, filename, pothole_count, severity, latitude, longitude, detected_at, status
        FROM detections
        WHERE id = ?
    """, (report_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "Report not found"})

    if row[3] == "High":
        priority = "Immediate"
    elif row[3] == "Medium":
        priority = "Scheduled"
    else:
        priority = "Monitor"

    return jsonify({
        "success": True,
        "id": row[0],
        "filename": row[1],
        "pothole_count": row[2],
        "severity": row[3],
        "priority": priority,
        "latitude": row[4],
        "longitude": row[5],
        "detected_at": row[6],
        "status": row[7],
        "image": "/uploads/result_" + row[1]
    })


# ----------------------------
# Map Data API
# ----------------------------
@app.route("/map-data")
def map_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, filename, pothole_count, severity, latitude, longitude, detected_at, status
        FROM detections
        WHERE latitude IS NOT NULL
          AND longitude IS NOT NULL
          AND status='Active'
        ORDER BY detected_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "id": row[0],
            "filename": row[1],
            "pothole_count": row[2],
            "severity": row[3],
            "latitude": row[4],
            "longitude": row[5],
            "detected_at": row[6],
            "status": row[7]
        })

    return jsonify(result)


# ----------------------------
# Stats API
# ----------------------------
@app.route("/stats")
def stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT SUM(pothole_count) FROM detections WHERE status='Active'")
    total = cursor.fetchone()[0]
    total = total if total else 0

    cursor.execute("SELECT COUNT(*) FROM detections WHERE severity='High' AND status='Active'")
    critical = cursor.fetchone()[0]

    road_health = max(0, 100 - (total * 2))

    if road_health > 70:
        health_status = "Good"
    elif road_health > 40:
        health_status = "Medium"
    else:
        health_status = "Poor"

    if critical > 10:
        accident_risk = "High"
    elif critical > 5:
        accident_risk = "Medium"
    else:
        accident_risk = "Low"

    cursor.execute("""
        SELECT id, filename, pothole_count, severity, latitude, longitude, detected_at, status
        FROM detections
        WHERE status='Active'
        ORDER BY id DESC
        LIMIT 5
    """)
    recent = cursor.fetchall()

    conn.close()

    return jsonify({
        "total": total,
        "critical": critical,
        "road_health": road_health,
        "health_status": health_status,
        "accident_risk": accident_risk,
        "recent": recent
    })


# ----------------------------
# Serve Uploaded Files
# ----------------------------
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ----------------------------
# Run App
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)