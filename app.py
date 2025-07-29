import joblib
from flask import Flask, render_template, request, redirect, jsonify, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import mysql.connector
from flask_cors import CORS

from datetime import datetime

def generate_safety_tips(weather, road, risk_label):
    tips = []

    # Risk-level based
    if risk_label == "High Risk":
        tips.append("⚠️ High risk detected. Drive cautiously and reduce speed.")
    else:
        tips.append("✅ Low risk. Continue practicing safe driving habits.")

    # Weather-specific
    if weather == "rainy":
        tips.append("🌧️ It's rainy. Turn on headlights and maintain a safe distance.")
    elif weather == "foggy":
        tips.append("🌫️ Fog detected. Use fog lights, and avoid overtaking.")
    elif weather == "clear":
        tips.append("☀️ Clear weather. Ideal for travel, but stay alert.")

    # Road condition-specific
    if road == "wet":
        tips.append("🛞 Wet roads ahead. Brake gently to avoid skidding.")
    elif road == "damp":
        tips.append("💧 Damp roads may still be slippery. Drive with caution.")
    elif road == "dry":
        tips.append("🛣️ Dry road. Good traction, but remain within speed limits.")

    return " ".join(tips)



app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = "accitrack_2025_secret_key_for_sessions"

# Load trained model and encoders
model = joblib.load("accident_prediction_model.pkl")
weather_encoder = joblib.load("weather_encoder.pkl")
road_encoder = joblib.load("road_conditions_encoder.pkl")
location_encoder = joblib.load("location_encoder.pkl")
time_encoder = joblib.load("time_encoder.pkl")

# DB connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="acci_track",
    ssl_disabled=True,  
    autocommit=True
)
cursor = db.cursor(dictionary=True)

# ---------------- AUTH ----------------
@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        return jsonify({'message': 'Login successful', 'role': user['role']})
    return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/signup', methods=['POST'])
def signup_submit():
    try:
        data = request.json
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password')
        access_code = data.get('access_code', '').strip()

        # Basic validation
        if not all([username, email, password, access_code]):
            return jsonify({'error': 'All fields are required.'}), 400

        if access_code != "Admin2025":
            return jsonify({'error': 'Invalid admin access code'}), 403

        # Check for existing email
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already exists'}), 409

        hashed_password = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO users (username, email, password, role, is_blocked, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (username, email, hashed_password, 'admin', 0, 'active'))

        db.commit()
        return jsonify({'message': 'Admin account created successfully'}), 201

    except Exception as e:
        import traceback
        traceback.print_exc()  
        return jsonify({'error': 'Server error occurred. Check terminal for details.'}), 500


# ---------------- PREDICTION ----------------
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    try:
        required_fields = ['weather', 'road_conditions', 'location', 'time', 'day_of_week', 'victim_unharmed']
        for field in required_fields:
            val = data.get(field)
            if val is None or str(val).strip().lower() in ["", "nan", "none"]:
                return jsonify({"error": f"Missing or invalid value for field: {field}"}), 400

        # Encode input values
        weather = weather_encoder.transform([data['weather'].strip().lower()])[0]
        road = road_encoder.transform([data['road_conditions'].strip().lower()])[0]
        location = location_encoder.transform([data['location'].strip().lower()])[0]
        victim_unharmed = 1 if data['victim_unharmed'].strip().lower() == 'yes' else 0

        time_raw = str(data['time']).strip()
        if not time_raw.isdigit() or len(time_raw) not in [1, 2]:
            return jsonify({"error": "Invalid time format, must be hour like '13'"}), 400

        time_encoded = time_encoder.transform([time_raw.zfill(2)])[0]
        hour = int(time_raw)
        day_of_week = int(data['day_of_week'])

        # Prepare features and predict
        features = [[
            weather, road, hour, location, day_of_week,
            time_encoded, victim_unharmed
        ]]

        prob = model.predict_proba(features)[0][1]        
        prediction = model.predict(features)[0]
        confidence = float(prob)                         
        risk_label = "High Risk" if confidence >= 0.5 else "Low Risk"

        # Save prediction result to DB
        cursor.execute("""
            INSERT INTO prediction_results 
            (weather, road_conditions, location, hour, day_of_week, victim_unharmed, prediction, confidence, risk_label)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['weather'],
            data['road_conditions'],
            data['location'],
            hour,
            day_of_week,
            victim_unharmed,
            int(prediction),
            confidence,
            risk_label
        ))
        db.commit()

        # Get coordinates from `locations` table (fix column name match)
        cursor.execute("""
            SELECT latitude, longitude
            FROM locations
            WHERE location_name = %s
        """, (data['location'],))  
        coords = cursor.fetchone() or {'latitude': None, 'longitude': None}

        return jsonify({
            "prediction": int(prediction),
            "confidence": round(confidence, 2),
            "message": risk_label,
            "location": data['location'],
            "lat": coords['latitude'],
            "lon": coords['longitude']
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- LOCATION API ----------------
@app.route('/location_stats')
def location_stats():
    cursor.execute("SELECT `Barangay/Location`, COUNT(*) as total FROM combined GROUP BY `Barangay/Location`")
    return jsonify(cursor.fetchall())

@app.route('/api/locations')
def api_locations():
    cursor = db.cursor(dictionary=True) 
    cursor.execute("SELECT DISTINCT `Barangay/Location` FROM combined ORDER BY `Barangay/Location`")
    results = cursor.fetchall()
    cursor.close() 
    return jsonify([row['Barangay/Location'] for row in results])


# returns all known locations + their coords
@app.route('/api/location-coords')
def api_location_coords():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT location_name, latitude, longitude FROM locations")
    rows = cursor.fetchall()
    cursor.close()
    return jsonify(rows)


@app.route('/api/heatmap-data')
def heatmap_data():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT location_name, latitude, longitude FROM locations WHERE latitude IS NOT NULL AND longitude IS NOT NULL")
    data = cursor.fetchall()
    cursor.close()
    return jsonify(data)



# ---------------- DASHBOARDS ----------------
@app.route('/')
def login_page():
    return render_template('login.html')


@app.route('/user_dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        return "Access denied", 403

    cursor.execute("SELECT COUNT(*) AS total FROM prediction_results")
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS high FROM prediction_results WHERE risk_label = 'High Risk'")
    high = cursor.fetchone()['high']

    cursor.execute("SELECT COUNT(*) AS low FROM prediction_results WHERE risk_label = 'Low Risk'")
    low = cursor.fetchone()['low']

    user_id = session.get('user_id')
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    username = user['email'] if user else 'User'

     # Get latest prediction made today
    cursor.execute("""
        SELECT weather, road_conditions, location, hour, confidence, risk_label, created_at
        FROM prediction_results
        WHERE DATE(created_at) = CURDATE()
        ORDER BY created_at DESC
        LIMIT 1
    """)
    latest_prediction = cursor.fetchone()

    safety_tips = None
    if latest_prediction:
        created_at = latest_prediction["created_at"]
        
        # Format hour as 12-hour time with AM/PM
        formatted_hour = created_at.strftime("%I:%M %p")  

        latest_prediction["formatted_hour"] = formatted_hour

        weather = latest_prediction['weather']
        road = latest_prediction['road_conditions']
        risk = latest_prediction['risk_label']

        safety_tips = generate_safety_tips(weather, road, risk)
    return render_template(
        'user_dashboard.html',
        total=total,
        high=high,
        low=low,
        username=username,
        latest=latest_prediction,
        safety_tips=safety_tips
    )


@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return "Access denied", 403

    cursor.execute("SELECT COUNT(*) AS total FROM prediction_results")
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS high FROM prediction_results WHERE risk_label = 'High Risk'")
    high = cursor.fetchone()['high']

    cursor.execute("SELECT COUNT(*) AS low FROM prediction_results WHERE risk_label = 'Low Risk'")
    low = cursor.fetchone()['low']

    # Get today's latest prediction with day_of_week
    cursor.execute("""
        SELECT weather, road_conditions, location, hour, confidence, risk_label, created_at
        FROM prediction_results
        WHERE DATE(created_at) = CURDATE()
        ORDER BY created_at DESC
        LIMIT 1
    """)
    latest_prediction = cursor.fetchone()

    safety_tips = None
    if latest_prediction:
        created_at = latest_prediction["created_at"]
        formatted_hour = created_at.strftime("%I:%M %p")  
        latest_prediction["formatted_hour"] = formatted_hour

        weather = latest_prediction['weather']
        road = latest_prediction['road_conditions']
        risk = latest_prediction['risk_label']

        safety_tips = generate_safety_tips(weather, road, risk)

    return render_template(
        'admin_dashboard.html',
        total=total,
        high=high,
        low=low,
        latest=latest_prediction,
        safety_tips=safety_tips
    )





@app.route('/history')
def history():
    if session.get('role') != 'admin':
        return "Access denied", 403

    cursor.execute("""
        SELECT id, weather, road_conditions, location, hour, day_of_week, victim_unharmed, prediction, confidence, risk_label, created_at
        FROM prediction_results
        ORDER BY created_at DESC
    """)
    history_data = cursor.fetchall()

    return render_template('history.html', history=history_data)

@app.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect('/login')

    admin_id = session['user_id']

    if request.method == 'POST':
        new_email = request.form['email']
        new_password = request.form['password']

        if new_password.strip():
            hashed_pw = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET email = %s, password = %s WHERE id = %s", (new_email, hashed_pw, admin_id))
        else:
            cursor.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, admin_id))

        db.commit()
        return redirect('/admin_profile')

    cursor.execute("SELECT email FROM users WHERE id = %s", (admin_id,))
    admin = cursor.fetchone()
    return render_template('admin_profile.html', email=admin['email'])


@app.route('/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect('/login')

    user_id = session['user_id']

    if request.method == 'POST':
        new_email = request.form['email']
        new_password = request.form['password']

        if new_password.strip() != "":
            hashed_pw = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET email = %s, password = %s WHERE id = %s", (new_email, hashed_pw, user_id))
        else:
            cursor.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, user_id))

        db.commit()
        return redirect('/profile')

    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    return render_template('profile.html', email=user['email'])

# -------------------------------------------------------------------------------
@app.route('/users')
def manage_users():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, email, role, status FROM users")
    users = cursor.fetchall()
    success = request.args.get('success')  
    return render_template('manage_users.html', users=users, success=success)


@app.route('/users/update/<int:user_id>', methods=['POST'])
def update_user(user_id):
    email = request.form['email']
    role = request.form['role']
    status = request.form['status']
    cursor = db.cursor()
    cursor.execute("UPDATE users SET email=%s, role=%s, status=%s WHERE id=%s",
                   (email, role, status, user_id))
    db.commit()
    return redirect(url_for('manage_users'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    db.commit()
    return redirect(url_for('manage_users'))

from werkzeug.security import generate_password_hash

@app.route('/users/add', methods=['POST'])
def add_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    status = request.form.get('status', 'active')

    hashed_pw = generate_password_hash(password)

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO users (username, email, password, role, status)
        VALUES (%s, %s, %s, %s, %s)
    """, (username, email, hashed_pw, role, status))
    db.commit()
    return redirect(url_for('manage_users', success='User added successfully'))



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ---------------- RUN SERVER ----------------
if __name__ == '__main__':
    app.run(debug=True)
