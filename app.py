import os
import io
import bcrypt
import pyotp
import qrcode
from flask import Flask, render_template_string, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==========================================
# 1. DATABASE MODEL
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    twofactor_secret = db.Column(db.String(32), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
# 2. STANDALONE HTML TEMPLATES (No Extensions)
# ==========================================
REGISTER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Registration</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <main style="max-width: 500px; margin: 40px auto; padding: 20px;">
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for msg in messages %}
              <blockquote style="border-left: 4px solid #ff4757; background: #ffe3e3; color: #ff4757; padding: 10px;">{{ msg }}</blockquote>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <h2>User Registration</h2>
        <form method="POST">
            <label>Email:</label>
            <input type="email" name="email" required placeholder="name@example.com">
            <label>Password:</label>
            <input type="password" name="password" minlength="8" required placeholder="Min 8 characters">
            <button type="submit">Sign Up</button>
        </form>
        <p>Already registered? <a href="{{ url_for('login') }}">Login here</a></p>
    </main>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Login</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <main style="max-width: 500px; margin: 40px auto; padding: 20px;">
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for msg in messages %}
              <blockquote style="border-left: 4px solid #ff4757; background: #ffe3e3; color: #ff4757; padding: 10px;">{{ msg }}</blockquote>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <h2>Secure Login</h2>
        <form method="POST">
            <label>Email:</label>
            <input type="email" name="email" required placeholder="name@example.com">
            <label>Password:</label>
            <input type="password" name="password" required placeholder="Your password">
            <button type="submit">Login</button>
        </form>
        <p>New user? <a href="{{ url_for('register') }}">Create an account</a></p>
    </main>
</body>
</html>
"""

TWOFACTOR_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Two-Factor Authentication</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <main style="max-width: 500px; margin: 40px auto; padding: 20px;">
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for msg in messages %}
              <blockquote style="border-left: 4px solid #ff4757; background: #ffe3e3; color: #ff4757; padding: 10px;">{{ msg }}</blockquote>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <h2>Two-Factor Authentication (2FA)</h2>
        <p>1. Scan this QR code using <b>Google Authenticator</b> or any TOTP app:</p>
        <div style="text-align: center; margin: 20px 0;">
            <img src="{{ url_for('get_qr') }}" alt="2FA QR Code" style="background: white; padding: 15px; border: 1px solid #ddd; border-radius: 4px;">
        </div>
        <hr>
        <form method="POST" action="{{ url_for('verify_2fa') }}">
            <label>2. Enter the 6-digit code from your app:</label>
            <input type="text" name="otp_code" maxlength="6" pattern="\\d{6}" required placeholder="123456" autocomplete="off" style="text-align: center; font-size: 1.2rem; letter-spacing: 4px;">
            <button type="submit" style="width: 100%; margin-top: 10px;">Verify & Log In</button>
        </form>
    </main>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <main style="max-width: 500px; margin: 40px auto; padding: 20px;">
        <h2>🔐 Secure Dashboard</h2>
        <p>You have successfully logged in using a secure authentication pipeline.</p>
        <p>Logged in as: <strong>{{ current_user.email }}</strong></p>
        <br>
        <a href="{{ url_for('logout') }}"><button style="background: #ff4757; color: white; border: none; padding: 10px 20px; cursor: pointer;">Secure Logout</button></a>
    </main>
</body>
</html>
"""

# ==========================================
# 3. ROUTES & LOGIC
# ==========================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        if not email or len(password) < 8:
            flash('Fields cannot be empty and password must be at least 8 characters long.')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        secret_key = pyotp.random_base32()

        new_user = User(email=email, password_hash=hashed_pw, twofactor_secret=secret_key)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template_string(REGISTER_HTML)

pending_2fa_users = {}

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            session_id = os.urandom(16).hex()
            pending_2fa_users[session_id] = user.id
            
            response = redirect(url_for('verify_2fa'))
            response.set_cookie('2fa_session', session_id, httponly=True)
            return response
        else:
            flash('Invalid email or password.')
            return redirect(url_for('login'))

    return render_template_string(LOGIN_HTML)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    session_id = request.cookies.get('2fa_session')
    user_id = pending_2fa_users.get(session_id)

    if not user_id:
        flash('Session expired or invalid token.')
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        totp = pyotp.TOTP(user.twofactor_secret)

        if totp.verify(otp_code):
            login_user(user)
            pending_2fa_users.pop(session_id, None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code. Please check again.')

    return render_template_string(TWOFACTOR_HTML)

@app.route('/qr-code')
def get_qr():
    session_id = request.cookies.get('2fa_session')
    user_id = pending_2fa_users.get(session_id)
    if not user_id:
        return "Unauthorized Access", 401

    user = User.query.get(user_id)
    totp = pyotp.TOTP(user.twofactor_secret)
    provisioning_url = totp.provisioning_uri(name=user.email, issuer_name="SecureLoginApp")
    
    img = qrcode.make(provisioning_url)
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Successfully logged out safely.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=False, port=5050)
