from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"  # replace in production

# Database setup (SQLite)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)

with app.app_context():
    db.create_all()

# --- Helper/demo functions ---
def demo_hashes_web(password: str):
    h1 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    h2 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return h1.decode('utf-8'), h2.decode('utf-8')

def brute_force_time(password: str, rounds: int = 12):
    start = time.time()
    _ = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=rounds))
    return time.time() - start

def parse_bcrypt_hash(hash_text: str):
    out = {}
    if not hash_text or not hash_text.startswith("$2"):
        out["error"] = "Not a valid bcrypt hash (must start with $2...)."
        return out
    parts = hash_text.split("$")
    if len(parts) < 4:
        out["error"] = "Unexpected bcrypt format (too few $ parts)."
        return out
    out["algorithm"] = parts[1]
    out["cost"] = parts[2]
    rest = parts[3]
    out["salt_and_hash"] = rest
    if len(rest) >= 53:
        out["salt"] = rest[:22]
        out["hash"] = rest[22:22+31]
    else:
        out["salt"] = rest[:22]
        out["hash"] = rest[22:] if len(rest) > 22 else ""
    return out

# --- Routes ---
@app.route('/')
def home():
    return render_template('index.html')

# registration/login/dashboard/logout unchanged (kept for brevity)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Please enter username and password.", "error")
            return redirect(url_for('register'))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already exists.", "error")
            return redirect(url_for('register'))

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username=username, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful — please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Please enter username and password.", "error")
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('login'))

        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            session['username'] = username
            flash("Login successful.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Incorrect password.", "error")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have logged out.", "success")
    return redirect(url_for('home'))

# --- Demo routes (robust) ---
@app.route('/demo_hashes', methods=['GET', 'POST'])
def demo_hashes():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        print("DEBUG demo_hashes POST received, password present?", bool(password))
        if password == '':
            flash("Enter a password to demo.", "error")
            return redirect(url_for('demo_hashes'))
        h1, h2 = demo_hashes_web(password)
        result = {'h1': h1, 'h2': h2}
        print("DEBUG demo_hashes produced:", result['h1'][:20], "...")
    return render_template('demo_hashes.html', result=result)

@app.route('/demo_bruteforce', methods=['GET', 'POST'])
def demo_bruteforce():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        rounds_raw = request.form.get('rounds', '')
        try:
            rounds = int(rounds_raw) if rounds_raw else 12
        except ValueError:
            rounds = 12
        print("DEBUG demo_bruteforce POST received: rounds=", rounds, "password present?", bool(password))
        if password == '':
            flash("Enter a password to time.", "error")
            return redirect(url_for('demo_bruteforce'))
        secs = brute_force_time(password, rounds=rounds)
        result = {'rounds': rounds, 'seconds': secs}
        print("DEBUG brute force time:", secs)
    return render_template('demo_bruteforce.html', result=result)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    parsed = None
    if request.method == 'POST':
        h = request.form.get('hashtext', '').strip()
        print("DEBUG analyze received:", bool(h))
        if not h:
            flash("Please paste a bcrypt hash to analyze.", "error")
            return redirect(url_for('analyze'))
        parsed = parse_bcrypt_hash(h)
        print("DEBUG analyze parsed:", parsed.get('error') if parsed.get('error') else "ok")
    return render_template('analyze.html', parsed=parsed)

if __name__ == "__main__":
    app.run(debug=True)
