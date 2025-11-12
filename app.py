from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from hash_utils import comp_sha256, save_hash_to_file, load_hash_from_file, verify_integrity, gen_fingerprint
from flask import send_from_directory
from crypto_utils import (
    generate_rsa_keypair,
    handle_upload_and_encrypt,
    handle_decrypt_and_verify,
    list_encrypted_files,
    KEYS_DIR,
    ENCRYPTED_DIR  # <-- add this
)
import bcrypt
import os
import time
from Crypto.PublicKey import RSA
from werkzeug.utils import secure_filename
from crypto_utils import (
    generate_rsa_keypair,
    handle_upload_and_encrypt,
    handle_decrypt_and_verify,
    list_encrypted_files,
    KEYS_DIR,
)


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

# Route to generate RSA keypair (one-time, protected in real app)
@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys():
    if 'username' not in session:
        flash("Please log in to generate keys.", "error")
        return redirect(url_for('login'))

    try:
        os.makedirs('keys', exist_ok=True)

        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Save to files
        with open("keys/rsa_private.pem", "wb") as priv_file:
            priv_file.write(private_key)
        with open("keys/rsa_public.pem", "wb") as pub_file:
            pub_file.write(public_key)

        flash("RSA keypair generated successfully!", "success")
    except Exception as e:
        flash(f"Could not generate keys: {e}", "error")

    # Redirect back to the homepage (not dashboard)
    return redirect(url_for('home'))
# Upload + encrypt route (available to logged-in users)
@app.route('/upload_encrypt', methods=['GET', 'POST'])
def upload_encrypt():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part.", "error")
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash("No selected file.", "error")
            return redirect(request.url)

        safe_name = secure_filename(file.filename)
        meta = handle_upload_and_encrypt(file, filename=safe_name)
        # You could store meta in DB for the user (filename, paths, fingerprint, etc.)
        flash(f"File encrypted and saved as {meta['encrypted_filename']}. SHA-256: {meta['fingerprint_sha256']}", "success")
        return redirect(url_for('dashboard'))

    return render_template('upload_encrypt.html')


# List encrypted files
@app.route('/files')
def files():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    all_files = list_encrypted_files()  # call the function!

    if not all_files:
        files_meta = []
    else:
        # Sort by modified time in ENCRYPTED_DIR
        all_files_full_paths = [
            os.path.join(ENCRYPTED_DIR, f + ".enc") for f in all_files
        ]
        latest_file_path = max(all_files_full_paths, key=os.path.getmtime)
        latest_file = os.path.basename(latest_file_path)[:-4]  # remove .enc
        files_meta = [{"name": latest_file, "method": "AES"}]  # adjust method if needed

    return render_template('files.html', files=files_meta)

# Decrypt file route (downloads decrypted file)
@app.route('/decrypt/<filename>', methods=['GET', 'POST'])
def decrypt(filename):
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # method selection can be used in the future
        method = request.form.get('method', 'AES')
        try:
            result = handle_decrypt_and_verify(filename)
            flash(f"Decryption completed. Verified: {result['verified']}. SHA-256: {result['decrypted_hash']}", "success")
        except FileNotFoundError:
            flash("Encrypted file or key not found.", "error")
        except ValueError:
            flash("Decryption failed or authentication tag mismatch.", "error")

        return redirect(url_for('files'))

    # GET request → show decrypt page
    return render_template('decrypt.html', filename=filename)

@app.route("/hash_file", methods=["GET", "POST"])
def hash_file():
    result = None
    if request.method == "POST":
        file = request.files['file']
        if file:
            path = os.path.join("uploads/hash_inputs", file.filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            file.save(path)

            # Compute SHA-256
            hex_digest, b64_digest = comp_sha256(path)
            hash_file_path = path + ".sha256"
            save_hash_to_file(hex_digest, hash_file_path)

            result = {
                "filename": file.filename,
                "hex": hex_digest,
                "b64": b64_digest,
                "hash_file": hash_file_path
            }
    return render_template("hash_file.html", result=result)

# Route: verify integrity (upload file and provide hex or choose saved .sha256)
@app.route('/verify_file', methods=['GET', 'POST'])
def verify_file():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    HASH_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "hash_inputs")
    os.makedirs(HASH_UPLOAD_DIR, exist_ok=True)

    verify_result = None
    if request.method == 'POST':
        f = request.files.get('file')
        hex_input = request.form.get('hex_digest', '').strip()
        saved_path = request.form.get('saved_hash_path', '').strip()

        if not f and not hex_input and not saved_path:
            flash("Please upload a file or provide a hex digest / .sha256 file.", "error")
            return redirect(request.url)

        # Save uploaded file if any
        if f and f.filename != '':
            fname = secure_filename(f.filename)
            dest = os.path.join(HASH_UPLOAD_DIR, "verify_" + fname)
            f.save(dest)
            file_to_check = dest
        else:
            file_to_check = None

        # Determine hex to compare
        if saved_path:
            try:
                if not os.path.isabs(saved_path):
                    saved_path = os.path.join(BASE_DIR, saved_path)
                orig_hex = load_hash_from_file(saved_path)
            except Exception as e:
                flash(f"Could not load saved hash: {e}", "error")
                return redirect(request.url)
        elif hex_input:
            orig_hex = hex_input
        else:
            if file_to_check:
                # compute hash from uploaded file
                orig_hex = comp_sha256(file_to_check)[0]
            else:
                flash("No hex digest provided.", "error")
                return redirect(request.url)

        # Verify integrity
        if file_to_check:
            ok = verify_integrity(orig_hex, file_to_check)
        else:
            flash("No file to verify.", "error")
            return redirect(request.url)

        verify_result = {"ok": ok, "expected": orig_hex}
        flash("Verification complete.", "success" if ok else "error")

    return render_template('verify_file.html', result=verify_result)

# Route: generate QR / fingerprint from hex (typed or uploaded file)
@app.route('/fingerprint', methods=['GET', 'POST'])
def fingerprint():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    HASH_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "hash_inputs")
    os.makedirs(HASH_UPLOAD_DIR, exist_ok=True)

    qr_path = None
    if request.method == 'POST':
        f = request.files.get('file')
        hex_input = request.form.get('hex_digest', '').strip()
        saved_path = request.form.get('saved_hash_path', '').strip()

        if not f and not hex_input and not saved_path:
            flash("Please upload a file or enter a hex digest.", "error")
            return redirect(request.url)

        # Compute SHA-256 if a file is uploaded
        if f and f.filename != '':
            fname = secure_filename(f.filename)
            dest = os.path.join(HASH_UPLOAD_DIR, "fp_" + fname)
            f.save(dest)
            hex_digest = comp_sha256(dest)[0]
        elif hex_input:
            hex_digest = hex_input
        elif saved_path:
            try:
                if not os.path.isabs(saved_path):
                    saved_path = os.path.join(BASE_DIR, saved_path)
                hex_digest = load_hash_from_file(saved_path)
            except Exception as e:
                flash(f"Could not load saved hash: {e}", "error")
                return redirect(request.url)
        else:
            flash("Cannot determine hex digest.", "error")
            return redirect(request.url)

        # Generate QR code
        try:
            qr_path = gen_fingerprint(hex_digest, output_path=os.path.join("static", "hash_qr.png"))
            flash("QR fingerprint generated.", "success")
        except Exception as e:
            flash(f"Could not generate QR: {e}", "error")

    return render_template('fingerprint.html', qr_path=qr_path)

@app.route('/download/<path:filename>')
def download_file(filename):
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    encrypted_dir = os.path.join(BASE_DIR, 'uploads', 'encrypted')
    file_path = os.path.join(encrypted_dir, filename)

    if not os.path.exists(file_path):
        flash("File not found.", "error")
        return redirect(url_for('files'))

    # This actually sends the file
    return send_from_directory(encrypted_dir, filename, as_attachment=True)
if __name__ == "__main__":
    app.run(debug=True)
