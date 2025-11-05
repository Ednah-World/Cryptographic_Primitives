# auth.py
"""
Authentication module used by both CLI and Flask web UI.

Provides:
- create_user(username, password, rounds)
- authenticate_user(username, password)
- demo_hashes_web(password) -> (hash1, hash2)
- brute_force_time(password, rounds) -> seconds
- parse_bcrypt_hash(hash_text) -> dict

Also keeps CLI register/login/demos for local terminal usage.
Requires: bcrypt
"""

import bcrypt
import json
import time
import os
import getpass
import re
from datetime import datetime
from typing import Dict, Any, Tuple

USERS_FILE = "users.json"
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 30
DELAY_ON_FAILURE = 1.5

# -------------------------
# Storage helpers
# -------------------------
def load_users() -> Dict[str, Any]:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        try:
            data = json.load(f)
            normalized = {}
            for user, val in data.items():
                if isinstance(val, str):
                    normalized[user] = {"hash": val, "failed_attempts": 0, "locked_until": 0}
                else:
                    normalized[user] = {
                        "hash": val.get("hash"),
                        "failed_attempts": val.get("failed_attempts", 0),
                        "locked_until": val.get("locked_until", 0),
                    }
            return normalized
        except json.JSONDecodeError:
            return {}

def save_users(users: Dict[str, Any]) -> None:
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# -------------------------
# bcrypt helpers
# -------------------------
def hash_password(password: str, rounds: int = 12) -> bytes:
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed

def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except ValueError:
        return False

# -------------------------
# Web-friendly wrapper functions
# -------------------------
def create_user(username: str, password: str, rounds: int = 12) -> Tuple[bool, str]:
    """
    Create a user programmatically (for web).
    Returns (success, message).
    """
    users = load_users()
    username = (username or "").strip()
    if not username:
        return False, "Username cannot be empty."

    if username in users:
        return False, "Username already exists."

    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters."

    try:
        rounds = int(rounds)
        if rounds < 4 or rounds > 31:
            rounds = 12
    except Exception:
        rounds = 12

    hashed = hash_password(password, rounds=rounds)
    users[username] = {
        "hash": hashed.decode("utf-8"),
        "failed_attempts": 0,
        "locked_until": 0
    }
    save_users(users)
    return True, "User created successfully."

def authenticate_user(username: str, password: str) -> Tuple[bool, str]:
    """
    Authenticate a user programmatically (for web).
    Returns (success, message).
    """
    users = load_users()
    username = (username or "").strip()
    if username not in users:
        return False, "User not found."

    user_record = users[username]

    # Lockout check
    locked_until = user_record.get("locked_until", 0)
    try:
        if time.time() < float(locked_until):
            return False, "Account is locked. Try later."
    except Exception:
        pass

    stored_hash = user_record.get("hash")
    if not stored_hash:
        return False, "Stored password missing or corrupted."

    if verify_password(password, stored_hash.encode("utf-8")):
        # reset counters
        user_record["failed_attempts"] = 0
        user_record["locked_until"] = 0
        users[username] = user_record
        save_users(users)
        return True, "Login successful."
    else:
        # failure handling
        user_record["failed_attempts"] = user_record.get("failed_attempts", 0) + 1
        users[username] = user_record
        save_users(users)
        attempts = user_record["failed_attempts"]
        if attempts >= LOCKOUT_THRESHOLD:
            user_record["locked_until"] = time.time() + LOCKOUT_SECONDS
            user_record["failed_attempts"] = 0
            users[username] = user_record
            save_users(users)
            return False, f"Too many attempts. Account locked for {LOCKOUT_SECONDS} seconds."
        else:
            return False, f"Invalid credentials. {LOCKOUT_THRESHOLD - attempts} attempts left."

# -------------------------
# Web-friendly demos / utils
# -------------------------
def demo_hashes_web(password: str) -> Tuple[str, str]:
    """
    Return two bcrypt hashes of the same password (as strings), demonstrating different salts.
    """
    h1 = hash_password(password)
    h2 = hash_password(password)
    return h1.decode("utf-8"), h2.decode("utf-8")

def brute_force_time(password: str, rounds: int = 12) -> float:
    """
    Time how long one bcrypt hash takes with given rounds. Returns seconds (float).
    """
    start = time.time()
    _ = hash_password(password, rounds=rounds)
    return time.time() - start

def parse_bcrypt_hash(hash_text: str) -> Dict[str, str]:
    """
    Parse a bcrypt hash into components where possible.
    Returns dict with algorithm, cost, salt, hash, or an error message.
    """
    out = {}
    if not hash_text or not hash_text.startswith("$2"):
        out["error"] = "Not a bcrypt-style hash."
        return out
    parts = hash_text.split("$")
    # ['', '2b', '12', 'saltandhash']
    if len(parts) < 4:
        out["error"] = "Unexpected bcrypt format."
        return out
    out["algorithm"] = parts[1]
    out["cost"] = parts[2]
    rest = parts[3]
    out["salt_and_hash"] = rest
    # try to split salt (22 chars) and hash (31 chars) if possible
    if len(rest) >= 53:
        out["salt"] = rest[:22]
        out["hash"] = rest[22:22+31]
    else:
        out["salt"] = rest[:22]
        out["hash"] = rest[22:] if len(rest) > 22 else ""
    return out

# -------------------------
# CLI functions kept for terminal use
# -------------------------
def password_strength_info(password: str):
    reasons = []
    score = 0
    if len(password) >= 8:
        score += 1
    else:
        reasons.append("Too short (>=8 chars recommended)")
    if re.search(r"[a-z]", password):
        score += 1
    else:
        reasons.append("No lowercase")
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        reasons.append("No uppercase")
    if re.search(r"\d", password):
        score += 1
    else:
        reasons.append("No digits")
    if re.search(r"[^\w\s]", password):
        score += 1
    else:
        reasons.append("No special chars")
    return {"score": score, "max_score": 5, "reasons": reasons}

def pretty_strength(password: str) -> str:
    info = password_strength_info(password)
    score = info["score"]
    bar = "[" + "#" * score + "-" * (info["max_score"] - score) + "]"
    text = f"{bar} {score}/{info['max_score']}"
    if info["reasons"]:
        text += "\n  Suggestions: " + "; ".join(info["reasons"])
    return text

# CLI register & login (unchanged)
def register():
    users = load_users()
    print("\n== Register New User ==")
    username = input("Enter a new username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    if username in users:
        print("❌ Username already exists.")
        return
    password = getpass.getpass("Enter password: ")
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("❌ Passwords do not match.")
        return
    print("\nPassword strength:")
    print(pretty_strength(password))
    proceed = input("Proceed with this password? (Y/n): ").strip().lower()
    if proceed == "n":
        print("Cancelled.")
        return
    rounds = 12
    try:
        rounds_input = input("Enter bcrypt cost factor (rounds) or press Enter to use 12: ").strip()
        if rounds_input:
            rounds = int(rounds_input)
            if rounds < 4 or rounds > 31:
                rounds = 12
    except ValueError:
        rounds = 12
    hashed = hash_password(password, rounds=rounds)
    users[username] = {"hash": hashed.decode("utf-8"), "failed_attempts": 0, "locked_until": 0}
    save_users(users)
    print(f"\n✅ User '{username}' registered successfully!")
    print("🔒 Stored bcrypt hash:")
    print(hashed)

def is_locked(user_record):
    locked_until = user_record.get("locked_until", 0)
    try:
        return time.time() < float(locked_until)
    except Exception:
        return False

def login():
    users = load_users()
    print("\n== Login ==")
    username = input("Username: ").strip()
    if username not in users:
        print("❌ User not found.")
        return False
    user_record = users[username]
    if is_locked(user_record):
        unlock_time = datetime.fromtimestamp(user_record["locked_until"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"⛔ Account locked due to multiple failed attempts. Try after: {unlock_time}")
        return False
    password = getpass.getpass("Password: ")
    stored_hash = user_record.get("hash")
    if stored_hash is None:
        print("Stored password is missing or corrupted.")
        return False
    success = verify_password(password, stored_hash.encode("utf-8"))
    if success:
        user_record["failed_attempts"] = 0
        user_record["locked_until"] = 0
        users[username] = user_record
        save_users(users)
        print("✅ Login successful! Welcome.")
        return True
    else:
        user_record["failed_attempts"] = user_record.get("failed_attempts", 0) + 1
        users[username] = user_record
        save_users(users)
        attempts = user_record["failed_attempts"]
        print("❌ Wrong password.")
        delay = min(DELAY_ON_FAILURE * attempts, 8.0)
        print(f"Please wait {delay:.1f} seconds before trying again.")
        time.sleep(delay)
        if attempts >= LOCKOUT_THRESHOLD:
            user_record["locked_until"] = time.time() + LOCKOUT_SECONDS
            user_record["failed_attempts"] = 0
            users[username] = user_record
            save_users(users)
            unlock_time = datetime.fromtimestamp(user_record["locked_until"]).strftime("%Y-%m-%d %H:%M:%S")
            print(f"🔒 Too many failed attempts. Account locked until {unlock_time} (for {LOCKOUT_SECONDS} seconds).")
        return False

if __name__ == "__main__":
    # CLI quick test loop
    while True:
        print("\n1) Register (CLI)  2) Login (CLI)  0) Quit")
        c = input("choice: ").strip()
        if c == "1":
            register()
        elif c == "2":
            login()
        elif c == "0":
            break
        else:
            print("Invalid")
