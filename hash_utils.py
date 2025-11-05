import hashlib
import base64
import os

def comp_sha256(file_path, chunk_size=4096):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    hex_digest = sha256.hexdigest()
    b64_digest = base64.b64encode(sha256.digest()).decode("ascii")
    return hex_digest, b64_digest

def verify_integrity(orig_hex_digest, file_path, chunk_size=4096):
    current_hex, _ = comp_sha256(file_path, chunk_size)
    return current_hex == orig_hex_digest

def save_hash_to_file(hex_digest, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True) if os.path.dirname(out_path) else None
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(hex_digest)

def load_hash_from_file(in_path):
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Hash file not found: {in_path}")
    with open(in_path, "r", encoding="utf-8")as f:
        return f.read().strip()
    
def gen_fingerprint(hex_digest, output_path="hash_qr.png"):
    try:
        import qrcode
    except ImportError as e:
        raise ImportError("qrcode package not installed. Install with: pip install qrcode[pil]") from e
    
    qr =qrcode.QRCode(box_size=6, border=2)
    qr.add_data(hex_digest)
    qr.make(fit=True)
    img =qr.make_image()
    img.save(output_path)
    return output_path