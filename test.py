import shutil
import os
from hash_utils import comp_sha256, save_hash_to_file, load_hash_from_file, verify_integrity, gen_fingerprint

def pretty_print(title, s=""):
    print(f"\n--- {title} ---")
    print(s)

def main():
    sample = "example.txt"
    with open(sample, "w", encoding="utf-8") as f:
        f.write("Demo filr for hashing and integrity")
    
    hex_digest, b64 = comp_sha256(sample)
    pretty_print("SHA-256 (hex)", hex_digest)
    pretty_print("SHA-256 (base64)", b64)

    hash_file = sample + ".sha256"
    save_hash_to_file(hex_digest, hash_file)
    print(f"\nSaved to {hash_file}")

    try:
        qr_path = gen_fingerprint(hex_digest, "eg_hash_qr_png")
        print(f"Fingerprint generated: {qr_path}")
    except Exception as e:
        print(f"QR code not installed:", e)

    os.makedirs("uploads/encrypted_files", exist_ok=True)
    encrypted_copy = os.path.join("uploads/encrypted_files", "example.enc")
    shutil.copyfile(sample, encrypted_copy)
    print(f"\nSimulated encryption: copied{sample} -> {encrypted_copy}")

    os.makedirs("uploads/decrypted_files", exist_ok=True)
    decrypted_copy = os.path.join("uploads/decrypted_files", "example_decrypted.txt")
    shutil.copyfile(encrypted_copy, decrypted_copy)
    print(f"\nSimulated decryption: copied{encrypted_copy} -> {decrypted_copy}")

    stored_hash = load_hash_from_file(hash_file)
    if verify_integrity(stored_hash, decrypted_copy):
        print("\nPASSED: file matches the original hash.")
    else:
        print("\nOh no, file DOESN'T match.")

    with open(decrypted_copy, "a") as f:
        f.write("\nAlert! Malicious line injected.\n")
    
    if verify_integrity(stored_hash, decrypted_copy):
        print("\nTamper test passed (it shouldn't happen btw)")
    else:
        print("\nTamper test FAILED.")

if __name__ == "__main__":
    main()