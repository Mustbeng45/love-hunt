import os, json, base64, getpass, sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

if __name__ == "__main__":
    # Cek apakah user memberikan file teks sebagai argumen
    if len(sys.argv) < 2:
        print("Usage: python3 encrypt_message.py <nama_file_pesan.txt>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File {file_path} tidak ditemukan.")
        sys.exit(1)

    # Baca isi file
    with open(file_path, "r", encoding="utf-8") as f:
        message = f.read().strip()

    print(f"Pesan yang akan dienkripsi ({len(message)} karakter):")
    print("-" * 50)
    print(message)
    print("-" * 50)

    password = getpass.getpass("Set password (kode yang akan kamu taruh di kado): ").strip()
    confirm = getpass.getpass("Ulangi password: ").strip()

    if password != confirm:
        raise SystemExit("Password tidak sama. Coba lagi.")

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(message.encode("utf-8"))

    payload = {
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
        "ciphertext_b64": token.decode("utf-8"),
    }

    with open("secret.json", "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)

    print("Pesan terenkripsi sudah disimpan di secret.json ✅")
