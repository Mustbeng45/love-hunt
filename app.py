import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import json, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# =========================
# App setup
# =========================
app = Flask(__name__)

# Pakai SECRET_KEY dari environment (aman untuk production).
# Saat lokal, jika belum diset, fallback ke nilai dev (ganti ya!).
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-this")

# =========================
# Data & helpers
# =========================
def load_riddles():
    """Load daftar riddle dari riddles.json."""
    try:
        with open("riddles.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list) or len(data) == 0:
                raise ValueError("riddles.json harus berupa list dan tidak kosong.")
            return data
    except FileNotFoundError:
        raise SystemExit("File riddles.json tidak ditemukan. Pastikan file ada di folder project.")
    except json.JSONDecodeError as e:
        raise SystemExit(f"Format riddles.json tidak valid: {e}")

RIDDLES = load_riddles()
TOTAL = len(RIDDLES)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive kunci simetris dari password dengan PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def try_decrypt(ciphertext_b64: str, salt_b64: str, password: str) -> str:
    """Coba decrypt. Jika gagal (password salah), return string kosong."""
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        return f.decrypt(ciphertext_b64.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""

def norm(s: str) -> str:
    return (s or "").strip().lower()

# =========================
# Routes
# =========================
@app.route("/")
def index():
    # Inisialisasi progress di session jika belum ada
    session.setdefault("progress", 0)
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start():
    # Mulai ulang progress dari 0
    session["progress"] = 0
    return redirect(url_for("riddle", num=1))

@app.route("/riddle/<int:num>", methods=["GET", "POST"])
def riddle(num: int):
    # Validasi nomor riddle
    if num < 1 or num > TOTAL:
        return "Not found", 404

    progress = session.get("progress", 0)

    # Cegah skip (tidak pakai flash agar tidak ada pesan selain salah)
    if num > progress + 1:
        return redirect(url_for("riddle", num=progress + 1))

    r = RIDDLES[num - 1]

    if request.method == "POST":
        answer = norm(request.form.get("answer"))
        if answer == norm(r["answer"]):
            # Update progress
            session["progress"] = num
            # Kalau belum terakhir → langsung ke riddle berikutnya tanpa pesan
            if num < TOTAL:
                return redirect(url_for("riddle", num=num + 1))
            # Kalau sudah terakhir → ke halaman sukses
            return redirect(url_for("success"))
        else:
            # HANYA tampilkan pesan ketika salah
            flash("Jawaban salah, coba lagi!")

    return render_template("riddle.html", num=num, total=TOTAL, r=r)

@app.route("/success")
def success():
    # Jangan izinkan akses jika belum menyelesaikan semua riddle
    if session.get("progress", 0) < TOTAL:
        return redirect(url_for("riddle", num=session.get("progress", 0) + 1))
    return render_template("success.html")

@app.route("/message", methods=["GET", "POST"])
def message():
    # Baca payload terenkripsi
    try:
        with open("secret.json", "r", encoding="utf-8") as f:
            payload = json.load(f)
    except FileNotFoundError:
        # Beri pesan jelas jika secret.json belum dibuat
        return (
            "<h3>secret.json tidak ditemukan.</h3>"
            "<p>Jalankan <code>python3 encrypt_message.py pesan.txt</code> untuk membuatnya.</p>",
            500,
        )
    except json.JSONDecodeError as e:
        return (f"<h3>secret.json rusak/format salah:</h3><pre>{e}</pre>", 500)

    revealed = ""
    error = ""
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        revealed = try_decrypt(payload.get("ciphertext_b64", ""), payload.get("salt_b64", ""), password)
        if not revealed:
            error = "Password salah 🗝️"

    return render_template("message.html", revealed=revealed, error=error)

# =========================
# Run server (prod-friendly)
# =========================
if __name__ == "__main__":
    # Platform hosting memberi PORT via env; fallback 5001 untuk lokal
    port = int(os.environ.get("PORT", "5001"))
    # Bind ke 0.0.0.0 agar bisa diakses oleh platform
    app.run(host="0.0.0.0", port=port, debug=False)
