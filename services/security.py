import io
import hmac
import time
import base64
import struct
import random
import hashlib
import secrets
import qrcode
import qrcode.image.svg

WEAK_PASSWORDS = {
    "password", "password1!", "password123!", "qwerty123!", "qwertyui1!",
    "admin123!", "12345678a!", "12345678aa!", "welcome1!"
}


def hash_password(password: str, salt: str = None) -> str:
    iterations = 600000
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, iter_str, salt, hex_digest = stored_hash.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iter_str)
        )
        return hmac.compare_digest(dk.hex(), hex_digest)
    except Exception:
        return False


def validate_password_policy(password: str, username: str = "") -> tuple[bool, list[str]]:
    errors = []
    if len(password) < 8:
        errors.append("Довжина пароля має бути не менше 8 символів.")
    if not (any(c.isupper() for c in password) and any(c.islower() for c in password)):
        errors.append("Пароль має містити великі та малі літери.")
    if not any(c.isdigit() for c in password):
        errors.append("Пароль має містити хоча б одну цифру.")
    if not any(not c.isalnum() for c in password):
        errors.append("Пароль має містити спеціальний символ (не літеру і не цифру).")

    low = password.lower()
    if low in WEAK_PASSWORDS or "123456" in low or "qwerty" in low or "password" in low:
        errors.append("Пароль занадто простий або поширений.")
    if username and len(username) >= 3 and username.lower() in low:
        errors.append("Пароль не повинен містити логін користувача.")

    return len(errors) == 0, errors


def generate_totp_secret(length: int = 16) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_totp_token(secret: str, time_step: int = 30, offset: int = 0) -> str:
    key = base64.b32decode(secret.upper(), casefold=True)
    counter = int(time.time() // time_step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    pos = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[pos:pos + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    clean = code.strip().replace(" ", "")
    for step in (-1, 0, 1):
        if hmac.compare_digest(get_totp_token(secret, offset=step), clean):
            return True
    return False


def generate_qr_svg_data_uri(data: str) -> str:
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(data, image_factory=factory, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def generate_captcha_svg() -> tuple[str, str]:
    chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    code = "".join(secrets.choice(chars) for _ in range(5))
    w, h = 180, 50
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
        f'style="background:#f1f5f9; border:1px solid #cbd5e1; border-radius:4px;">'
    ]
    for _ in range(5):
        x1, y1 = random.randint(0, w), random.randint(0, h)
        x2, y2 = random.randint(0, w), random.randint(0, h)
        parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#94a3b8" stroke-width="1.2"/>')

    for i, ch in enumerate(code):
        x = 20 + i * 30 + random.randint(-2, 2)
        y = 33 + random.randint(-4, 4)
        rot = random.randint(-18, 18)
        parts.append(
            f'<text x="{x}" y="{y}" fill="#1e293b" font-family="monospace" font-size="24" font-weight="bold" '
            f'transform="rotate({rot} {x} {y})">{ch}</text>'
        )
    parts.append("</svg>")
    b64 = base64.b64encode("".join(parts).encode("utf-8")).decode("ascii")
    return code, f"data:image/svg+xml;base64,{b64}"
