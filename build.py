"""בונה את index.html של "צוות הסוכנים" מתוך src/.

נתוני הסוכנים מוצפנים (AES-GCM, מפתח מ-PBKDF2) ונפתחים רק בדפדפן עם הסיסמה,
כדי שאפשר יהיה לארח את הדף בכתובת ציבורית בלי לחשוף מספרים של העסק.

    python3 build.py "<סיסמה>"

**המקור חייב להישאר בריפו.** בפעם הקודמת הוא היה רק בתיקייה זמנית ואבד,
ואז כל שינוי קטן דרש לפענח את הדף החי כדי לשחזר אותו.
"""

import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent
ITER = 200_000
PASSWORD = sys.argv[1] if len(sys.argv) > 1 else "dinamo2026"


def encrypt(plaintext: str, password: str) -> str:
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt,
                     iterations=ITER).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + iv + ct).decode("ascii")


def main():
    agents = json.loads((ROOT / "src" / "agents.json").read_text(encoding="utf-8"))
    payload = json.dumps(agents, ensure_ascii=False, separators=(",", ":"))
    shell = (ROOT / "src" / "shell.html").read_text(encoding="utf-8")

    html = (shell
            .replace("__CIPHER__", encrypt(payload, PASSWORD))
            .replace("__ITER__", str(ITER)))
    (ROOT / "index.html").write_text(html, encoding="utf-8")

    by_status = {}
    for a in agents:
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
    print(f"  {len(agents)} סוכנים · {by_status}")
    print(f"  index.html: {len(html):,} תווים")


if __name__ == "__main__":
    main()
