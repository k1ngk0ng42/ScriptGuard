import base64
import gzip
import re
from typing import Optional


_BASE64_RE = re.compile(
    r'(?:[A-Za-z0-9+/]{20,}={0,2})'
)


def _try_decode(blob: bytes) -> Optional[str]:
    """
    Пытается:
    - utf‑8
    - utf‑16le
    - gzip → utf‑8 / utf‑16le
    """
    # plain utf‑8
    try:
        return blob.decode("utf-8")
    except Exception:
        pass

    # plain utf‑16le (PowerShell)
    try:
        return blob.decode("utf-16le")
    except Exception:
        pass

    # gzip → utf‑8 / utf‑16le
    try:
        decompressed = gzip.decompress(blob)
        try:
            return decompressed.decode("utf-8")
        except Exception:
            return decompressed.decode("utf-16le", errors="ignore")
    except Exception:
        pass

    return None


def _looks_useful(s: str) -> bool:
    """
    Минимальная эвристика полезности.
    """
    if not s or len(s) < 10:
        return False

    low = s.lower()
    return any(k in low for k in (
        "http", "https", "powershell", "invoke",
        "function", "cmd.exe", "wscript",
        "createobject", "new-object", "eval("
    ))


def decode_base64(text: str) -> str:
    """
    Ищет base64 внутри текста, пытается декодировать,
    выбирает лучший результат.
    """
    best = text
    best_len = 0

    for match in _BASE64_RE.finditer(text):
        b64 = match.group(0)

        # padding fix
        padded = b64 + "=" * ((4 - len(b64) % 4) % 4)

        try:
            raw = base64.b64decode(padded)
        except Exception:
            continue

        decoded = _try_decode(raw)
        if not decoded:
            continue

        if not _looks_useful(decoded):
            continue

        if len(decoded) > best_len:
            best = text.replace(b64, decoded)
            best_len = len(decoded)

    return best
