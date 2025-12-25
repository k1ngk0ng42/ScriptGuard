import base64
import re
import string


_PS_ENC_RE = re.compile(
    r'-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]+)',
    re.IGNORECASE
)


def _fix_padding(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _looks_like_powershell(s: str) -> bool:
    keywords = [
        "invoke", "iex", "download", "http",
        "new-object", "powershell", "cmd.exe",
        "wscript", "start-process"
    ]
    low = s.lower()
    return any(k in low for k in keywords)


def decode_powershell(text: str) -> str:
    matches = list(_PS_ENC_RE.finditer(text))
    if not matches:
        return text

    for m in matches:
        blob = m.group(1)

        try:
            fixed = _fix_padding(blob)
            decoded = base64.b64decode(fixed).decode("utf-16le", errors="ignore")
        except Exception:
            continue

        if len(decoded) < 10:
            continue

        printable_ratio = sum(c in string.printable for c in decoded) / len(decoded)
        if printable_ratio < 0.8:
            continue

        if not _looks_like_powershell(decoded):
            continue

        # аккуратно заменяем только найденный аргумент
        text = text.replace(m.group(0), decoded, 1)

    return text
