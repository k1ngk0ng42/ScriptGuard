import base64
import re
import string


_BASE64_RE = re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b')


def _looks_like_code(s: str) -> bool:
    keywords = [
        "function", "var ", "let ", "const ",
        "powershell", "invoke", "object",
        "sub ", "dim ", "createobject"
    ]
    s_low = s.lower()
    return any(k in s_low for k in keywords)


def decode_base64(text: str) -> str:
    for match in _BASE64_RE.finditer(text):
        blob = match.group(0)

        try:
            decoded = base64.b64decode(blob).decode("utf-8", errors="ignore")
        except Exception:
            continue

        if len(decoded) < 8:
            continue

        printable_ratio = sum(c in string.printable for c in decoded) / len(decoded)
        if printable_ratio < 0.85:
            continue

        if not _looks_like_code(decoded):
            continue

        text = text.replace(blob, decoded, 1)

    return text
