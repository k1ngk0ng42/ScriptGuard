import string
from typing import Optional

_PRINTABLE = set(string.printable)


def _rot_alpha(s: str, shift: int) -> str:
    res = []
    for c in s:
        o = ord(c)
        if 97 <= o <= 122:   # a-z
            res.append(chr((o - 97 - shift) % 26 + 97))
        elif 65 <= o <= 90:  # A-Z
            res.append(chr((o - 65 - shift) % 26 + 65))
        else:
            res.append(c)
    return "".join(res)


def _rot47(s: str) -> str:
    res = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            res.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c in _PRINTABLE for c in s) / len(s)


def _looks_like_code(s: str) -> bool:
    keywords = (
        "http", "https", "powershell", "invoke",
        "function", "var ", "let ", "const ",
        "cmd.exe", "wscript", "createobject",
        "sub ", "dim ", "new-object", "eval("
    )
    low = s.lower()
    return any(k in low for k in keywords)


def decode_rot(text: str) -> str:
    """
    Пробует ROT‑1 … ROT‑25 и ROT47.
    Возвращает лучший результат по score.
    """
    best: Optional[str] = None
    best_score = 0.0

    # ROT‑N (1–25)
    for shift in range(1, 26):
        decoded = _rot_alpha(text, shift)

        pr = _printable_ratio(decoded)
        if pr < 0.85:
            continue

        if not _looks_like_code(decoded):
            continue

        score = pr
        if score > best_score:
            best = decoded
            best_score = score

    # ROT47
    decoded47 = _rot47(text)
    pr47 = _printable_ratio(decoded47)

    if pr47 >= 0.85 and _looks_like_code(decoded47):
        if pr47 > best_score:
            best = decoded47
            best_score = pr47

    return best if best else text
