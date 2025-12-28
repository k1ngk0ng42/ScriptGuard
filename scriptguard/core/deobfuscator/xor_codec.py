import string
from typing import List


_PRINTABLE = set(string.printable)


class XORCandidate:
    __slots__ = ("code", "key", "score")

    def __init__(self, code: str, key: int, score: float):
        self.code = code
        self.key = key
        self.score = score


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


def decode_xor(text: str, max_candidates: int = 5) -> List[str]:
    """
    XOR single‑byte brute‑force.
    Возвращает TOP‑N кандидатов для engine.
    """
    if len(text) < 20:
        return []

    candidates: List[XORCandidate] = []

    data = text.encode(errors="ignore")

    for key in range(1, 256):
        try:
            decoded_bytes = bytes(b ^ key for b in data)
            decoded = decoded_bytes.decode(errors="ignore")
        except Exception:
            continue

        pr = _printable_ratio(decoded)
        if pr < 0.85:
            continue

        if not _looks_like_code(decoded):
            continue

        score = pr
        candidates.append(XORCandidate(decoded, key, score))

    if not candidates:
        return []

    candidates.sort(key=lambda c: c.score, reverse=True)

    return [c.code for c in candidates[:max_candidates]]
