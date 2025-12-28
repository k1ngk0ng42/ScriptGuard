import string
import base64
from typing import List, Dict, Tuple, Optional

_PRINTABLE = set(string.printable)

# ключевой candidate для engine
class XORCandidate:
    def __init__(self, code: str, key: int, score: float):
        self.code = code
        self.key = key
        self.score = score


def _looks_like_code(s: str) -> bool:
    """Эвристика: содержит подозрительные ключевые слова"""
    keywords = [
        "http", "https", "powershell", "invoke",
        "function", "var ", "let ", "const ",
        "cmd.exe", "wscript", "createobject",
        "sub ", "dim ", "new-object", "eval(", "window"
    ]
    low = s.lower()
    return any(k in low for k in keywords)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c in _PRINTABLE for c in s) / len(s)


def decode_xor(text: str, max_candidates: int = 3) -> str:
    """
    Попытка XOR-декодирования текста.
    Поддерживает single-byte и rolling XOR.
    Возвращает лучший результат для engine.
    """
    best_candidate: Optional[XORCandidate] = None

    data = text.encode(errors="ignore")

    for key in range(1, 256):
        try:
            # single-byte XOR
            decoded_bytes = bytes(b ^ key for b in data)
            decoded = decoded_bytes.decode(errors="ignore")
        except Exception:
            continue

        if _printable_ratio(decoded) < 0.85:
            continue
        if not _looks_like_code(decoded):
            continue

        score = _printable_ratio(decoded)
        if best_candidate is None or score > best_candidate.score:
            best_candidate = XORCandidate(decoded, key, score)

    # fallback: rolling XOR (key repeated over text)
    if best_candidate is None and len(data) > 1:
        for key in range(1, 256):
            try:
                decoded_bytes = bytes(data[i] ^ key for i in range(len(data)))
                decoded = decoded_bytes.decode(errors="ignore")
            except Exception:
                continue

            if _printable_ratio(decoded) < 0.85:
                continue
            if not _looks_like_code(decoded):
                continue

            score = _printable_ratio(decoded)
            if best_candidate is None or score > best_candidate.score:
                best_candidate = XORCandidate(decoded, key, score)

    return best_candidate.code if best_candidate else text
