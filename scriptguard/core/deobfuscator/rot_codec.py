import string


_PRINTABLE = string.printable


def _rot_alpha(s: str, shift: int) -> str:
    res = []
    for c in s:
        o = ord(c)
        if 97 <= o <= 122:  # a-z
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
    return sum(c in _PRINTABLE for c in s) / max(len(s), 1)


def _looks_like_code(s: str) -> bool:
    keywords = [
        "http", "https", "powershell", "invoke",
        "function", "var ", "let ", "const ",
        "cmd.exe", "wscript", "createobject",
        "sub ", "dim ", "new-object"
    ]
    low = s.lower()
    return any(k in low for k in keywords)


def _score(s: str) -> float:
    pr = _printable_ratio(s)
    score = pr * 0.6

    if _looks_like_code(s):
