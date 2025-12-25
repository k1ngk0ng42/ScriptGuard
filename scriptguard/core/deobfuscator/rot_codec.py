import string


def _looks_like_code(s: str) -> bool:
    keywords = [
        "function", "var ", "let ", "const ",
        "powershell", "invoke", "object",
        "sub ", "dim ", "createobject",
        "http", "https", "cmd", "wscript"
    ]
    s_low = s.lower()
    return any(k in s_low for k in keywords)


def _rot(s: str, n: int) -> str:
    result = []
    for c in s:
        if c.isalpha():
            a = 'a' if c.islower() else 'A'
            result.append(chr((ord(c) - ord(a) + n) % 26 + ord(a)))
        else:
            result.append(c)
    return "".join(result)


def decode_rot(text: str) -> str:
    best = text

    for n in range(1, 26):
        candidate = _rot(text, n)

        printable_ratio = sum(c in string.printable for c in candidate) / len(candidate)
        if printable_ratio < 0.85:
            continue

        if _looks_like_code(candidate):
            best = candidate
            break

    return best
