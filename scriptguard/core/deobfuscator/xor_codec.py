import string


def _looks_like_code(s: str) -> bool:
    keywords = [
        "http", "https", "powershell", "invoke",
        "function", "var ", "let ", "const ",
        "cmd.exe", "wscript", "createobject",
        "sub ", "dim "
    ]
    s_low = s.lower()
    return any(k in s_low for k in keywords)


def decode_xor(text: str) -> str:
    if len(text) < 20:
        return text

    # если это явно многострочный скрипт — не трогаем
    if "\n" in text and " " in text:
        return text

    best = text
    best_score = 0.0

    for key in range(1, 256):
        try:
            decoded = "".join(chr(ord(c) ^ key) for c in text)
        except Exception:
            continue

        if len(decoded) < 10:
            continue

        printable_ratio = sum(c in string.printable for c in decoded) / len(decoded)
        if printable_ratio < 0.85:
            continue

        if not _looks_like_code(decoded):
            continue

        score = printable_ratio
        dlow = decoded.lower()
        if "http" in dlow:
            score += 0.1
        if "powershell" in dlow or "cmd.exe" in dlow:
            score += 0.1

        if score > best_score:
            best = decoded
            best_score = score

    return best
