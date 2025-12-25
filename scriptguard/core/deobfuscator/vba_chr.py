import re

_CHR_RE = re.compile(r'\bChrW?\(([^)]+)\)', re.IGNORECASE)
_ASC_RE = re.compile(r'\bAsc\("([^"])"\)', re.IGNORECASE)
_CONCAT_RE = re.compile(r'"([^"]*)"\s*&\s*"([^"]*)"')


def _safe_eval(expr: str):
    try:
        if re.fullmatch(r"[0-9+\-*/ ()]+", expr):
            return int(eval(expr, {"__builtins__": {}}))
    except Exception:
        pass
    return None


def decode_vba_chr(text: str) -> str:
    # Asc("A") → 65
    def asc_repl(m):
        return str(ord(m.group(1)))

    text = _ASC_RE.sub(asc_repl, text)

    # Chr / ChrW
    def chr_repl(m):
        val = _safe_eval(m.group(1))
        if val is None:
            return m.group(0)
        if 0 <= val <= 0x10FFFF:
            return chr(val)
        return m.group(0)

    text = _CHR_RE.sub(chr_repl, text)

    # многократные конкатенации "A" & "B" & "C"
    prev = None
    while prev != text:
        prev = text
        text = _CONCAT_RE.sub(
            lambda m: f'"{m.group(1)}{m.group(2)}"',
            text
        )

    return text
