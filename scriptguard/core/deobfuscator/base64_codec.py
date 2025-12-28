import base64
import binascii
import gzip
import io
import re
from typing import List


BASE64_RE = re.compile(
    r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])'
)


def _try_decode(raw: bytes) -> List[str]:
    """
    Пробует различные декодирования байтов → строк.
    """
    results = []

    # utf‑8
    try:
        s = raw.decode("utf-8")
        if _looks_ok(s):
            results.append(s)
    except Exception:
        pass

    # utf‑16le
    try:
        s = raw.decode("utf-16le")
        if _looks_ok(s):
            results.append(s)
    except Exception:
        pass

    # gzip
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            data = gz.read()
            try:
                s = data.decode("utf-8")
                if _looks_ok(s):
                    results.append(s)
            except Exception:
                pass
    except Exception:
        pass

    return results


def _looks_ok(s: str) -> bool:
    if len(s) < 6:
        return False
    printable = sum(c.isprintable() for c in s)
    return printable / len(s) > 0.85


def decode_base64(text: str) -> List[str]:
    """
    Base64 EXPAND decoder.

    Возвращает:
    - оригинальный текст
    - текст с заменой base64
    - чисто decoded payload
    """
    results = [text]

    matches = set(BASE64_RE.findall(text))
    if not matches:
        return results

    for b64 in matches:
        try:
            raw = base64.b64decode(b64, validate=True)
        except binascii.Error:
            continue

        decoded_variants = _try_decode(raw)

        for decoded in decoded_variants:
            # 1️⃣ вариант: decoded как отдельный кандидат
            results.append(decoded)

            # 2️⃣ вариант: replace внутри текста
            replaced = text.replace(b64, decoded)
            if replaced != text:
                results.append(replaced)

    # уникализация + сохранение порядка
    seen = set()
    final = []
    for r in results:
        if r not in seen:
            seen.add(r)
            final.append(r)

    return final
