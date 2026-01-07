import math
import string
from dataclasses import dataclass, field
from typing import Callable, List, Set, Union

from scriptguard.core.deobfuscator.base64_codec import decode_base64
from scriptguard.core.deobfuscator.rot_codec import decode_rot
from scriptguard.core.deobfuscator.ps_encoded import decode_powershell
from scriptguard.core.deobfuscator.vba_chr import decode_vba_chr
from scriptguard.core.deobfuscator.xor_codec import decode_xor


DECODERS: List[Callable[[str], Union[str, List[str]]]] = [
    decode_powershell,
    decode_vba_chr,
    decode_base64,
    decode_rot,
    decode_xor,
]

_ASCII_PRINTABLE = set(string.printable)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def ascii_printable_ratio(s: str) -> float:
    """
    Важно: НЕ используем str.isprintable(), потому что он считает печатными
    множество unicode-символов (из-за этого выигрывают "кракозябры").
    """
    if not s:
        return 0.0
    return sum(c in _ASCII_PRINTABLE for c in s) / len(s)


def unicode_ratio(s: str) -> float:
    """
    Доля символов вне ASCII-диапазона.
    Для кода (PS/VBA/JS/HTML) обычно это почти 0.
    """
    if not s:
        return 0.0
    return sum(ord(c) > 127 for c in s) / len(s)


def looks_like_script(s: str) -> float:
    """
    Небольшой бонус к score, если строка похожа на реальный скрипт/пейлоад.
    Возвращает значение 0..1 (не слишком агрессивно).
    """
    low = s.lower()
    hits = 0

    keywords = (
        # PowerShell
        "powershell", "encodedcommand", "invoke-webrequest", "iwr ", "iex", "invoke-expression",
        "new-object", "start-process", "downloadstring", "frombase64string",
        # VBA / Office macro
        "createobject", "wscript.shell", "shell(", "sub ", "function ", "dim ", "chr(", "chrb(",
        # JS/HTML
        "<script", "function(", "eval(", "atob(", "document.", "window.", "xmlhttprequest",
        # generic
        "http://", "https://", ".exe", ".dll", ".ps1", "cmd.exe", "rundll32"
    )

    for k in keywords:
        if k in low:
            hits += 1

    # мягкая нормализация
    if hits <= 0:
        return 0.0
    if hits >= 6:
        return 1.0
    return hits / 6.0


@dataclass(order=True)
class Candidate:
    score: float
    code: str = field(compare=False)
    path: List[str] = field(default_factory=list, compare=False)
    depth: int = field(default=0, compare=False)


class DeobfuscationEngine:
    def __init__(self, max_depth: int = 8, beam_width: int = 4):
        self.max_depth = max_depth
        self.beam_width = beam_width

    def _score(self, text: str) -> float:
        """
        Composite heuristic score.

        Идея:
        - низкая энтропия (ближе к "осмысленному") => плюс
        - высокий ASCII printable ratio => плюс
        - много Unicode (кракозябры) => штраф
        - признаки реального скрипта => бонус
        """
        if not text:
            return 0.0

        e = entropy(text)
        p = ascii_printable_ratio(text)
        u = unicode_ratio(text)
        k = looks_like_script(text)

        # 0..1
        entropy_score = 1.0 - min(e / 8.0, 1.0)

        # длина: чтобы короткие "обрывки" не побеждали всегда,
        # но и огромные простыни не давали мегабонус
        length_score = min(len(text) / 6000, 1.0)

        # штраф за unicode: уже при 5-10% заметно
        unicode_penalty = min(u / 0.20, 1.0)  # 0..1

        score = (
            entropy_score * 0.40 +
            p * 0.35 +
            length_score * 0.10 +
            k * 0.25 -
            unicode_penalty * 0.35
        )

        return score

    def run(self, code: str) -> dict:
        visited: Set[str] = set()

        initial = Candidate(
            score=self._score(code),
            code=code,
            path=[],
            depth=0
        )

        frontier: List[Candidate] = [initial]
        best = initial

        for _ in range(self.max_depth):
            next_frontier: List[Candidate] = []

            for cand in frontier:
                if cand.code in visited:
                    continue
                visited.add(cand.code)

                for decoder in DECODERS:
                    try:
                        results = decoder(cand.code)
                    except Exception:
                        continue

                    if isinstance(results, str):
                        results = [results]

                    for decoded in results:
                        if not decoded or decoded == cand.code:
                            continue
                        if decoded in visited:
                            continue

                        # фильтр: режем мусор жёстче, но не “убиваем” всё
                        if ascii_printable_ratio(decoded) < 0.70:
                            continue
                        if unicode_ratio(decoded) > 0.10:
                            # 10%+ non-ascii — почти всегда кракозябры/битые строки
                            continue

                        score = self._score(decoded)

                        new_cand = Candidate(
                            score=score,
                            code=decoded,
                            path=cand.path + [decoder.__name__],
                            depth=cand.depth + 1
                        )
                        next_frontier.append(new_cand)

                        if score > best.score:
                            best = new_cand

            if not next_frontier:
                break

            next_frontier.sort(reverse=True)
            frontier = next_frontier[: self.beam_width]

            # мягкий early stop:
            # если нашли очень “похожий на скрипт” результат, дальше обычно только портит
            if looks_like_script(best.code) >= 0.8 and best.depth >= 1:
                break

        confidence = min(
            1.0,
            0.2 + best.depth * 0.15 + best.score * 0.4
        )

        return {
            "code": best.code,
            "iterations": best.depth,
            "confidence": round(confidence, 2),
            "path": best.path,
        }
