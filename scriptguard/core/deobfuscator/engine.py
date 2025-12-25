import math

from scriptguard.core.deobfuscator.base64_codec import decode_base64
from scriptguard.core.deobfuscator.rot_codec import decode_rot
from scriptguard.core.deobfuscator.ps_encoded import decode_powershell
from scriptguard.core.deobfuscator.vba_chr import decode_vba_chr
from scriptguard.core.deobfuscator.xor_codec import decode_xor


DECODERS = [
    decode_powershell,
    decode_vba_chr,
    decode_base64,
    decode_rot,
    decode_xor,
]


def entropy(s: str) -> float:
    """Shannon entropy"""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isprintable() for c in s) / len(s)


class DeobfuscationEngine:
    def __init__(self, max_iter: int = 10):
        self.max_iter = max_iter

    def _score(self, s: str) -> float:
        """
        Эвристическая оценка «качества» расшифровки
        """
        return (
            (1.0 - min(entropy(s) / 8.0, 1.0)) * 0.5 +
            printable_ratio(s) * 0.4 +
            min(len(s) / 10000, 1.0) * 0.1
        )

    def run(self, code: str) -> dict:
        seen = set()
        iterations = 0
        confidence = 0.0

        current = code
        current_score = self._score(current)

        for _ in range(self.max_iter):
            best = current
            best_score = current_score

            for decoder in DECODERS:
                try:
                    candidate = decoder(current)
                except Exception:
                    continue

                if not candidate or candidate == current:
                    continue
                if candidate in seen:
                    continue

                score = self._score(candidate)

                if score > best_score:
                    best = candidate
                    best_score = score

            if best == current:
                break

            seen.add(current)
            current = best
            current_score = best_score
            iterations += 1
            confidence += 0.15

            # защита от деградации
            if printable_ratio(current) < 0.6:
                break

        return {
            "code": current,
            "iterations": iterations,
            "confidence": round(min(confidence, 1.0), 2),
        }
