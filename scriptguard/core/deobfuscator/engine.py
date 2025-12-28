import math
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


def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isprintable() for c in s) / len(s)


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
        """
        e = entropy(text)
        p = printable_ratio(text)

        entropy_score = 1.0 - min(e / 8.0, 1.0)
        length_score = min(len(text) / 8000, 1.0)

        return (
            entropy_score * 0.5 +
            p * 0.3 +
            length_score * 0.2
        )

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

                    # backward compatibility: decoder may return str
                    if isinstance(results, str):
                        results = [results]

                    for decoded in results:
                        if not decoded or decoded == cand.code:
                            continue

                        if decoded in visited:
                            continue

                        if printable_ratio(decoded) < 0.6:
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

            # beam search: keep best candidates
            next_frontier.sort(reverse=True)
            frontier = next_frontier[: self.beam_width]

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
