class DeobfuscationEngine:
    def __init__(self, max_iter: int = 10):
        self.max_iter = max_iter

    def _score(self, s: str) -> float:
        return (
            (1.0 - min(entropy(s) / 8.0, 1.0)) * 0.5 +
            printable_ratio(s) * 0.4 +
            min(len(s) / 10000, 1.0) * 0.1
        )

    def run(self, code: str):
        seen = set()
        iterations = 0
        confidence = 0.0
        steps = []

        current = code
        current_score = self._score(current)

        for _ in range(self.max_iter):
            best = current
            best_score = current_score
            best_decoder = None

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
                    best_decoder = decoder.__name__

            if best == current:
                break

            seen.add(current)
            current = best
            current_score = best_score
            iterations += 1
            confidence += 0.15

            steps.append({
                "decoder": best_decoder,
                "score": round(best_score, 3),
                "length": len(best)
            })

            if printable_ratio(current) < 0.6:
                break

        return {
            "code": current,
            "iterations": iterations,
            "confidence": round(min(confidence, 1.0), 2),
            "steps": steps
        }
