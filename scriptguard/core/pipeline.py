# scriptguard/core/pipeline.py

from pathlib import Path
from typing import Dict

from scriptguard.core.detector import detect_script
from scriptguard.core.deobfuscator.engine import DeobfuscationEngine
from scriptguard.core.ioc.extract import extract_ioc
from scriptguard.core.mitre.rules import classify_mitre


def analyze(file_path: Path, verbose: bool = False) -> Dict:
    """
    Основной pipeline анализа скрипта.
    """
    try:
        raw = file_path.read_bytes()
    except Exception as e:
        raise RuntimeError(f"Failed to read file: {e}")

    # Определение типа и декодирование текста
    script_type, text, detect_conf = detect_script(raw)

    # Деобфускация
    engine = DeobfuscationEngine()
    result = engine.run(text)

    deobfuscated = result["code"]
    iterations = result["iterations"]
    deobf_conf = result.get("confidence", 0.0)

    # IOC и MITRE
    ioc = extract_ioc(deobfuscated)
    mitre = classify_mitre(deobfuscated)

    # Итоговая уверенность (взвешенная)
    final_confidence = round(
        detect_conf * 0.4 + deobf_conf * 0.6,
        2
    )

    if verbose:
        print(f"[INFO] Type: {script_type}")
        print(f"[INFO] Iterations: {iterations}")
        print(f"[INFO] Confidence: {final_confidence}")

    return {
        "file": str(file_path),
        "type": script_type,
        "iterations": iterations,
        "confidence": final_confidence,

        "ips": ioc.get("ips", []),
        "urls": ioc.get("urls", []),
        "domains": ioc.get("domains", []),
        "emails": ioc.get("emails", []),
        "hashes": ioc.get("hashes", {}),

        "mitre": mitre,
        "deobfuscated_code": deobfuscated[:5000],
    }
