# scriptguard/core/pipeline.py

from scriptguard.core.detector import detect_script
from scriptguard.core.deobfuscator.engine import DeobfuscationEngine
from scriptguard.core.ioc.extract import extract_ioc
from scriptguard.core.mitre.rules import classify_mitre
from scriptguard.core.report.render import render_report


def analyze(path, output, report_format="json", verbose=False):
    if verbose:
        print(f"[INFO] Reading file: {path}")

    with open(path, "rb") as f:
        raw = f.read()

    # FIX: теперь 3 значения
    script_type, text, detect_confidence = detect_script(raw)

    if verbose:
        print(f"[INFO] Script type detected: {script_type}")
        print("[INFO] Starting deobfuscation")

    engine = DeobfuscationEngine()
    result = engine.run(text)

    code = result.get("code", "")
    iterations = result.get("iterations", 0)
    engine_confidence = result.get("confidence", 0.0)

    # итоговая уверенность
    confidence = round((detect_confidence + engine_confidence) / 2, 2)

    if verbose:
        print("[INFO] Extracting indicators of compromise")

    ioc = extract_ioc(code)
    mitre = classify_mitre(code)

    report = {
        "file": path,
        "type": script_type,
        "iterations": iterations,
        "confidence": confidence,
        "ips": ioc.get("ips"),
        "urls": ioc.get("urls"),
        "domains": ioc.get("domains"),
        "emails": ioc.get("emails"),
        "hashes": ioc.get("hashes"),
        "mitre": mitre,
        "deobfuscated_code": code[:8000],
    }

    if verbose:
        print(f"[INFO] Writing report: {output}")

    render_report(report, output, report_format)
    return report
