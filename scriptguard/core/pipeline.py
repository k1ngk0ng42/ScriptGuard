from scriptguard.core.detector import detect_script
from scriptguard.core.deobfuscator.engine import DeobfuscationEngine
from scriptguard.core.ioc.extract import extract_ioc
from scriptguard.core.mitre.rules import classify_mitre
from scriptguard.core.report.render import render_report


def analyze(path, output, report_format="json", verbose=False):
    if verbose:
        print(f"[INFO] Reading file: {path}")

    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception as e:
        raise RuntimeError(f"Failed to read input file: {e}")

    script_type, text = detect_script(raw)

    if verbose:
        print(f"[INFO] Script type detected: {script_type}")
        print("[INFO] Starting deobfuscation")

    engine = DeobfuscationEngine()
    result = engine.run(text)

    code = result.get("code", "")
    iterations = result.get("iterations", 0)
    confidence = result.get("confidence", 0.0)

    if verbose:
        print("[INFO] Extracting indicators of compromise")

    ioc = extract_ioc(code)
    mitre = classify_mitre(code)

    report = {
        "file": path,
        "type": script_type,
        "iterations": iterations,
        "confidence": confidence,
        "ioc": ioc,
        "mitre": mitre,
        "deobfuscated_code": code[:8000],
    }

    if verbose:
        print(f"[INFO] Writing report: {output}")

    render_report(report, output, report_format)
