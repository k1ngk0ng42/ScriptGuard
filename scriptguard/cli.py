import argparse
import os
import sys
from scriptguard.core.pipeline import analyze

def main():
    parser = argparse.ArgumentParser(
        description="ScriptGuard v2 - Static deobfuscation and analysis tool"
    )

    parser.add_argument("file", help="Input script file")
    parser.add_argument(
        "-o", "--output", default="report.json", help="Output report file"
    )
    parser.add_argument(
        "--format", choices=["json", "html"], default="json",
        help="Output report format"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERROR] File '{args.file}' not found")
        sys.exit(1)

    if args.verbose:
        print(f"[INFO] Starting analysis: {args.file}")
        print(f"[INFO] Output format: {args.format}")

    try:
        # Вызов analyze с поддержкой verbose и report_format
        result = analyze(
            path=args.file,
            output=args.output,
            report_format=args.format,
            verbose=args.verbose
        )
        if args.verbose:
            # confidence теперь есть в result
            confidence = result.get("confidence", 0.0)
            script_type = result.get("type", "Unknown")
            print(f"[INFO] Detected script type: {script_type} (confidence: {confidence:.2f})")
            print(f"[INFO] Report saved to {args.output}")

    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
