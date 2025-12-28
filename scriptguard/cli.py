# scriptguard/cli.py

import argparse
from pathlib import Path
import sys

from scriptguard.core.pipeline import analyze
from scriptguard.core.report.render import render_report


def main():
    """
    Command-line interface for ScriptGuard.
    Анализирует скрипты (VBA, PowerShell, JavaScript) и
    генерирует отчёт в JSON или HTML.
    """
    parser = argparse.ArgumentParser(
        description="ScriptGuard — malware script analyzer"
    )

    parser.add_argument(
        "file",
        type=str,
        help="Path to script file for analysis"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        default="report.json",
        help="Output report file (default: report.json)"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["json", "html"],
        default="json",
        help="Report format"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()
    input_path = Path(args.file)
    output_path = Path(args.output)

    if not input_path.exists() or not input_path.is_file():
        print(f"[ERROR] File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.verbose:
            print(f"[INFO] Starting analysis: {input_path}")
            print(f"[INFO] Output format: {args.format}")

        report = analyze(input_path, verbose=args.verbose)

        # Создаём директории для отчёта, если их нет
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if args.verbose:
            print(f"[INFO] Writing report to: {output_path}")

        render_report(report, output_path, fmt=args.format)

        if args.verbose:
            print(f"[INFO] Analysis completed successfully")

        sys.exit(0)

    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
