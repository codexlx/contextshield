import argparse
import sys
from pathlib import Path
from typing import List, Optional
from .models import PackReport, Severity
from .packer import RepositoryPacker


class TerminalUI:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"

    @classmethod
    def color(cls, text: str, color_code: str) -> str:
        if not sys.stderr.isatty():
            return text
        return f"{color_code}{text}{cls.RESET}"

    @classmethod
    def print_report(cls, report: PackReport) -> None:
        err = sys.stderr
        err.write("\n" + cls.color("═" * 78, cls.CYAN) + "\n")
        err.write(cls.color(" 🛡️  CONTEXTSHIELD — AI CONTEXT PACKER & SECURITY AUDIT REPORT", cls.BOLD) + "\n")
        err.write(cls.color("═" * 78, cls.CYAN) + "\n\n")

        # Таблица файлов
        err.write(f"{'File Path':<40} | {'Mode':<10} | {'Orig Tok':>8} | {'Final Tok':>9} | {'Saved':>6}\n")
        err.write("─" * 78 + "\n")

        for f in report.files[:25]:
            short_path = f.relative_path if len(f.relative_path) <= 40 else "..." + f.relative_path[-37:]
            mode_str = (
                cls.color("SKELETON", cls.YELLOW)
                if f.compression_mode.value == "SKELETON"
                else cls.color("FULL    ", cls.GREEN)
            )
            err.write(
                f"{short_path:<40} | {mode_str} | {f.original_tokens:>8,} | "
                f"{f.processed_tokens:>9,} | {f.compression_ratio:>5.1f}%\n"
            )

        if len(report.files) > 25:
            err.write(f"... and {len(report.files) - 25} more files.\n")

        err.write("─" * 78 + "\n")
        total_ratio = (
            (1.0 - (report.total_processed_tokens / report.total_original_tokens)) * 100.0
            if report.total_original_tokens > 0
            else 0.0
        )
        err.write(
            f"📊 {cls.color('TOTALS:', cls.BOLD)} {len(report.files)} files packed "
            f"({report.skipped_files} skipped) | "
            f"Tokens: {report.total_original_tokens:,} -> "
            f"{cls.color(f'{report.total_processed_tokens:,}', cls.CYAN)} "
            f"({cls.color(f'-{total_ratio:.1f}%', cls.GREEN)})\n\n"
        )

        # Отчёт безопасности
        findings = report.all_findings
        if not findings:
            err.write(cls.color("✅ Security Scan: CLEAN (0 secrets, 0 prompt injections detected)\n\n", cls.GREEN))
        else:
            err.write(
                cls.color(
                    f"⚠️  Security Scan: {len(findings)} THREAT(S) DETECTED & SANITIZED:\n",
                    cls.RED,
                )
            )
            for item in findings:
                sev_color = cls.RED if item.severity in (Severity.CRITICAL, Severity.HIGH) else cls.YELLOW
                status = "REDACTED" if item.redacted else "WARN"
                err.write(
                    f"  • [{cls.color(item.severity.value, sev_color)}] "
                    f"{item.file_path}:{item.line_number} — {item.rule_name} ({status})\n"
                    f"    Snippet: {item.snippet}\n"
                )
            err.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contextshield",
        description="Pack codebases into token-optimized, security-hardened LLM prompts.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the repository or directory (default: current directory)",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path (e.g. context.md or prompt.xml). Prints to stdout if omitted.",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["markdown", "xml"],
        default="markdown",
        help="Output format: 'markdown' or 'xml' (optimized for Claude) (default: markdown)",
    )
    parser.add_argument(
        "-b", "--budget",
        type=int,
        default=None,
        help="Target token budget (e.g. 16000). Automatically AST-compresses low-priority files to fit.",
    )
    parser.add_argument(
        "--skeleton",
        action="store_true",
        help="Force AST skeleton compression on all files for maximum token savings.",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable automatic secret redaction (still reports findings).",
    )
    parser.add_argument(
        "--fail-on-threat",
        action="store_true",
        help="Exit with code 1 if any secret leak or prompt injection is found (useful for CI/CD).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target_path = Path(args.path)
    if not target_path.exists():
        sys.stderr.write(f"Error: Path '{target_path}' does not exist.\n")
        return 2

    packer = RepositoryPacker(
        root_dir=target_path,
        token_budget=args.budget,
        skeleton_all=args.skeleton,
        redact_secrets=not args.no_redact,
        sanitize_injections=not args.no_redact,
    )

    report = packer.pack()
    TerminalUI.print_report(report)

    rendered = packer.render_output(report, fmt=args.format)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(rendered, encoding="utf-8")
        sys.stderr.write(f"💾 Saved context pack to: {out_path.resolve()}\n")
    else:
        sys.stdout.write(rendered + "\n")

    if args.fail_on_threat and report.all_findings:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())