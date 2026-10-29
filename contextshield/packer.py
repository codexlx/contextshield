import fnmatch
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from .compressor import ASTCodeCompressor
from .models import CompressionMode, PackReport, ProcessedFile
from .security import SecurityScanner


class RepositoryPacker:
    DEFAULT_IGNORE_DIRS: Set[str] = {
        ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", ".tox", ".venv", "venv", "env", "node_modules",
        "dist", "build", "target", "out", ".next", ".nuxt", ".idea", ".vscode",
        "coverage", "htmlcov", "eggs", ".eggs",
    }

    DEFAULT_IGNORE_PATTERNS: List[str] = [
        "*.pyc", "*.pyo", "*.pyd", "*.so", "*.dll", "*.dylib", "*.exe", "*.bin",
        "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.webp",
        "*.mp3", "*.mp4", "*.wav", "*.pdf", "*.zip", "*.tar", "*.gz", "*.7z",
        "*.woff", "*.woff2", "*.ttf", "*.eot", "*.lock", "package-lock.json",
        "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "*.min.js", "*.min.css",
    ]

    EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
        ".py": "python", ".pyi": "python",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".h": "c", ".c": "c",
        ".rs": "rust", ".go": "go", ".java": "java", ".cs": "csharp",
        ".rb": "ruby", ".php": "php", ".swift": "swift", ".kt": "kotlin",
        ".sql": "sql", ".sh": "bash", ".ps1": "powershell",
        ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml",
        ".md": "markdown", ".html": "html", ".css": "css",
    }

    def __init__(
        self,
        root_dir: Path,
        token_budget: Optional[int] = None,
        skeleton_all: bool = False,
        redact_secrets: bool = True,
        sanitize_injections: bool = True,
        max_file_size_kb: int = 512,
    ):
        self.root_dir = root_dir.resolve()
        self.token_budget = token_budget
        self.skeleton_all = skeleton_all
        self.max_file_size_bytes = max_file_size_kb * 1024
        self.scanner = SecurityScanner(
            redact_secrets=redact_secrets,
            sanitize_injections=sanitize_injections,
        )
        self.gitignore_patterns = self._load_gitignore()

    def _load_gitignore(self) -> List[str]:
        patterns = list(self.DEFAULT_IGNORE_PATTERNS)
        gitignore_path = self.root_dir / ".gitignore"
        if gitignore_path.is_file():
            try:
                for line in gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#"):
                        patterns.append(cleaned.rstrip("/"))
            except OSError:
                pass
        return patterns

    def _should_ignore(self, rel_path: str, name: str) -> bool:
        for pattern in self.gitignore_patterns:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel_path, pattern):
                return True
        return False

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """
        Fast heuristic token estimation calibrated for BPE tokenizers (cl100k_base / o200k_base).
        Code averages ~3.6 characters per token due to punctuation and indentation.
        """
        if not text:
            return 0
        return max(1, int(len(text) / 3.6))

    @staticmethod
    def _is_binary(file_path: Path) -> bool:
        try:
            with file_path.open("rb") as f:
                chunk = f.read(2048)
            return b"\x00" in chunk
        except OSError:
            return True

    @staticmethod
    def _calculate_priority(rel_path: str, language: str) -> float:
        """
        Scores file importance (0.1 to 10.0) so budget optimizer keeps core code intact
        and compresses tests, docs, or configs first.
        """
        lower = rel_path.lower()
        score = 5.0

        # Точки входа и ядро архитектуры имеют наивысший приоритет
        if any(k in lower for k in ("main.", "app.", "core", "engine", "models", "server", "index.", "cli.")):
            score += 3.0

        # Исходный код важнее статики и разметки
        if language in {"python", "typescript", "javascript", "cpp", "rust", "go", "java"}:
            score += 2.0

        # Тесты, примеры, миграции и документация сжимаются в первую очередь
        if any(k in lower for k in ("test", "spec", "mock", "fixture", "example", "benchmark", "migration", "docs/")):
            score -= 3.5

        # Чем глубже вложенность, тем чуть ниже приоритет
        depth = rel_path.count("/") + rel_path.count("\\")
        score -= depth * 0.2

        return max(0.5, min(10.0, score))

    def pack(self) -> PackReport:
        report = PackReport(root_dir=str(self.root_dir), token_budget=self.token_budget)

        for current_root, dirs, files in os.walk(self.root_dir):
            # Фильтрация игнорируемых директорий на лету
            dirs[:] = [
                d for d in sorted(dirs)
                if d not in self.DEFAULT_IGNORE_DIRS
                and not self._should_ignore(
                    str(Path(current_root, d).relative_to(self.root_dir).as_posix()), d
                )
            ]

            for file_name in sorted(files):
                abs_path = Path(current_root) / file_name
                rel_path = abs_path.relative_to(self.root_dir).as_posix()

                if self._should_ignore(rel_path, file_name):
                    report.skipped_files += 1
                    continue

                try:
                    if abs_path.stat().st_size > self.max_file_size_bytes or self._is_binary(abs_path):
                        report.skipped_files += 1
                        continue
                    raw_content = abs_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    report.skipped_files += 1
                    continue

                if not raw_content.strip():
                    report.skipped_files += 1
                    continue

                ext = abs_path.suffix.lower()
                language = self.EXTENSION_LANGUAGE_MAP.get(ext, "text")

                # 1. Сканирование безопасности и санитизация
                sanitized_content, findings = self.scanner.scan_and_sanitize(rel_path, raw_content)
                orig_tokens = self.estimate_tokens(sanitized_content)

                # 2. Начальный режим сжатия
                if self.skeleton_all:
                    compressed = ASTCodeCompressor.compress(sanitized_content, language)
                    proc_tokens = self.estimate_tokens(compressed)
                    mode = CompressionMode.SKELETON
                else:
                    compressed = sanitized_content
                    proc_tokens = orig_tokens
                    mode = CompressionMode.FULL

                priority = self._calculate_priority(rel_path, language)

                report.files.append(
                    ProcessedFile(
                        relative_path=rel_path,
                        absolute_path=abs_path,
                        language=language,
                        original_content=sanitized_content,
                        processed_content=compressed,
                        original_tokens=orig_tokens,
                        processed_tokens=proc_tokens,
                        compression_mode=mode,
                        priority_score=priority,
                        findings=findings,
                    )
                )

        # 3. Оптимизация под бюджет токенов (если задан --budget)
        if self.token_budget and not self.skeleton_all:
            self._optimize_for_budget(report, self.token_budget)

        # Сортируем файлы по приоритету (важные файлы идут первыми в промпте)
        report.files.sort(key=lambda f: (-f.priority_score, f.relative_path))
        return report

    def _optimize_for_budget(self, report: PackReport, budget: int) -> None:
        """
        Greedily compresses lowest-priority files into AST skeletons until total tokens fit the budget.
        """
        if report.total_processed_tokens <= budget:
            return

        # Сортируем от наименее приоритетных к наиболее важным
        candidates = sorted(report.files, key=lambda f: (f.priority_score, -f.original_tokens))

        for file_obj in candidates:
            if report.total_processed_tokens <= budget:
                break
            if file_obj.compression_mode == CompressionMode.FULL:
                skeleton = ASTCodeCompressor.compress(file_obj.original_content, file_obj.language)
                new_tokens = self.estimate_tokens(skeleton)
                if new_tokens < file_obj.processed_tokens:
                    file_obj.processed_content = skeleton
                    file_obj.processed_tokens = new_tokens
                    file_obj.compression_mode = CompressionMode.SKELETON

    @staticmethod
    def build_directory_tree(files: List[ProcessedFile]) -> str:
        tree_lines = ["."]
        paths = sorted(f.relative_path for f in files)
        for p in paths:
            parts = p.split("/")
            indent = "  " * (len(parts) - 1)
            tree_lines.append(f"{indent}├── {parts[-1]}")
        return "\n".join(tree_lines)

    def render_output(self, report: PackReport, fmt: str = "markdown") -> str:
        tree_str = self.build_directory_tree(report.files)

        if fmt == "xml":
            chunks = [
                "<repository_context>",
                f"  <metadata total_files=\"{len(report.files)}\" "
                f"total_tokens=\"{report.total_processed_tokens}\" "
                f"saved_tokens=\"{report.total_saved_tokens}\" "
                f"security_findings=\"{len(report.all_findings)}\" />",
                "  <directory_tree>",
                tree_str,
                "  </directory_tree>",
                "  <files>",
            ]
            for f in report.files:
                chunks.append(
                    f"    <file path=\"{f.relative_path}\" language=\"{f.language}\" "
                    f"mode=\"{f.compression_mode.value}\" tokens=\"{f.processed_tokens}\">"
                )
                chunks.append(f.processed_content)
                chunks.append("    </file>")
            chunks.append("  </files>")
            chunks.append("</repository_context>")
            return "\n".join(chunks)

        # По умолчанию: структурированный Markdown для LLM
        chunks = [
            "# Repository Context Pack",
            "",
            f"- **Files included:** {len(report.files)}",
            f"- **Estimated tokens:** {report.total_processed_tokens:,} "
            f"(Saved {report.total_saved_tokens:,} tokens via AST compression)",
            f"- **Security findings redacted/sanitized:** {len(report.all_findings)}",
            "",
            "## Directory Structure",
            "```text",
            tree_str,
            "```",
            "",
            "## Source Files",
            "",
        ]
        for f in report.files:
            badge = "AST-SKELETON" if f.compression_mode == CompressionMode.SKELETON else "FULL"
            chunks.append(f"### `{f.relative_path}` [{badge} | {f.processed_tokens} tokens]")
            chunks.append(f"```{f.language}")
            chunks.append(f.processed_content)
            chunks.append("```")
            chunks.append("")

        return "\n".join(chunks)