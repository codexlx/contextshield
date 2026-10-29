from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    SECRET_LEAK = "SECRET_LEAK"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    TROJAN_UNICODE = "TROJAN_UNICODE"


class CompressionMode(str, Enum):
    FULL = "FULL"
    SKELETON = "SKELETON"
    SUMMARY = "SUMMARY"


@dataclass
class SecurityFinding:
    file_path: str
    line_number: int
    category: ThreatCategory
    severity: Severity
    rule_name: str
    snippet: str
    redacted: bool = False


@dataclass
class ProcessedFile:
    relative_path: str
    absolute_path: Path
    language: str
    original_content: str
    processed_content: str
    original_tokens: int
    processed_tokens: int
    compression_mode: CompressionMode = CompressionMode.FULL
    priority_score: float = 1.0
    findings: List[SecurityFinding] = field(default_factory=list)

    @property
    def saved_tokens(self) -> int:
        return max(0, self.original_tokens - self.processed_tokens)

    @property
    def compression_ratio(self) -> float:
        if self.original_tokens == 0:
            return 0.0
        return (1.0 - (self.processed_tokens / self.original_tokens)) * 100.0


@dataclass
class PackReport:
    root_dir: str
    files: List[ProcessedFile] = field(default_factory=list)
    skipped_files: int = 0
    token_budget: Optional[int] = None

    @property
    def total_original_tokens(self) -> int:
        return sum(f.original_tokens for f in self.files)

    @property
    def total_processed_tokens(self) -> int:
        return sum(f.processed_tokens for f in self.files)

    @property
    def total_saved_tokens(self) -> int:
        return max(0, self.total_original_tokens - self.total_processed_tokens)

    @property
    def all_findings(self) -> List[SecurityFinding]:
        results: List[SecurityFinding] = []
        for f in self.files:
            results.extend(f.findings)
        return results