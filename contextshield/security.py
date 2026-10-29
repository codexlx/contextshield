import math
import re
from typing import List, Tuple
from .models import SecurityFinding, Severity, ThreatCategory


class SecurityScanner:
    """
    Scans source files for hardcoded secrets, prompt injections targeting AI coding agents,
    and invisible Trojan Source Unicode characters.
    """

    SECRET_RULES: List[Tuple[str, re.Pattern, Severity]] = [
        (
            "OpenAI API Key",
            re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"),
            Severity.CRITICAL,
        ),
        (
            "Anthropic API Key",
            re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{40,}\b"),
            Severity.CRITICAL,
        ),
        (
            "GitHub Token",
            re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}\b"),
            Severity.CRITICAL,
        ),
        (
            "AWS Access Key ID",
            re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
            Severity.CRITICAL,
        ),
        (
            "Telegram Bot Token",
            re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
            Severity.HIGH,
        ),
        (
            "Private SSH/RSA Key",
            re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----"),
            Severity.CRITICAL,
        ),
        (
            "Generic Secret Assignment",
            re.compile(
                r"(?i)\b(?:api_key|secret_key|access_token|auth_token|password|passwd|client_secret)\b"
                r"\s*[:=]\s*['\"]([A-Za-z0-9_\-\+/=]{16,})['\"]"
            ),
            Severity.HIGH,
        ),
        (
            "JWT Token",
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            Severity.MEDIUM,
        ),
    ]

    INJECTION_RULES: List[Tuple[str, re.Pattern, Severity]] = [
        (
            "System Prompt Override",
            re.compile(
                r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+"
                r"(?:instructions|prompts|rules|directives)"
            ),
            Severity.CRITICAL,
        ),
        (
            "AI Agent Command Hijack",
            re.compile(
                r"(?i)(?:you\s+are\s+now\s+in\s+developer\s+mode|new\s+system\s+instruction|"
                r"important\s+instruction\s+for\s+(?:the\s+)?(?:ai|llm|assistant|claude|chatgpt|cursor))"
            ),
            Severity.HIGH,
        ),
        (
            "Hidden Exfiltration Directive",
            re.compile(
                r"(?i)(?:curl|wget|fetch|http[s]?://)\s+[^\s]+.*?(?:env|secret|ssh|id_rsa|token)"
            ),
            Severity.HIGH,
        ),
        (
            "Fake System Tag Injection",
            re.compile(r"(?i)<\s*/?\s*(?:system_prompt|system_instruction|antml:thinking)\s*>"),
            Severity.HIGH,
        ),
    ]

    # Невидимые и двунаправленные символы Unicode (Trojan Source & Zero-Width steganography)
    TROJAN_CODEPOINTS = {
        "\u202a": "LRE (Left-to-Right Embedding)",
        "\u202b": "RLE (Right-to-Left Embedding)",
        "\u202d": "LRO (Left-to-Right Override)",
        "\u202e": "RLO (Right-to-Left Override)",
        "\u2066": "LRI (Left-to-Right Isolate)",
        "\u2067": "RLI (Right-to-Left Isolate)",
        "\u2068": "FSI (First Strong Isolate)",
        "\u202c": "PDF (Pop Directional Formatting)",
        "\u2069": "PDI (Pop Directional Isolate)",
        "\u200b": "ZWSP (Zero-Width Space)",
        "\u200c": "ZWNJ (Zero-Width Non-Joiner)",
        "\u200d": "ZWJ (Zero-Width Joiner)",
    }

    def __init__(self, redact_secrets: bool = True, sanitize_injections: bool = True):
        self.redact_secrets = redact_secrets
        self.sanitize_injections = sanitize_injections

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculates Shannon entropy of a string to distinguish real keys from placeholders."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies = {char: data.count(char) for char in set(data)}
        for count in frequencies.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        lower = value.lower()
        placeholders = ("example", "your_", "xxx", "todo", "changeme", "dummy", "placeholder", "test_")
        return any(p in lower for p in placeholders) or len(set(value)) <= 4

    def scan_and_sanitize(self, file_path: str, content: str) -> Tuple[str, List[SecurityFinding]]:
        findings: List[SecurityFinding] = []
        sanitized_lines: List[str] = []

        lines = content.splitlines(keepends=True)

        for idx, line in enumerate(lines, start=1):
            modified_line = line

            # 1. Проверка на скрытые символы Unicode (Trojan Source)
            for char, description in self.TROJAN_CODEPOINTS.items():
                if char in modified_line:
                    findings.append(
                        SecurityFinding(
                            file_path=file_path,
                            line_number=idx,
                            category=ThreatCategory.TROJAN_UNICODE,
                            severity=Severity.HIGH,
                            rule_name=f"Trojan Unicode: {description}",
                            snippet=repr(modified_line.strip())[:80],
                            redacted=self.sanitize_injections,
                        )
                    )
                    if self.sanitize_injections:
                        modified_line = modified_line.replace(char, "")

            # 2. Проверка на утечки секретов и API-ключей
            for rule_name, pattern, severity in self.SECRET_RULES:
                for match in list(pattern.finditer(modified_line)):
                    secret_candidate = match.group(1) if match.lastindex else match.group(0)

                    # Игнорируем очевидные заглушки и низкоэнтропийные строки для общих правил
                    if self._is_placeholder(secret_candidate):
                        continue
                    if rule_name == "Generic Secret Assignment" and self.shannon_entropy(secret_candidate) < 3.3:
                        continue

                    masked_preview = (
                        f"{secret_candidate[:4]}...{secret_candidate[-3:]}"
                        if len(secret_candidate) > 8
                        else "***"
                    )
                    findings.append(
                        SecurityFinding(
                            file_path=file_path,
                            line_number=idx,
                            category=ThreatCategory.SECRET_LEAK,
                            severity=severity,
                            rule_name=rule_name,
                            snippet=f"Matched {rule_name} ({masked_preview})",
                            redacted=self.redact_secrets,
                        )
                    )
                    if self.redact_secrets:
                        modified_line = modified_line.replace(
                            secret_candidate, f"[REDACTED_{rule_name.upper().replace(' ', '_')}]"
                        )

            # 3. Проверка на Prompt Injection для ИИ-ассистентов
            for rule_name, pattern, severity in self.INJECTION_RULES:
                if pattern.search(modified_line):
                    findings.append(
                        SecurityFinding(
                            file_path=file_path,
                            line_number=idx,
                            category=ThreatCategory.PROMPT_INJECTION,
                            severity=severity,
                            rule_name=rule_name,
                            snippet=modified_line.strip()[:80],
                            redacted=self.sanitize_injections,
                        )
                    )
                    if self.sanitize_injections:
                        modified_line = pattern.sub(
                            "[SANITIZED_PROMPT_INJECTION_ATTEMPT]", modified_line
                        )

            sanitized_lines.append(modified_line)

        return "".join(sanitized_lines), findings