import ast
import re
from typing import List


class ASTCodeCompressor:
    """
    Compresses source code into an architectural skeleton, preserving classes,
    function signatures, type annotations, and docstrings while stripping implementation bodies.
    """

    @classmethod
    def compress(cls, content: str, language: str) -> str:
        if language == "python":
            return cls._compress_python_ast(content)
        if language in {"cpp", "c", "javascript", "typescript", "java", "go", "rust", "csharp"}:
            return cls._compress_c_like(content)
        return cls._compress_fallback(content)

    @classmethod
    def _compress_python_ast(cls, source: str) -> str:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return cls._compress_fallback(source)

        output_lines: List[str] = []

        # Модульный докстринг
        module_doc = ast.get_docstring(tree)
        if module_doc:
            first_line = module_doc.strip().splitlines()[0]
            output_lines.append(f'"""{first_line}"""\n')

        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                output_lines.append(ast.unparse(node))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                unparsed = ast.unparse(node)
                if len(unparsed) <= 120:
                    output_lines.append(unparsed)
                else:
                    output_lines.append(unparsed[:117] + "...")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                output_lines.append("")
                output_lines.extend(cls._format_function(node, indent=0))
            elif isinstance(node, ast.ClassDef):
                output_lines.append("")
                output_lines.extend(cls._format_class(node, indent=0))

        result = "\n".join(output_lines).strip()
        return result if result else cls._compress_fallback(source)

    @classmethod
    def _format_function(cls, node: ast.AST, indent: int = 0) -> List[str]:
        pad = "    " * indent
        lines: List[str] = []

        for dec in getattr(node, "decorator_list", []):
            lines.append(f"{pad}@{ast.unparse(dec)}")

        prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        args_str = ast.unparse(node.args)
        returns_str = f" -> {ast.unparse(node.returns)}" if getattr(node, "returns", None) else ""
        lines.append(f"{pad}{prefix} {node.name}({args_str}){returns_str}:")

        doc = ast.get_docstring(node)
        if doc:
            summary = doc.strip().splitlines()[0]
            lines.append(f'{pad}    """{summary}"""')

        lines.append(f"{pad}    ...  # [implementation omitted]")
        return lines

    @classmethod
    def _format_class(cls, node: ast.ClassDef, indent: int = 0) -> List[str]:
        pad = "    " * indent
        lines: List[str] = []

        for dec in node.decorator_list:
            lines.append(f"{pad}@{ast.unparse(dec)}")

        bases = [ast.unparse(b) for b in node.bases]
        keywords = [f"{k.arg}={ast.unparse(k.value)}" for k in node.keywords if k.arg]
        inheritance = ", ".join(bases + keywords)
        inh_str = f"({inheritance})" if inheritance else ""
        lines.append(f"{pad}class {node.name}{inh_str}:")

        doc = ast.get_docstring(node)
        if doc:
            summary = doc.strip().splitlines()[0]
            lines.append(f'{pad}    """{summary}"""')

        has_members = False
        for child in node.body:
            if isinstance(child, (ast.Assign, ast.AnnAssign)):
                unparsed = ast.unparse(child)
                if len(unparsed) <= 100:
                    lines.append(f"{pad}    {unparsed}")
                    has_members = True
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lines.extend(cls._format_function(child, indent=indent + 1))
                has_members = True
            elif isinstance(child, ast.ClassDef):
                lines.extend(cls._format_class(child, indent=indent + 1))
                has_members = True

        if not has_members and not doc:
            lines.append(f"{pad}    ...")

        return lines

    @classmethod
    def _compress_c_like(cls, source: str) -> str:
        """
        Structural compressor for C/C++/JS/TS/Go/Rust/Java.
        Keeps top-level declarations, imports/includes, class/struct headers, and method signatures.
        """
        sig_pattern = re.compile(
            r"^\s*(?:#include|import|export|package|using|namespace|template|"
            r"(?:pub\s+)?(?:async\s+)?(?:fn|func|function|class|struct|interface|enum|type|trait|impl)|"
            r"(?:public|private|protected|static|virtual|inline|constexpr|async)\s+)"
        )
        lines = source.splitlines()
        kept: List[str] = []
        brace_depth = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            open_braces = line.count("{")
            close_braces = line.count("}")

            if brace_depth <= 1 and (sig_pattern.match(line) or stripped.startswith("//") or stripped.startswith("/*")):
                if open_braces > close_braces and not stripped.endswith("}"):
                    kept.append(line.rstrip() + " ... }")
                else:
                    kept.append(line.rstrip())
            elif brace_depth == 0 and ("(" in stripped and ")" in stripped and stripped.endswith("{")):
                kept.append(line.rstrip() + " ... }")

            brace_depth = max(0, brace_depth + open_braces - close_braces)

        if not kept:
            return cls._compress_fallback(source)
        return "\n".join(kept)

    @staticmethod
    def _compress_fallback(source: str) -> str:
        lines = [line for line in source.splitlines() if line.strip()]
        if len(lines) <= 30:
            return source
        head = "\n".join(lines[:20])
        tail = "\n".join(lines[-5:])
        omitted = len(lines) - 25
        return f"{head}\n\n# ... [{omitted} lines omitted in skeleton mode] ...\n\n{tail}"