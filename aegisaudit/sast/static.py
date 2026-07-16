import ast
from pathlib import Path
from typing import List, Optional
from aegisaudit.models import Finding, Severity


def _is_inert(stmt: ast.stmt) -> bool:
    """True if a statement does nothing: `pass` or a bare `...`."""
    if isinstance(stmt, ast.Pass):
        return True
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    )


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, display_path: Optional[str] = None) -> None:
        self.file_path = file_path
        self.location = display_path if display_path is not None else str(file_path)
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        # Check for dangerous functions
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self._add_finding(
                    node.lineno, "eval-detected", Severity.HIGH, "Use of eval() detected"
                )
            elif node.func.id == "exec":
                self._add_finding(
                    node.lineno, "exec-detected", Severity.HIGH, "Use of exec() detected"
                )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # A bare `except:` whose body does nothing swallows every error. Only a
        # `pass` or an `...` (Ellipsis) body is inert; a handler that calls
        # something -- `except: log_error()` -- actually handles the error and
        # must not be flagged, so match ast.Expr only when its value is the
        # Ellipsis constant rather than any expression statement.
        if node.type is None and len(node.body) == 1 and _is_inert(node.body[0]):
            self._add_finding(
                node.lineno,
                "blind-except",
                Severity.LOW,
                "Blind exception handler (except: pass)",
            )
        self.generic_visit(node)

    def _add_finding(self, lineno: int, id: str, severity: Severity, title: str) -> None:
        self.findings.append(
            Finding(
                id=id,
                severity=severity,
                title=title,
                description="Static analysis detected a potentially dangerous code pattern.",
                evidence=f"Line {lineno}",
                url=self.location,
                line=lineno,
                remediation="Review and refactor dangerous code.",
                tags=["sast", "python-ast"],
            )
        )


def scan_python_ast(path: Path, display_path: Optional[str] = None) -> List[Finding]:
    """Scan one Python file for dangerous patterns.

    display_path is the location reported on the finding. It should be relative
    to the scan root so SARIF consumers can match it against a repo tree.
    """
    findings = []
    try:
        content = path.read_text(encoding="utf-8")
        tree = ast.parse(content)
        visitor = SecurityVisitor(path, display_path)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except Exception:
        pass  # Parse errors
    return findings
