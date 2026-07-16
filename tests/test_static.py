"""AST static-analysis edge cases.

A bare `except:` that does nothing (`pass` or `...`) silently swallows every
error and is worth flagging. But the blind-handler check matched any
single-statement body of type ast.Expr, so a bare handler that actually does
something -- `except: log_error()` -- was wrongly reported as a blind
`except: pass`. Only pass and an ellipsis body are blind.
"""

from pathlib import Path

from aegisaudit.sast.static import scan_python_ast


def _ids(source: str, tmp_path: Path) -> list[str]:
    f = tmp_path / "m.py"
    f.write_text(source)
    return [x.id for x in scan_python_ast(f)]


class TestBlindExcept:
    def test_bare_except_pass_is_flagged(self, tmp_path):
        ids = _ids("try:\n    risky()\nexcept:\n    pass\n", tmp_path)
        assert "blind-except" in ids

    def test_bare_except_ellipsis_is_flagged(self, tmp_path):
        ids = _ids("try:\n    risky()\nexcept:\n    ...\n", tmp_path)
        assert "blind-except" in ids

    def test_bare_except_that_does_something_is_not_flagged(self, tmp_path):
        """`except: log_error()` handles the error; it is not blind."""
        ids = _ids("try:\n    risky()\nexcept:\n    log_error()\n", tmp_path)
        assert "blind-except" not in ids

    def test_bare_except_with_a_lone_expression_is_not_flagged(self, tmp_path):
        """Only pass and `...` count as blind; any other single expression
        statement (a call, a bare string) is left alone to avoid false
        positives."""
        ids = _ids('try:\n    risky()\nexcept:\n    "ignore"\n', tmp_path)
        assert "blind-except" not in ids
