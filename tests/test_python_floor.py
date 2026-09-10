"""Guard `requires-python = ">=3.8"` against annotations that need 3.9/3.10.

CI runs on 3.12, where `List[str] | None` in a signature evaluates fine — so an
import smoke test here would prove nothing. The floor only breaks on the user's
interpreter, which is how `transcripts/adapters/__init__.py` shipped a PEP 604
union that made five modules unimportable on 3.8/3.9.

An annotation is evaluated at def time unless the module opts into PEP 563, so
the rule is: use `X | Y` or `list[str]` in annotations only with
`from __future__ import annotations`.
"""

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "prismor"
NEW_GENERICS = {"list", "dict", "set", "tuple", "frozenset", "type"}


def _too_new(node):
    """Annotation subtrees that 3.8 cannot evaluate."""
    for n in ast.walk(node):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
            yield "PEP 604 union"
        elif isinstance(n, ast.Subscript) and getattr(n.value, "id", None) in NEW_GENERICS:
            yield f"builtin generic {n.value.id}[...]"


def test_annotations_evaluate_on_the_declared_floor():
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(
            isinstance(n, ast.ImportFrom)
            and n.module == "__future__"
            and any(a.name == "annotations" for a in n.names)
            for n in tree.body
        ):
            continue
        for node in ast.walk(tree):
            annotations = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                annotations = [a.annotation for a in node.args.args + node.args.kwonlyargs]
                annotations += [node.returns]
            elif isinstance(node, ast.AnnAssign):
                annotations = [node.annotation]
            for ann in filter(None, annotations):
                for why in _too_new(ann):
                    offenders.append(f"{path.relative_to(PKG.parent)}:{ann.lineno}: {why}")
    assert not offenders, "add `from __future__ import annotations` to:\n" + "\n".join(offenders)
