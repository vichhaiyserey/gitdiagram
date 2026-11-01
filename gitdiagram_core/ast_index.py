"""Per-file Python AST extraction: definitions, imports, calls, and assignments."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

MAX_TEXT = 240


def _text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        rendered = ast.unparse(node)
    except Exception:  # pragma: no cover - defensive for exotic nodes
        rendered = node.__class__.__name__
    rendered = " ".join(rendered.split())
    if len(rendered) > MAX_TEXT:
        rendered = rendered[: MAX_TEXT - 3] + "..."
    return rendered


@dataclass(slots=True)
class ImportRec:
    module: str | None
    names: list[tuple[str, str | None]]
    level: int
    line: int
    is_from: bool
    star: bool = False


@dataclass(slots=True)
class DefRec:
    kind: str
    name: str
    qualname: str
    path: str
    line: int
    col: int
    end_line: int
    doc: str | None
    decorators: list[str] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    parent: str | None = None
    args: list[str] = field(default_factory=list)
    positional_args: list[str] = field(default_factory=list)
    arg_types: dict[str, str] = field(default_factory=dict)
    return_type: str | None = None
    is_async: bool = False
    routes: list[dict[str, str]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CallRec:
    scope: str
    scope_kind: str
    callee: str
    line: int
    col: int
    arg_texts: list[str] = field(default_factory=list)
    arg_names: list[str] = field(default_factory=list)
    arg_names_by_position: list[list[str]] = field(default_factory=list)
    keywords: dict[str, str] = field(default_factory=dict)
    assigned_to: list[str] = field(default_factory=list)
    has_star: bool = False
    has_fstring: bool = False
    is_await: bool = False


@dataclass(slots=True)
class AssignRec:
    scope: str
    target: str
    value_text: str
    value_names: list[str] = field(default_factory=list)
    value_callee: str | None = None
    value_type: str | None = None
    line: int = 0


@dataclass(slots=True)
class FileIndex:
    path: str
    module: str
    is_package: bool
    doc: str | None = None
    imports: list[ImportRec] = field(default_factory=list)
    defs: list[DefRec] = field(default_factory=list)
    calls: list[CallRec] = field(default_factory=list)
    assigns: list[AssignRec] = field(default_factory=list)
    strings: list[tuple[str, int]] = field(default_factory=list)
    error: str | None = None
    text: str = ""


def _expr_names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(_text(child))
    return sorted(names)


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        out: list[str] = []
        for element in node.elts:
            out.extend(_target_names(element))
        return out
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return [_text(node)]
    return []


def _has_fstring(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            return True
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "format":
            return True
    return False


class _Indexer(ast.NodeVisitor):
    def __init__(self, path: str, module: str, is_package: bool) -> None:
        self.index = FileIndex(path=path, module=module, is_package=is_package)
        self.scope: list[tuple[str, str]] = [(module, "module")]

    @property
    def current_scope(self) -> tuple[str, str]:
        return self.scope[-1]

    def visit_Module(self, node: ast.Module) -> None:
        self.index.doc = ast.get_docstring(node, clean=True)
        for child in node.body:
            self.visit(child)

    def _decorators(self, node: ast.AST) -> list[str]:
        out = []
        for dec in getattr(node, "decorator_list", []):
            out.append(_text(dec))
        return out

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, kind: str | None = None) -> None:
        parent, parent_kind = self.current_scope
        qualname = f"{parent}.{node.name}" if parent else node.name
        actual_kind = kind or ("method" if parent_kind == "class" else "function")
        positional = [arg.arg for arg in node.args.posonlyargs + node.args.args]
        all_args = (
            positional
            + ([node.args.vararg.arg] if node.args.vararg else [])
            + [arg.arg for arg in node.args.kwonlyargs]
            + ([node.args.kwarg.arg] if node.args.kwarg else [])
        )
        arg_types = {}
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            if arg.annotation is not None:
                arg_types[arg.arg] = _text(arg.annotation)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg is not None and arg.annotation is not None:
                arg_types[arg.arg] = _text(arg.annotation)
        record = DefRec(
            kind=actual_kind,
            name=node.name,
            qualname=qualname,
            path=self.index.path,
            line=node.lineno,
            col=node.col_offset,
            end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            doc=ast.get_docstring(node, clean=True),
            decorators=self._decorators(node),
            parent=parent,
            args=all_args,
            positional_args=positional,
            arg_types=arg_types,
            return_type=_text(node.returns) if node.returns is not None else None,
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )
        self.index.defs.append(record)

        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            self.visit(default)

        self.scope.append((qualname, "function"))
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        parent, _ = self.current_scope
        qualname = f"{parent}.{node.name}" if parent else node.name
        record = DefRec(
            kind="class",
            name=node.name,
            qualname=qualname,
            path=self.index.path,
            line=node.lineno,
            col=node.col_offset,
            end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            doc=ast.get_docstring(node, clean=True),
            decorators=self._decorators(node),
            bases=[_text(base) for base in node.bases],
            parent=parent,
        )
        self.index.defs.append(record)
        self.scope.append((qualname, "class"))
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        names = [(alias.name, alias.asname) for alias in node.names]
        self.index.imports.append(
            ImportRec(module=None, names=names, level=0, line=node.lineno, is_from=False)
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        names = [(alias.name, alias.asname) for alias in node.names]
        star = any(name == "*" for name, _ in names)
        self.index.imports.append(
            ImportRec(
                module=node.module,
                names=names,
                level=node.level or 0,
                line=node.lineno,
                is_from=True,
                star=star,
            )
        )

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) <= 2000:
            self.index.strings.append((node.value, node.lineno))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets: list[str] = []
        for target in node.targets:
            targets.extend(_target_names(target))
        value_callee = _text(node.value.func) if isinstance(node.value, ast.Call) else None
        self.index.assigns.append(
            AssignRec(
                scope=self.current_scope[0],
                target=", ".join(targets),
                value_text=_text(node.value),
                value_names=_expr_names(node.value),
                value_callee=value_callee,
                line=node.lineno,
            )
        )
        if isinstance(node.value, ast.Call):
            self._record_call(node.value, assigned_to=targets)
        else:
            self.visit(node.value)
        for target in node.targets:
            if not isinstance(target, (ast.Name, ast.Tuple, ast.List)):
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        targets = _target_names(node.target)
        value_callee = _text(node.value.func) if isinstance(node.value, ast.Call) else None
        self.index.assigns.append(
            AssignRec(
                scope=self.current_scope[0],
                target=", ".join(targets),
                value_text=_text(node.value),
                value_names=_expr_names(node.value),
                value_callee=value_callee,
                value_type=_text(node.annotation),
                line=node.lineno,
            )
        )
        if isinstance(node.value, ast.Call):
            self._record_call(node.value, assigned_to=targets)
        elif node.value is not None:
            self.visit(node.value)
        self.visit(node.annotation)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        targets = _target_names(node.target)
        value_callee = _text(node.value.func) if isinstance(node.value, ast.Call) else None
        self.index.assigns.append(
            AssignRec(
                scope=self.current_scope[0],
                target=", ".join(targets),
                value_text=_text(node.value),
                value_names=_expr_names(node.value),
                value_callee=value_callee,
                line=node.lineno,
            )
        )
        if isinstance(node.value, ast.Call):
            self._record_call(node.value, assigned_to=targets)
        else:
            self.visit(node.value)
        self.visit(node.target)

    def _with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            targets = _target_names(item.optional_vars) if item.optional_vars is not None else []
            value_callee = _text(item.context_expr.func) if isinstance(item.context_expr, ast.Call) else None
            self.index.assigns.append(
                AssignRec(
                    scope=self.current_scope[0],
                    target=", ".join(targets),
                    value_text=_text(item.context_expr),
                    value_names=_expr_names(item.context_expr),
                    value_callee=value_callee,
                    line=getattr(item.context_expr, "lineno", node.lineno),
                )
            )
            if isinstance(item.context_expr, ast.Call):
                self._record_call(item.context_expr, assigned_to=targets)
            else:
                self.visit(item.context_expr)
        for child in node.body:
            self.visit(child)

    def visit_With(self, node: ast.With) -> None:
        self._with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._with(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._record_call(node)

    def _record_call(self, node: ast.Call, assigned_to: Iterable[str] | None = None) -> None:
        scope, scope_kind = self.current_scope
        args = list(node.args)
        self.index.calls.append(
            CallRec(
                scope=scope,
                scope_kind=scope_kind,
                callee=_text(node.func),
                line=node.lineno,
                col=node.col_offset,
                arg_texts=[_text(arg) for arg in args],
                arg_names=sorted({name for arg in args for name in _expr_names(arg)}),
                arg_names_by_position=[_expr_names(arg) for arg in args],
                keywords={kw.arg or "**": _text(kw.value) for kw in node.keywords},
                assigned_to=list(assigned_to or []),
                has_star=any(isinstance(arg, ast.Starred) for arg in args),
                has_fstring=any(_has_fstring(arg) for arg in args),
                is_await=isinstance(getattr(node, "parent", None), ast.Await),
            )
        )
        self.visit(node.func)
        for arg in args:
            self.visit(arg)
        for kw in node.keywords:
            self.visit(kw.value)


def module_name_for_path(path: str) -> tuple[str, bool]:
    """Derive a dotted module name from a repo-relative path."""
    parts = path.replace("\\", "/").split("/")
    is_package = parts[-1] == "__init__.py"
    if is_package:
        parts = parts[:-1]
    else:
        parts = parts[:-1] + [parts[-1][:-3]]
    if parts and parts[0] in {"src", "lib"} and len(parts) > 1:
        parts = parts[1:]
    if not parts:
        return "__init__", True
    return ".".join(parts), is_package


def index_file(root: Path, rel_path: str) -> FileIndex:
    module, is_package = module_name_for_path(rel_path)
    absolute = root / rel_path
    try:
        resolved = absolute.resolve()
        if not resolved.is_relative_to(root.resolve()):
            return FileIndex(path=rel_path, module=module, is_package=is_package, error="path escapes repository root")
    except (ValueError, OSError) as exc:
        return FileIndex(path=rel_path, module=module, is_package=is_package, error=f"path resolution error: {exc}")
    try:
        text = absolute.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        return FileIndex(path=rel_path, module=module, is_package=is_package, error=f"read error: {exc}")
    index = FileIndex(path=rel_path, module=module, is_package=is_package, text=text)
    try:
        tree = ast.parse(text, filename=rel_path)
    except (SyntaxError, ValueError) as exc:
        if isinstance(exc, SyntaxError):
            index.error = f"SyntaxError: {exc.msg} (line {exc.lineno})"
        else:
            index.error = f"{type(exc).__name__}: {exc}"
        return index
    visitor = _Indexer(rel_path, module, is_package)
    visitor.visit(tree)
    result = visitor.index
    result.text = text
    result.doc = ast.get_docstring(tree, clean=True)
    return result


def index_repo(root: Path, rel_paths: list[str]) -> dict[str, FileIndex]:
    indexes: dict[str, FileIndex] = {}
    for rel_path in rel_paths:
        indexes[rel_path] = index_file(root, rel_path)
    return indexes
