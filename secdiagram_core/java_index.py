"""Standalone, stdlib-only lexical Java/Spring Boot analyzer.

Comments are masked, then a single brace-splitting pass yields nested code
blocks (with their declaration headers) and statements with line numbers.
Class / method / field recognition runs on those plain-text fragments, and
Spring annotations drive routing, stereotypes, dependency-injection edges,
and SAST heuristics mirroring ``security.py``.

Every output is deterministic: files are processed in sorted order and all
collections are sorted before serialization.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cache import IndexCache, file_digest, resolve_jobs
from .model import SEVERITY_RANK, Finding, Graph, Loc, Node, stable_id

MAX_TEXT = 240
MAX_SOURCE_BYTES = 5 * 1024 * 1024

MAPPING_ANN: dict[str, tuple[str, ...]] = {
    "GetMapping": ("GET",),
    "PostMapping": ("POST",),
    "PutMapping": ("PUT",),
    "DeleteMapping": ("DELETE",),
    "PatchMapping": ("PATCH",),
    "RequestMapping": ("ALL",),
}

STEREOTYPE_ANN: dict[str, str] = {
    "RestController": "controller",
    "Controller": "controller",
    "Service": "service",
    "Repository": "repository",
    "Component": "component",
    "Configuration": "configuration",
    "ControllerAdvice": "advice",
    "Entity": "entity",
}

TASK_ANN = frozenset({"Scheduled", "KafkaListener", "RabbitListener", "JmsListener", "EventListener"})

DI_ANN = frozenset({"Autowired", "Resource", "Inject", "PersistenceContext"})

CONTROL_KEYWORDS = frozenset(
    {"assert", "catch", "do", "else", "for", "if", "return", "synchronized", "switch", "throw", "throws", "try", "while"}
)

# --------------------------------------------------------------------- regexes
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT_RE = re.compile(r"//[^\n]*")
STRING_LITERAL_RE = re.compile(r'"(?:(?:\\.)|[^"\\\n])*"')
ANN_NAME_RE = re.compile(r"@(\w+)")
ANN_ARGS_RE = re.compile(r"@(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)")
CLASS_DECL_RE = re.compile(
    r"\b(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+|static\s+|strictfp\s+|sealed\s+|non-sealed\s+)*"
    r"(class|interface|enum|record)\s+([A-Za-z_$][\w$]*)"
    r"(?:\s+extends\s+([^{]+?))?"
    r"(?:\s+implements\s+([^{]+?))?\s*(?:\{|$)"
)
METHOD_DECL_RE = re.compile(
    r"^(?:public|protected|private|static|final|abstract|synchronized|native|default|strictfp)\b"
    r"[\w\s$<>]*?"
    r"([\w.$<>]+(?:<[^<>]*>)?(?:\[\])*)\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*"
    r"(?:throws\s+[\w.,$\s]+)?$"
)
CONSTRUCTOR_DECL_RE = re.compile(r"^(?:public|protected|private)\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)$")
FIELD_RE = re.compile(
    r"^(?:(?:public|protected|private|static|final|transient|volatile)\s+)*"
    r"([A-Za-z_$][\w.$<>]*?(?:<[^<>]*>)?(?:\[\])*)\s+([a-z_$][\w$]*)\s*(?:=[^;]*)?$"
)
PACKAGE_RE = re.compile(r"^package\s+([\w.]+)\s*;?\s*$")
IMPORT_RE = re.compile(r"^import\s+(?:static\s+)?([\w.*]+)\s*;?\s*$")
CALL_TEXT_RE = re.compile(r"\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
NEW_TEXT_RE = re.compile(r"\bnew\s+([A-Za-z_$][\w.$]*)(?:\s*<[^<>]*>)*\s*\(")
LOCAL_ASSIGN_RE = re.compile(
    r"^(?:final\s+)?([A-Z][\w.$<>]*)\s+([a-z_$][\w$]*)\s*=\s*(?:new\s+([A-Z][\w.$<>]*))?"
)
VALUE_KEY_RE = re.compile(r'(?:value|path)\s*=\s*"([^"]*)"')

# --------------------------------------------------------------- SAST patterns
SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[\s;:\"'])([\w.\-]*?(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token)[\w.\-]*)\s*[:=]\s*(\S.*)"
)
SECRET_PLACEHOLDERS = frozenset(
    {"changeme", "change_me", "password", "secret", "example", "none", "null", "todo", "xxx", "placeholder"}
)
SECRET_PREFIXES = ("$", "${", "<", "your_", "your-", "env.", "os.", "***", "ENC(", "{noop}")

SECRET_CWE = "CWE-798"
SECRET_RECOMMENDATION = "Remove the secret from source, rotate it, and load it from environment variables or a secret manager."

TAINT_PARAM_ANN_RE = re.compile(
    r"@(?:Request|Path|Query|Form|Session|RequestHeader|Cookie|ModelAttribute|RequestBody|SessionAttribute)\w*"
)
TAINT_SOURCE_CALL_RE = re.compile(
    r"\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|"
    r"getInputStream|getReader|getQueryString|getPart|getParts|getCookies|"
    r"getRequestURI|getPathInfo|getServletPath|getRemoteUser)\s*\("
)

JAVA_SANITIZERS: dict[str, re.Pattern[str]] = {
    "sql": re.compile(
        r"\b(?:Integer|Long|Double|Float|Boolean)\.(?:parse\w+|valueOf)\s*\(|"
        r"\b(?:ESAPI\.encoder\(\)\.encodeForSQL|setString|setInt|setLong)\s*\("
    ),
    "command": re.compile(
        r"\b(?:Integer|Long)\.(?:parse\w+|valueOf)\s*\(|"
        r"\b(?:ESAPI\.encoder\(\)\.encodeForOS|StringEscapeUtils\.escapeShell)\s*\("
    ),
    "xss": re.compile(
        r"\b(?:StringEscapeUtils\.escapeHtml\w*|Encode\.forHtml\w*|"
        r"ESAPI\.encoder\(\)\.encodeForHTML\w*|escapeHtml\w*)\s*\("
    ),
    "path": re.compile(
        r"\b(?:FilenameUtils\.getName|File\.getName|Path\.getFileName)\s*\("
    ),
    "xxe": re.compile(
        r"\bsetFeature\s*\([^)]*(?:disallow-doctype-decl|external-general-entities|"
        r"external-parameter-entities)[^)]*true|setExpandEntityReferences\s*\(\s*false"
    ),
}

# (category, sink regex, cwe, title, remediation, tainted_severity, base_severity)
JAVA_SINK_RULES: tuple[tuple[str, str, str, str, str, str, str | None], ...] = (
    (
        "sql",
        r"\b(?:createQuery|createNativeQuery|createSQLQuery|prepareStatement|prepareCall)\s*\(|"
        r"\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|addBatch)\s*\(",
        "CWE-89",
        "Possible SQL injection (Java)",
        "Use parameterized queries (EntityManager bindings or JDBC PreparedStatement) instead of string concatenation.",
        "critical",
        "medium",
    ),
    (
        "command",
        r"\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder)\s*\(",
        "CWE-78",
        "Possible command injection (Java)",
        "Avoid executing raw command strings; validate and allowlist user-controlled values.",
        "critical",
        "medium",
    ),
    (
        "deserialization",
        r"\b(?:readObject|readUnshared|readValue|XMLDecoder)\s*\(|\.\s*fromXML\s*\(",
        "CWE-502",
        "Unsafe deserialization (Java)",
        "Never deserialize untrusted Java objects; prefer format-constrained JSON binding with type allowlists.",
        "critical",
        "medium",
    ),
    (
        "code",
        r"\b(?:eval|parseExpression)\s*\(",
        "CWE-95",
        "Dynamic code execution (Java)",
        "Do not evaluate user-controlled expressions or scripts; use a fixed dispatch table.",
        "critical",
        "medium",
    ),
    (
        "template",
        r"\b(?:process|evaluate|mergeTemplateIntoString)\s*\(",
        "CWE-1336",
        "Possible server-side template injection (Java)",
        "Do not render user-controlled template source; use fixed templates and context variables.",
        "critical",
        "medium",
    ),
    (
        "crypto",
        r'(?:MessageDigest|KeyGenerator|KeyPairGenerator)\s*\.\s*getInstance\s*\(\s*"(MD5|SHA-?1|DES|DESede|RC2|RC4|Blowfish)"|'
        r'Cipher\s*\.\s*getInstance\s*\(\s*"(DES|DESede|Blowfish|RC2|RC4|AES[^"]*ECB)',
        "CWE-327",
        "Weak cryptographic primitive (Java)",
        "Use SHA-256 or stronger digests and AES-GCM with random IVs; never ECB for data.",
        "medium",
        "medium",
    ),
    (
        "network",
        r"\.\s*(?:openConnection|openStream|getForObject|getForEntity|postForObject|postForEntity|exchange|execute)\s*\(|"
        r"\b(?:HttpClient|WebClient|RestTemplate)\s*\.\s*(?:create|builder|newHttpClient)\s*\(",
        "CWE-918",
        "Server-side request with untrusted destination (Java)",
        "Validate and allowlist outbound destinations; block link-local and metadata addresses.",
        "high",
        None,
    ),
    (
        "path",
        r"\bnew\s+File\s*\(|\bPaths\s*\.\s*get\s*\(|\bnew\s+FileInputStream\s*\(|"
        r"\bnew\s+FileOutputStream\s*\(|\bFiles\s*\.\s*(?:readAllBytes|write|newInputStream|newOutputStream)\s*\(|"
        r"\.getResourceAsStream\s*\(|\.getRealPath\s*\(",
        "CWE-22",
        "Possible path traversal (Java)",
        "Resolve paths against an allowlisted base directory and reject traversal segments.",
        "high",
        None,
    ),
    (
        "xss",
        r"\.getWriter\s*\(\s*\)\s*\.\s*(?:println|print|write)\s*\(",
        "CWE-79",
        "Possible reflected XSS (Java)",
        "Escape output or use template engines with context-aware auto-encoding.",
        "medium",
        None,
    ),
    (
        "redirect",
        r"\b(?:sendRedirect|RedirectView)\s*\(|"
        r"\.\s*setViewName\s*\(\s*\"redirect:",
        "CWE-601",
        "Possible open redirect (Java)",
        "Validate redirect targets against an allowlist of trusted destinations.",
        "medium",
        None,
    ),
    (
        "xxe",
        r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReader)\b|"
        r"\.\s*(?:parse|unmarshal)\s*\(",
        "CWE-611",
        "Possible XML external entity injection (Java)",
        "Disable DTDs and external entities on the XML parser factory.",
        "high",
        None,
    ),
)


# ------------------------------------------------------------ parsing structures
@dataclass(slots=True)
class _Block:
    depth: int
    header: str
    line: int
    parent: int | None = None
    kind: str = "block"  # class | interface | enum | record | method | block
    statement_start: int = 0
    statement_end: int = 0


@dataclass(slots=True)
class _Stmt:
    depth: int
    line: int
    text: str
    owner: int | None = None


@dataclass(slots=True)
class JavaCall:
    callee: str
    line: int
    instantiates: bool = False

    def to_payload(self) -> dict[str, Any]:
        return {"callee": self.callee, "line": self.line, "instantiates": self.instantiates}

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> JavaCall:
        return cls(
            callee=str(data["callee"]),
            line=int(data.get("line", 0)),
            instantiates=bool(data.get("instantiates", False)),
        )


@dataclass(slots=True)
class JavaMethod:
    name: str
    qualname: str
    path: str
    line: int
    params: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    body: list[tuple[int, str]] = field(default_factory=list)
    locals: dict[str, str] = field(default_factory=dict)
    routes: list[dict[str, str]] = field(default_factory=list)
    role: str | None = None  # endpoint | task

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qualname": self.qualname,
            "path": self.path,
            "line": self.line,
            "params": self.params,
            "annotations": self.annotations,
            "body": [[line, text] for line, text in self.body],
            "locals": self.locals,
            "routes": self.routes,
            "role": self.role,
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> JavaMethod:
        return cls(
            name=str(data["name"]),
            qualname=str(data["qualname"]),
            path=str(data.get("path", "")),
            line=int(data.get("line", 0)),
            params=list(data.get("params", [])),
            annotations=list(data.get("annotations", [])),
            body=[(int(item[0]), str(item[1])) for item in data.get("body", [])],
            locals=dict(data.get("locals", {})),
            routes=[dict(item) for item in data.get("routes", [])],
            role=data.get("role"),
        )

    def tainted_vars(self) -> set[str]:
        """Parameter variable names that may carry request-derived input."""
        tainted: set[str] = set()
        for param in self.params:
            if TAINT_PARAM_ANN_RE.search(param):
                token = param.split()[-1].rstrip(",) ")
                name = token.split("=")[0].strip()
                if name and name.isidentifier():
                    tainted.add(name)
        return tainted


@dataclass(slots=True)
class JavaField:
    name: str
    type_name: str
    qualname: str
    path: str
    line: int
    annotations: list[str] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type_name": self.type_name,
            "qualname": self.qualname,
            "path": self.path,
            "line": self.line,
            "annotations": self.annotations,
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> JavaField:
        return cls(
            name=str(data["name"]),
            type_name=str(data.get("type_name", "")),
            qualname=str(data.get("qualname", "")),
            path=str(data.get("path", "")),
            line=int(data.get("line", 0)),
            annotations=list(data.get("annotations", [])),
        )

    def is_injected(self) -> bool:
        return bool(set(self.annotations) & DI_ANN)


@dataclass(slots=True)
class JavaClassDef:
    kind: str  # class | interface | enum | record
    name: str
    qualname: str
    package: str
    path: str
    line: int
    extends: list[str] = field(default_factory=list)
    implements: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    request_mapping: str = ""
    methods: list[JavaMethod] = field(default_factory=list)
    fields: list[JavaField] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "qualname": self.qualname,
            "package": self.package,
            "path": self.path,
            "line": self.line,
            "extends": self.extends,
            "implements": self.implements,
            "annotations": self.annotations,
            "request_mapping": self.request_mapping,
            "methods": [item.to_payload() for item in self.methods],
            "fields": [item.to_payload() for item in self.fields],
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> JavaClassDef:
        return cls(
            kind=str(data.get("kind", "class")),
            name=str(data["name"]),
            qualname=str(data.get("qualname", "")),
            package=str(data.get("package", "")),
            path=str(data.get("path", "")),
            line=int(data.get("line", 0)),
            extends=list(data.get("extends", [])),
            implements=list(data.get("implements", [])),
            annotations=list(data.get("annotations", [])),
            request_mapping=str(data.get("request_mapping", "")),
            methods=[JavaMethod.from_payload(item) for item in data.get("methods", [])],
            fields=[JavaField.from_payload(item) for item in data.get("fields", [])],
        )

    def stereotype(self) -> str | None:
        for annotation in self.annotations:
            if annotation in STEREOTYPE_ANN:
                return STEREOTYPE_ANN[annotation]
        bases = self.extends + self.implements
        if any("Repository" in base for base in bases):
            return "repository"
        return None


@dataclass(slots=True)
class JavaFileIndex:
    path: str
    package: str = ""
    imports: list[str] = field(default_factory=list)
    classes: list[JavaClassDef] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "package": self.package,
            "imports": self.imports,
            "classes": [item.to_payload() for item in self.classes],
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> JavaFileIndex:
        return cls(
            path=str(data["path"]),
            package=str(data.get("package", "")),
            imports=list(data.get("imports", [])),
            classes=[JavaClassDef.from_payload(item) for item in data.get("classes", [])],
        )


@dataclass(slots=True)
class JavaProject:
    name: str
    path: str
    build_tool: str  # maven | gradle
    dependencies: set[str] = field(default_factory=set)


@dataclass(slots=True)
class JavaIndex:
    files: dict[str, JavaFileIndex] = field(default_factory=dict)
    classes_by_qualname: dict[str, JavaClassDef] = field(default_factory=dict)
    classes_by_name: dict[str, JavaClassDef] = field(default_factory=dict)
    projects: list[JavaProject] = field(default_factory=list)
    property_files: list[str] = field(default_factory=list)
    unresolved_count: int = 0

    def controllers(self) -> list[JavaClassDef]:
        return sorted(
            (cls for cls in self.classes_by_qualname.values() if cls.stereotype() == "controller"),
            key=lambda cls: cls.qualname,
        )

    def services(self) -> list[JavaClassDef]:
        return sorted(
            (cls for cls in self.classes_by_qualname.values() if cls.stereotype() == "service"),
            key=lambda cls: cls.qualname,
        )

    def model_classes(self) -> list[JavaClassDef]:
        return sorted(
            (cls for cls in self.classes_by_qualname.values() if cls.stereotype() == "entity"),
            key=lambda cls: cls.qualname,
        )


# ----------------------------------------------------------------------- utils
def _mask(text: str) -> str:
    """Blank out comments while preserving strings, quotes and newlines."""

    out: list[str] = []
    i = 0
    length = len(text)
    quote: str | None = None
    in_block = False
    in_line = False
    while i < length:
        ch = text[i]
        if in_block:
            if text.startswith("*/", i):
                in_block = False
                out.append("  ")
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue
        if in_line:
            if ch == "\n":
                in_line = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if quote is not None:
            out.append(ch)
            if ch == "\\" and i + 1 < length:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if text.startswith("//", i):
            in_line = True
            out.append("  ")
            i += 2
            continue
        if text.startswith("/*", i):
            in_block = True
            out.append("  ")
            i += 2
            continue
        if ch in {'"', "'"}:
            quote = ch
        out.append(ch)
        i += 1
    return "".join(out)


def _short(text: str) -> str:
    rendered = " ".join(text.split())
    if len(rendered) > MAX_TEXT:
        rendered = rendered[: MAX_TEXT - 3] + "..."
    return rendered


def _simple_name(text: str) -> str:
    return text.rsplit(".", 1)[-1].split("$")[0].strip("<>[], ")


def _strip_annotations(text: str) -> tuple[str, list[str]]:
    names = list(dict.fromkeys(ANN_NAME_RE.findall(text)))
    cleaned = ANN_ARGS_RE.sub(" ", text)
    cleaned = ANN_NAME_RE.sub(" ", cleaned)
    return " ".join(cleaned.split()), names


def _callee_tokens(text: str) -> list[str]:
    found: list[str] = []
    for callee in CALL_TEXT_RE.findall(text):
        parts = [part.strip() for part in re.split(r"\s*\.\s*", callee.strip()) if part]
        if not parts:
            continue
        if parts[0] == "this":
            parts = parts[1:]
        if parts and parts[0] in CONTROL_KEYWORDS:
            parts = parts[1:]
        if parts:
            found.append(" ".join(parts).replace(" . ", ".").replace(". ", ".").replace(" .", "."))
    return [token.replace(" ", "") for token in found]


def _new_tokens(text: str) -> list[str]:
    return [match for match in NEW_TEXT_RE.findall(text) if match]


def _dedupe_routes(routes: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: dict[tuple[str, str], dict[str, str]] = {}
    for route in routes:
        key = (route["method"], route["path"])
        seen.setdefault(key, route)
    return [seen[key] for key in sorted(seen)]


def _route_path(args: str) -> str:
    match = VALUE_KEY_RE.search(args)
    if match:
        return match.group(1)
    literal = STRING_LITERAL_RE.search(args)
    return literal.group(0)[1:-1] if literal else ""


# ------------------------------------------------- block/statement tokenization
def _split_blocks(masked_lines: list[str]) -> tuple[list[_Block], list[_Stmt]]:
    blocks: list[_Block] = []
    statements: list[_Stmt] = []
    stack: list[int] = []
    depth = 0
    buffer: list[str] = []
    buffer_line = 0

    for number, raw in enumerate(masked_lines, start=1):
        i = 0
        quote: str | None = None
        while i < len(raw):
            ch = raw[i]
            if quote is not None:
                if not buffer:
                    buffer_line = number
                buffer.append(ch)
                if ch == "\\" and i + 1 < len(raw):
                    buffer.append(raw[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch in {'"', "'"}:
                quote = ch
                if not buffer:
                    buffer_line = number
                buffer.append(ch)
                i += 1
                continue
            if ch == "{":
                header = " ".join("".join(buffer).split())
                block = _Block(
                    depth=depth + 1,
                    header=header,
                    line=buffer_line or number,
                    parent=stack[-1] if stack else None,
                )
                block.statement_start = len(statements)
                blocks.append(block)
                stack.append(len(blocks) - 1)
                buffer = []
                buffer_line = 0
                depth += 1
                i += 1
            elif ch == "}":
                if stack:
                    blocks[stack.pop()].statement_end = len(statements)
                if buffer:
                    buffer = []
                    buffer_line = 0
                depth -= 1
                i += 1
            elif ch == ";":
                text = " ".join("".join(buffer).split())
                if text:
                    statements.append(
                        _Stmt(depth=depth, line=buffer_line or number, text=text, owner=stack[-1] if stack else None)
                    )
                buffer = []
                buffer_line = 0
                i += 1
            else:
                if not buffer:
                    buffer_line = number
                buffer.append(ch)
                i += 1
        if buffer:
            buffer.append(" ")
    return blocks, statements


def _descendants(blocks: list[_Block], idx: int) -> set[int]:
    out: set[int] = set()
    frontier = [idx]
    while frontier:
        current = frontier.pop()
        for position, block in enumerate(blocks):
            if block.parent == current and position not in out:
                out.add(position)
                frontier.append(position)
    return out


def _classify_block(header: str) -> tuple[str, re.Match[str] | None]:
    if not header:
        return "block", None
    class_match = CLASS_DECL_RE.search(header)
    if class_match:
        return class_match.group(1), class_match
    cleaned_header, _ = _strip_annotations(header)
    constructor = CONSTRUCTOR_DECL_RE.match(cleaned_header)
    if constructor:
        return "method", constructor
    method_match = METHOD_DECL_RE.match(cleaned_header)
    if method_match and _is_method_header(cleaned_header, method_match):
        return "method", method_match
    return "block", None


def _is_method_header(header: str, match: re.Match[str]) -> bool:
    name = match.group(2)
    ret = match.group(1).strip()
    if not name or name.lower() in CONTROL_KEYWORDS:
        return False
    if name.upper() in {"IF", "FOR", "WHILE", "SWITCH", "CATCH"}:
        return False
    # constructors have no return type; METHOD_DECL_RE requires one
    if not ret:
        return False
    # exclude qualifiers like `foo.bar.method(`
    return "." not in name


# --------------------------------------------------------------------- parser
def parse_java_file(path: str, text: str) -> JavaFileIndex:
    parser = JavaParser(path, text)
    return parser.parse()


class JavaParser:
    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.masked_lines = _mask(text).splitlines()

    def parse(self) -> JavaFileIndex:
        blocks, statements = _split_blocks(self.masked_lines)
        index = JavaFileIndex(path=self.path)

        for raw in self.masked_lines:
            line = " ".join(raw.split())
            package = PACKAGE_RE.match(line)
            if package and not index.package:
                index.package = package.group(1)
            imported = IMPORT_RE.match(line)
            if imported:
                index.imports.append(imported.group(1))
        index.imports = sorted(dict.fromkeys(index.imports))

        # classify once
        kinds: list[tuple[str, re.Match[str] | None]] = [_classify_block(b.header) for b in blocks]

        # find top-level class blocks: parent None or parent is not class
        for idx, block in enumerate(blocks):
            kind, match = kinds[idx]
            if match is None or kind not in {"class", "interface", "enum", "record"}:
                continue
            parent = block.parent
            if parent is not None and kinds[parent][0] == "method":
                continue
            cls = self._class_from(match, block, index.package)
            # nested classes
            for nested_idx in sorted(_descendants(blocks, idx)):
                nested_block = blocks[nested_idx]
                nested_kind, nested_match = kinds[nested_idx]
                if nested_match is None or nested_kind not in {"class", "interface", "enum", "record"}:
                    continue
                nested = self._class_from(
                    nested_match, nested_block, package=f"{cls.qualname}", parent_kind="nested"
                )
                index.classes.append(nested)
            # methods: direct children only
            for child_idx in sorted(_descendants(blocks, idx)):
                child = blocks[child_idx]
                if child.parent != idx:
                    continue
                child_kind, child_match = kinds[child_idx]
                if child_kind == "method" and child_match is not None:
                    cls.methods.append(self._method_from(child, child_match, cls, blocks, statements))
            # fields: statements directly owned by the class block
            for position in range(block.statement_start, block.statement_end):
                stmt = statements[position]
                if stmt.owner != idx:
                    continue
                cleaned_text, annotations = _strip_annotations(stmt.text)
                field_match = FIELD_RE.match(cleaned_text)
                if field_match and "(" not in cleaned_text:
                    cls.fields.append(
                        JavaField(
                            name=field_match.group(2),
                            type_name=_simple_name(field_match.group(1)),
                            qualname=f"{cls.qualname}.{field_match.group(2)}",
                            path=self.path,
                            line=stmt.line,
                            annotations=annotations,
                        )
                    )
            index.classes.append(cls)

        # deterministic file-level class ordering by line
        index.classes.sort(key=lambda cls: (cls.line, cls.name))
        return index

    def _class_from(self, match: re.Match[str], block: _Block, package: str, parent_kind: str = "") -> JavaClassDef:
        kind = match.group(1)
        name = match.group(2)
        extends = [_simple_name(part) for part in re.split(r",", match.group(3) or "") if _simple_name(part)]
        implements = [_simple_name(part) for part in re.split(r",", match.group(4) or "") if _simple_name(part)]
        _, annotations = _strip_annotations(block.header)
        request_mapping = ""
        for annotation_name, args in ANN_ARGS_RE.findall(block.header):
            if annotation_name == "RequestMapping" and args and not request_mapping:
                request_mapping = _route_path(args)
        return JavaClassDef(
            kind=kind,
            name=name,
            qualname=f"{package}.{name}" if package else name,
            package=package,
            path=self.path,
            line=block.line,
            extends=extends,
            implements=implements,
            annotations=annotations,
            request_mapping=request_mapping,
        )

    def _method_from(
        self,
        block: _Block,
        match: re.Match[str],
        cls: JavaClassDef,
        blocks: list[_Block],
        statements: list[_Stmt],
    ) -> JavaMethod:
        header = block.header
        cleaned_header, annotations = _strip_annotations(header)
        constructor = CONSTRUCTOR_DECL_RE.match(cleaned_header)
        params_raw = ""
        name = ""
        if constructor:
            name = constructor.group(1)
            params_raw = constructor.group(2)
        else:
            name = match.group(2)
            params_raw = match.group(3)
            # Keep parameter annotations (e.g. @RequestParam) for taint tracking.
            header_params = re.search(
                r"[A-Za-z_$][\w$]*\s*\(([^()]*)\)\s*(?:throws\s+[\w.,$\s]+)?$", header
            )
            if header_params:
                params_raw = header_params.group(1)
        method = JavaMethod(
            name=name,
            qualname=f"{cls.qualname}.{name}",
            path=self.path,
            line=block.line,
            params=[part.strip() for part in params_raw.split(",") if part.strip()],
            annotations=annotations,
        )
        routes: list[dict[str, str]] = []
        for annotation_name, args in ANN_ARGS_RE.findall(header):
            if annotation_name in MAPPING_ANN:
                path_part = (_route_path(args) if args else "").strip("/")
                base = cls.request_mapping.strip("/")
                path = "/" + "/".join(part for part in (base, path_part) if part)
                for request_method in MAPPING_ANN[annotation_name]:
                    if request_method == "ALL":
                        for verb in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            routes.append({"method": verb, "path": path})
                    else:
                        routes.append({"method": request_method, "path": path})
            if annotation_name in TASK_ANN:
                method.role = "task"
        if routes:
            method.routes = _dedupe_routes(routes)
            method.role = "endpoint"

        # method body: statements owned by the method block or any descendant
        own_idx = self._block_index(blocks, block)
        owned = {own_idx} | _descendants(blocks, own_idx)
        for stmt in statements:
            if stmt.owner not in owned:
                continue
            cleaned_body, _ = _strip_annotations(stmt.text)
            if cleaned_body:
                method.body.append((stmt.line, cleaned_body))
        # locals map
        for _line, text in method.body:
            local = LOCAL_ASSIGN_RE.match(text)
            if local:
                method.locals[_simple_name(local.group(2))] = _simple_name(local.group(1))
        return method

    @staticmethod
    def _block_index(blocks: list[_Block], block: _Block) -> int:
        for position, candidate in enumerate(blocks):
            if candidate is block:
                return position
        return -1


def _resolve_class(index: JavaIndex, name: str) -> JavaClassDef | None:
    if not name:
        return None
    return index.classes_by_name.get(_simple_name(name))


# ------------------------------------------------------------------- manifests
def parse_pom(root_dir: Path, rel_path: str) -> JavaProject | None:
    target = root_dir / rel_path
    try:
        resolved = target.resolve()
        if not resolved.is_relative_to(root_dir.resolve()) or not resolved.is_file():
            return None
        if resolved.stat().st_size > MAX_SOURCE_BYTES:
            return None
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        return None

    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        if re.search(r"<!ENTITY\s+", text, re.IGNORECASE) or re.search(r"<!DOCTYPE[^>]*\[", text, re.IGNORECASE):
            return None

    try:
        root_element = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        return None

    deps: set[str] = set()
    for dep in root_element.iter():
        if dep.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        artifact = None
        group = ""
        for child in dep:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "artifactId" and (child.text or "").strip():
                artifact = (child.text or "").strip()
            elif tag == "groupId" and (child.text or "").strip():
                group = (child.text or "").strip()
        if artifact:
            deps.add(f"{group}:{artifact}")
    name = ""
    for child in root_element:
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "artifactId":
            name = (child.text or "").strip()
    if not name:
        name = rel_path.rsplit("/", 1)[0].split("/")[-1] if "/" in rel_path else "java_project"
    return JavaProject(name=name, path=rel_path, build_tool="maven", dependencies=deps)


GRADLE_DEP_RE = re.compile(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|implementation platform)\s*[('\"]([\w.\-]+:[\w.\-]+)")

def parse_gradle(root_dir: Path, rel_path: str) -> JavaProject | None:
    target = root_dir / rel_path
    try:
        resolved = target.resolve()
        if not resolved.is_relative_to(root_dir.resolve()) or not resolved.is_file():
            return None
        if resolved.stat().st_size > MAX_SOURCE_BYTES:
            return None
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        return None
    name = ""
    archive = re.search(r'rootProject\.name\s*=\s*["\']([^"\']+)["\']', text)
    if archive:
        name = archive.group(1)
    deps = set(match.group(1) for match in GRADLE_DEP_RE.finditer(text))
    deps2 = set()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(("implementation", "api", "compileOnly", "runtimeOnly", "testImplementation")):
            continue
        for match in re.finditer(r"[('\"]((?:[\w.\-]+:)?[\w.\-]+(?::[\w.\-]+)?)['\")]", line):
            deps2.add(match.group(1))
    deps2 = {dep for dep in (deps | deps2) if "gradle" not in dep.split(":")[0]}
    if not name:
        name = rel_path.rsplit("/", 1)[0].split("/")[-1] if "/" in rel_path else "java_project"
    return JavaProject(name=name, path=rel_path, build_tool="gradle", dependencies=deps2)


# ------------------------------------------------------------------- discovery
def _load_java_file(root: Path, rel_path: str) -> JavaFileIndex | None:
    target = root / rel_path
    try:
        resolved = target.resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            return None
        if resolved.stat().st_size > MAX_SOURCE_BYTES:
            return None
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        return None
    return parse_java_file(rel_path, text)


def _parse_java_task(root: str, rel_path: str) -> JavaFileIndex | None:
    return _load_java_file(Path(root), rel_path)


def index_java(
    root: Path,
    rel_files: list[str],
    *,
    jobs: int = 1,
    cache: IndexCache | None = None,
) -> JavaIndex:
    """Index every Java source and manifest in the repository, deterministically."""
    index = JavaIndex()
    java_files = sorted(path for path in rel_files if path.endswith(".java"))
    parsed: dict[str, JavaFileIndex] = {}
    misses: list[tuple[str, str]] = []

    for path in java_files:
        digest = file_digest(root / path) if cache is not None and cache.enabled else None
        if digest is not None and cache is not None:
            payload = cache.load(path, digest)
            if payload is not None:
                try:
                    parsed[path] = JavaFileIndex.from_payload(payload)
                    continue
                except (KeyError, TypeError, ValueError, IndexError):
                    cache.errors += 1
        misses.append((path, digest or ""))

    workers = resolve_jobs(jobs, len(misses))
    if workers <= 1 or len(misses) < 2:
        for path, digest in misses:
            file_index = _load_java_file(root, path)
            if file_index is None:
                continue
            parsed[path] = file_index
            if cache is not None and digest:
                cache.save(path, digest, file_index.to_payload())
    else:
        try:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(_parse_java_task, str(root), path): (path, digest)
                    for path, digest in misses
                }
                for future in as_completed(futures):
                    path, digest = futures[future]
                    try:
                        file_index = future.result()
                    except Exception:  # pragma: no cover - worker crash fallback
                        file_index = _load_java_file(root, path)
                    if file_index is None:
                        continue
                    parsed[path] = file_index
                    if cache is not None and digest:
                        cache.save(path, digest, file_index.to_payload())
        except Exception:  # pragma: no cover - pool startup/runtime fallback
            for path, digest in misses:
                if path in parsed:
                    continue
                file_index = _load_java_file(root, path)
                if file_index is None:
                    continue
                parsed[path] = file_index
                if cache is not None and digest:
                    cache.save(path, digest, file_index.to_payload())

    for path in java_files:
        file_index = parsed.get(path)
        if file_index is None:
            continue
        index.files[path] = file_index
        for cls in file_index.classes:
            index.classes_by_qualname.setdefault(cls.qualname, cls)
            index.classes_by_name.setdefault(cls.name, cls)
    for path in sorted(rel_files):
        name = path.rsplit("/", 1)[-1]
        if name == "pom.xml":
            project = parse_pom(root, path)
            if project is not None:
                index.projects.append(project)
        elif name in {"build.gradle", "build.gradle.kts"}:
            project = parse_gradle(root, path)
            if project is not None:
                index.projects.append(project)
        elif name in {"application.properties", "application.yml", "application.yaml"}:
            index.property_files.append(path)
    return index

# --------------------------------------------------------------- graph builder
def _tag(node: Node, tag: str) -> None:
    tags = set(node.attrs.get("security", []))
    tags.add(tag)
    node.attrs["security"] = sorted(tags)


def build_java_graph(graph: Graph, index: JavaIndex) -> None:
    """Append Java nodes and edges to the graph (deterministic)."""
    packages: dict[str, str] = {}

    def package_id(package: str) -> str:
        if package not in packages:
            packages[package] = stable_id("jpackage", package)
        return packages[package]

    classes_by_simple = index.classes_by_name
    method_nodes: dict[str, str] = {}

    for path in sorted(index.files):
        file_index = index.files[path]
        for cls in sorted(file_index.classes, key=lambda c: (c.line, c.name)):
            stereotype = cls.stereotype()
            attrs: dict[str, Any] = {"java": True, "kind": cls.kind}
            if stereotype:
                attrs["stereotype"] = stereotype
            node = Node(
                id=stable_id("jclass", cls.path, cls.qualname),
                kind="class",
                name=cls.name,
                qualname=cls.qualname,
                path=cls.path,
                line=cls.line,
                attrs=attrs,
            )
            graph.add_node(node)
            if cls.package:
                pkg_node = graph.nodes.get(package_id(cls.package))
                if pkg_node is None:
                    pkg_node = Node(
                        id=package_id(cls.package),
                        kind="package",
                        name=cls.package,
                        qualname=cls.package,
                        attrs={"java": True, "language": "java"},
                    )
                    graph.add_node(pkg_node)
                graph.add_edge(
                    pkg_node.id,
                    node.id,
                    "contains",
                    confidence=1.0,
                    resolution="exact",
                    evidence=[Loc(cls.path, cls.line)],
                )
            for base in sorted(cls.extends + cls.implements):
                target = classes_by_simple.get(base)
                if target is None:
                    continue
                target_id = stable_id("jclass", target.path, target.qualname)
                if target_id not in graph.nodes or target_id == node.id:
                    continue
                graph.add_edge(
                    node.id,
                    target_id,
                    "inherits",
                    confidence=0.95,
                    resolution="java",
                    evidence=[Loc(cls.path, cls.line)],
                    attrs={"base": base},
                )
            for field_def in cls.fields:
                if field_def.is_injected():
                    target = _resolve_class(index, field_def.type_name)
                    if target is not None and target.qualname != cls.qualname:
                        graph.add_edge(
                            node.id,
                            stable_id("jclass", target.path, target.qualname),
                            "calls",
                            confidence=0.85,
                            resolution="autowired",
                            evidence=[Loc(field_def.path, field_def.line)],
                            attrs={"injection": ",".join(sorted(field_def.annotations)) or "field"},
                        )
            for method in sorted(cls.methods, key=lambda m: (m.line, m.name)):
                kind = "endpoint" if method.role == "endpoint" else ("task" if method.role == "task" else "method")
                attrs = {"java": True}
                if method.params:
                    attrs["args"] = [_short(_param_name(param)) for param in method.params]
                if stereotype:
                    attrs["stereotype"] = stereotype
                if method.body:
                    attrs["body_lines"] = len(method.body)
                if method.routes:
                    attrs["routes"] = sorted(method.routes, key=lambda r: (r["method"], r["path"]))
                node = Node(
                    id=stable_id("jsym", method.path, method.qualname),
                    kind=kind,
                    name=method.name,
                    qualname=method.qualname,
                    path=method.path,
                    line=method.line,
                    attrs=attrs,
                )
                graph.add_node(node)
                method_nodes[method.qualname] = node.id
                graph.add_edge(
                    graph.nodes[stable_id("jclass", cls.path, cls.qualname)].id,
                    node.id,
                    "contains",
                    confidence=1.0,
                    resolution="exact",
                    evidence=[Loc(method.path, method.line)],
                )

    # inter-class calls: resolve owner variables via fields/params/locals
    for path in sorted(index.files):
        file_index = index.files[path]
        for cls in sorted(file_index.classes, key=lambda c: (c.line, c.name)):
            field_types = {field_def.name: field_def.type_name for field_def in cls.fields}
            src_class_id = stable_id("jclass", cls.path, cls.qualname)
            for method in sorted(cls.methods, key=lambda m: (m.line, m.name)):
                src_self = stable_id("jsym", method.path, method.qualname)
                if src_self not in graph.nodes:
                    continue
                resolved_vars: dict[str, str] = {}
                for param in method.params:
                    tokens = [part for part in re.sub(r"[^\w.$ ]", " ", param).split() if part]
                    if len(tokens) >= 2:
                        resolved_vars[tokens[-1]] = _simple_name(tokens[-2])
                resolved_vars.update(field_types)
                resolved_vars.update(method.locals)
                for line_no, text in method.body:
                    for token in _new_tokens(text):
                        target = _resolve_class(index, token)
                        if target is None or target.qualname == cls.qualname:
                            continue
                        dst_exact = stable_id("jclass", target.path, target.qualname)
                        graph.add_edge(
                            src_self if src_self in graph.nodes else src_class_id,
                            dst_exact,
                            "instantiates",
                            confidence=0.9,
                            resolution="java",
                            evidence=[Loc(method.path, line_no)],
                            attrs={"type": token},
                        )
                    for token in _callee_tokens(text):
                        owner_text, _, callee_name = token.rpartition(".")
                        owner_name = owner_text.split(".")[-1] if owner_text else ""
                        var_type = resolved_vars.get(owner_name) if owner_name else None
                        if owner_name == "this" or not owner_name:
                            target_method = method_nodes.get(f"{cls.qualname}.{token if not owner_text else callee_name}")
                            if target_method and target_method != src_self:
                                graph.add_edge(
                                    src_self,
                                    target_method,
                                    "calls",
                                    confidence=0.9,
                                    resolution="java",
                                    evidence=[Loc(method.path, line_no)],
                                    attrs={"callee": _short(token)},
                                )
                            continue
                        target_cls = _resolve_class(index, var_type or owner_name)
                        if target_cls is None:
                            continue
                        target_cls_id = stable_id("jclass", target_cls.path, target_cls.qualname)
                        target_method_id = method_nodes.get(f"{target_cls.qualname}.{callee_name}")
                        dst = target_method_id or target_cls_id
                        if dst == src_self or dst not in graph.nodes:
                            continue
                        graph.add_edge(
                            src_self,
                            dst,
                            "calls",
                            confidence=0.9 if var_type else 0.75,
                            resolution="java",
                            evidence=[Loc(method.path, line_no)],
                            attrs={"callee": _short(token)},
                        )

    # project manifests as external build tooling nodes
    for project in sorted(index.projects, key=lambda p: p.path):
        if not project.dependencies:
            continue
        node = Node(
            id=stable_id("javaproject", project.path, project.name),
            kind="external",
            name=project.name,
            qualname=f"java:{project.path}",
            path=project.path,
            line=1,
            attrs={"build_tool": project.build_tool, "dependencies": sorted(project.dependencies)[:50], "java": True},
        )
        graph.add_node(node)


def _param_name(param: str) -> str:
    tokens = [part for part in param.split() if part.strip()]
    return tokens[-1].rstrip(",") if tokens else param


# ---------------------------------------------------------------------- SAST
def _java_trace(method: JavaMethod, line_no: int) -> list[Loc]:
    """Best-effort source-to-sink path for a tainted Java sink."""
    sink = Loc(method.path, line_no)
    source = Loc(method.path, method.line)
    return [source] if source == sink else [source, sink]


def analyze_java_security(graph: Graph, index: JavaIndex, repo_root: Path, repo_name: str = "") -> list[Finding]:
    """SAST scan over Java sources and Spring configuration files."""
    findings: list[Finding] = []
    seen: set[str] = set()

    def add(
        category: str,
        severity: str,
        title: str,
        message: str,
        loc: Loc,
        cwe: str | None,
        node_id: str | None,
        confidence: float,
        recommendation: str,
        trace: list[Loc] | None = None,
    ) -> None:
        key = f"{category}:{loc.path}:{loc.line}:{title}"
        if key in seen:
            return
        seen.add(key)
        node = graph.nodes.get(node_id or "")
        if node is not None:
            _tag(node, "sink")
            _tag(node, category)
        findings.append(
            Finding(
                id=stable_id("finding", category, loc.path, str(loc.line), title),
                category=category,
                severity=severity,
                title=title,
                message=message,
                node_id=node_id,
                cwe=cwe,
                confidence=confidence,
                evidence=[loc],
                recommendation=recommendation,
                trace=list(trace or []),
            )
        )

    for path in sorted(index.files):
        file_index = index.files[path]
        for cls in sorted(file_index.classes, key=lambda c: (c.line, c.name)):
            cls_node_id = graph.nodes.get(stable_id("jclass", cls.path, cls.qualname))
            node_id = cls_node_id.id if cls_node_id else None
            for method in sorted(cls.methods, key=lambda m: (m.line, m.name)):
                method_node = graph.nodes.get(stable_id("jsym", method.path, method.qualname))
                method_id = method_node.id if method_node else node_id
                tainted = set(method.tainted_vars())
                for line_no, text in method.body:
                    referenced = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", text))
                    for match in re.finditer(
                        r"(\w+)\s*=\s*[^=;]*?\w+\.\s*"
                        r"(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|"
                        r"getQueryString|getReader|getInputStream|getPathInfo|getRequestURI)\s*\(",
                        text,
                    ):
                        tainted.add(match.group(1))
                    anonymous_source = bool(TAINT_SOURCE_CALL_RE.search(text))
                    tainted_here = anonymous_source or bool(referenced & tainted)
                    for category, pattern, cwe, title, remediation, tainted_sev, base_sev in JAVA_SINK_RULES:
                        if not re.search(pattern, text):
                            continue
                        sanitizer = JAVA_SANITIZERS.get(category)
                        if sanitizer is not None and sanitizer.search(text):
                            continue
                        category_tainted = tainted_here
                        if base_sev is None and not category_tainted:
                            continue
                        severity = tainted_sev if category_tainted else base_sev
                        if severity is None:
                            continue
                        detail = (
                            "receives request-derived input."
                            if category_tainted
                            else "uses a risky pattern."
                        )
                        trace: list[Loc] = []
                        if category_tainted:
                            trace = _java_trace(method, line_no)
                        add(
                            category,
                            severity,
                            title,
                            f"`{method.qualname.split('.')[-1]}` at {loc_ref(method.path, line_no)} {detail}",
                            Loc(method.path, line_no),
                            cwe,
                            method_id,
                            0.95 if category_tainted else 0.75,
                            remediation,
                            trace,
                        )
                    for match in re.finditer(
                        r"(?:^|[;{]\s*)(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)?"
                        r"(\w+)\s*=\s*([^=].*)",
                        text,
                    ):
                        lhs, rhs = match.group(1), match.group(2)
                        if lhs in tainted:
                            continue
                        if any(re.search(rf"\b{re.escape(name)}\b", rhs) for name in tainted):
                            tainted.add(lhs)

    _scan_java_property_files(graph, index, repo_root, add)
    findings.sort(
        key=lambda f: (
            -SEVERITY_RANK.get(f.severity, 0),
            f.category,
            f.evidence[0].path if f.evidence else "",
            f.evidence[0].line if f.evidence else 0,
            f.id,
        )
    )
    return findings


def loc_ref(path: str, line: int) -> str:
    return f"{path}:{line}"


def _scan_java_property_files(graph: Graph, index: JavaIndex, repo_root, add) -> None:
    for path in sorted(index.property_files):
        target = repo_root / path
        try:
            resolved = target.resolve()
            if not resolved.is_relative_to(repo_root.resolve()) or not resolved.is_file():
                continue
            if resolved.stat().st_size > MAX_SOURCE_BYTES:
                continue
            content = resolved.read_text(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue
        for line_no, line in enumerate(content.splitlines(), start=1):
            match = SECRET_KEY_RE.search(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip().strip(";,")
            lowered = value.lower().strip('"\'')
            if not value or lowered in SECRET_PLACEHOLDERS or any(lowered.startswith(prefix) for prefix in SECRET_PREFIXES):
                continue
            if any(token in lowered for token in ("example", "changeme", "placeholder", "your_")):
                continue
            add(
                "secret",
                "high",
                f"Possible hardcoded secret: {key}",
                f"Credential-like assignment found in {path} at line {line_no}.",
                Loc(path, line_no),
                SECRET_CWE,
                None,
                0.75,
                SECRET_RECOMMENDATION,
            )
