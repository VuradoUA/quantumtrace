"""Code scanner (Phase 2b): tree-sitter ASTs for Python / Java / Go, regex fallback for the rest.

    parse_code_files(paths, root) -> list[Finding]   (one Finding per crypto call site)

The grammars come from the official per-language packages (tree-sitter-python,
-java, -go), which ship the compiled grammar inside the wheel: nothing is
downloaded at runtime, so scanning works offline and inside Docker.
"""
from __future__ import annotations

from pathlib import Path

import tree_sitter as ts

from ...catalog import Catalog, load_catalog
from ...models import Finding
from . import go_lang, java_lang, python_lang
from .base import FileCtx, finalize
from .fallback import EXTENSIONS as FALLBACK_EXTENSIONS
from .fallback import parse_fallback

MAX_BYTES = 2_000_000          # skip generated / minified giants


def _grammar(lang: str):
    if lang == "python":
        import tree_sitter_python as g
    elif lang == "java":
        import tree_sitter_java as g
    else:
        import tree_sitter_go as g
    return ts.Language(g.language())


LANGS = {".py": ("python", python_lang), ".java": ("java", java_lang), ".go": ("go", go_lang)}
EXTENSIONS = set(LANGS) | FALLBACK_EXTENSIONS
_parsers: dict[str, ts.Parser] = {}


def parser_for(lang: str) -> ts.Parser:
    if lang not in _parsers:
        _parsers[lang] = ts.Parser(_grammar(lang))
    return _parsers[lang]


def parse_code_file(path: Path, rel: str, cat: Catalog | None = None) -> list[Finding]:
    cat = cat or load_catalog()
    if path.stat().st_size > MAX_BYTES:
        return []
    suffix = path.suffix.lower()
    if suffix not in LANGS:
        return parse_fallback(path, rel, cat) if suffix in FALLBACK_EXTENSIONS else []
    lang, module = LANGS[suffix]
    src = path.read_bytes()
    tree = parser_for(lang).parse(src)
    ctx = FileCtx(path=path, rel=rel, lang=lang, src=src, tree=tree)
    module.visit(ctx)
    findings = finalize(ctx)
    if tree.root_node.has_error:                     # tree-sitter recovers from syntax errors; say so
        for f in findings:
            f.flags.add("parse-errors")
            f.confidence = min(f.confidence, 0.7)
    return findings


def parse_code_files(paths: list[Path], root: Path | None = None, catalog: Catalog | None = None) -> list[Finding]:
    cat = catalog or load_catalog()
    out: list[Finding] = []
    for p in paths:
        rel = str(Path(p).relative_to(root)) if root else Path(p).name
        out += parse_code_file(Path(p), rel, cat)
    return out
