"""The open verifier runs offline and makes no network call: it imports only
the standard library, cryptography and asn1crypto, and none of the standard
library's networking modules. Read from its own source, so a new import
that could reach the network fails here before it ships."""

import ast
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "bitexact_verifier.py"
THIRD_PARTY = {"cryptography", "asn1crypto"}
NETWORK = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "poplib",
           "imaplib", "telnetlib", "xmlrpc", "asyncio", "selectors",
           "socketserver", "wsgiref", "webbrowser"}


def _imported_roots() -> set:
    roots = set()
    for node in ast.walk(ast.parse(SOURCE.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    return roots


def test_the_verifier_imports_only_the_standard_library_and_its_two_libraries():
    outside = {r for r in _imported_roots()
               if r not in sys.stdlib_module_names and r not in THIRD_PARTY}
    assert outside == set()


def test_the_verifier_imports_nothing_that_reaches_the_network():
    assert _imported_roots() & NETWORK == set()


def test_the_verifier_package_depends_on_its_two_libraries_alone():
    import re
    import tomllib
    project = tomllib.loads((SOURCE.parent / "pyproject.toml").read_text(
        encoding="utf-8"))["project"]
    names = {re.split(r"[<>=!~;\[ ]", d, maxsplit=1)[0].lower()
             for d in project.get("dependencies", [])}
    assert names == THIRD_PARTY
