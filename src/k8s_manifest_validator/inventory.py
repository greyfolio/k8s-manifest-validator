"""Manifest inventory + original YAML JSON-pointer-to-source mapping."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
import io
import json
import re
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
import yaml
from .models import Finding

# Kubernetes-owned API groups (not third-party CRD API groups).
BUILTIN_GROUPS = frozenset({
    "", "apps", "batch", "autoscaling", "extensions", "policy", "scheduling.k8s.io",
    "networking.k8s.io", "storage.k8s.io", "rbac.authorization.k8s.io",
    "apiextensions.k8s.io", "apiregistration.k8s.io", "admissionregistration.k8s.io",
    "certificates.k8s.io", "coordination.k8s.io", "discovery.k8s.io", "events.k8s.io",
    "flowcontrol.apiserver.k8s.io", "node.k8s.io", "resource.k8s.io",
    "authentication.k8s.io", "authorization.k8s.io", "imagepolicy.k8s.io",
    "internal.apiserver.k8s.io", "storagemigration.k8s.io", "metrics.k8s.io",
})
GATEWAY_GROUP = "gateway.networking.k8s.io"
PRE_RELEASE = re.compile(r"^v\d+(?:alpha|beta)\d+$", re.I)


def group_and_version(api_version: str) -> tuple[str, str]:
    return tuple(api_version.rsplit("/", 1)) if "/" in api_version else ("", api_version)


def category(api_version: str, builtin_groups: set[str]) -> str:
    group, _ = group_and_version(api_version)
    if group == GATEWAY_GROUP:
        return "gateway"
    if group in BUILTIN_GROUPS or group in builtin_groups:
        return "kubernetes"
    return "custom"


def pointer_part(value: Any) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def path_positions(node: Any, pointer: str = "") -> dict[str, tuple[int, int]]:
    """Extract 1-based line/column for YAML nodes and mapping keys."""
    loc: dict[str, tuple[int, int]] = {}
    line = getattr(getattr(node, "lc", None), "line", None)
    col = getattr(getattr(node, "lc", None), "col", None)
    if line is not None and col is not None:
        loc[pointer] = (line + 1, col + 1)
    if isinstance(node, CommentedMap):
        for key, value in node.items():
            p = pointer + "/" + pointer_part(key)
            try:
                line, col = node.lc.key(key)
                loc[p] = (line + 1, col + 1)
            except (TypeError, KeyError, AttributeError):
                pass
            loc.update(path_positions(value, p))
            # Prefer key position when showing an unknown-field validation error.
            try:
                line, col = node.lc.key(key)
                loc[p] = (line + 1, col + 1)
            except (TypeError, KeyError, AttributeError):
                pass
    elif isinstance(node, CommentedSeq):
        for i, value in enumerate(node):
            p = pointer + "/" + str(i)
            try:
                line, col = node.lc.item(i)
                loc[p] = (line + 1, col + 1)
            except (TypeError, KeyError, AttributeError):
                pass
            loc.update(path_positions(value, p))
    return loc


def plain(node: Any) -> Any:
    if isinstance(node, dict):
        return {str(k): plain(v) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [plain(v) for v in node]
    if isinstance(node, (str, bool, int, float)) or node is None:
        return node
    return str(node)


def position_for(positions: dict[str, tuple[int, int]], pointer: str) -> tuple[int | None, int | None]:
    path = pointer.rstrip("/")
    while True:
        if path in positions:
            return positions[path]
        if not path:
            break
        path = path.rpartition("/")[0]
    return None, None


def nearest_path(positions: dict[str, tuple[int, int]], line: int) -> str:
    candidates = [(pos[0], len(path), path) for path, pos in positions.items() if pos[0] <= line]
    if not candidates:
        return ""
    return max(candidates)[2]


@dataclass
class Manifest:
    file: str
    document: int
    data: dict[str, Any]
    positions: dict[str, tuple[int, int]]
    # Top-level object, or pointer to item in a `kind: List`.
    prefix: str = ""

    @property
    def api_version(self) -> str:
        return str(self.data.get("apiVersion", ""))

    @property
    def kind(self) -> str:
        return str(self.data.get("kind", ""))

    @property
    def resource(self) -> dict[str, str]:
        meta = self.data.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        return {"apiVersion": self.api_version, "kind": self.kind,
                "name": str(meta.get("name") or meta.get("generateName") or ""),
                "namespace": str(meta.get("namespace") or "")}

    def source(self, pointer: str = "") -> dict[str, Any]:
        line, col = position_for(self.positions, self.prefix + pointer)
        return {k: v for k, v in {"file": self.file, "document": self.document,
                                   "line": line, "column": col}.items() if v is not None}

    def kind_category(self, extra_groups: set[str]) -> str:
        return category(self.api_version, extra_groups)


def _yaml(text: str) -> Iterator[Any]:
    parser = YAML(typ="rt")
    parser.allow_duplicate_keys = False
    yield from parser.load_all(io.StringIO(text))


def load_manifests(source: str, extra_groups: set[str]) -> tuple[list[Manifest], list[Finding]]:
    files: list[tuple[str, str]] = []
    findings: list[Finding] = []
    if source == "-":
        import sys
        files.append(("<stdin>", sys.stdin.read()))
    else:
        p = Path(source)
        if not p.exists():
            raise ValueError(f"input not found: {source}")
        if p.is_dir():
            paths = sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".yaml", ".yml", ".json"))
        elif p.is_file():
            paths = [p]
        else:
            raise ValueError(f"input must be file, directory, or '-': {source}")
        for path in paths:
            try:
                files.append((str(path), path.read_text(encoding="utf-8-sig")))
            except (UnicodeError, OSError) as exc:
                findings.append(Finding("INPUT_READ_ERROR", "parser", "ERROR", str(exc),
                                        source={"file": str(path)}, category="scanner_error"))
    manifests: list[Manifest] = []
    for filename, content in files:
        try:
            for doc_idx, node in enumerate(_yaml(content), 1):
                if node is None:
                    continue
                if not isinstance(node, dict):
                    findings.append(Finding("INPUT_NOT_OBJECT", "parser", "ERROR", "YAML document is not a mapping",
                                            source={"file": filename, "document": doc_idx}))
                    continue
                positions = path_positions(node)
                data = plain(node)
                if data.get("kind") == "List" and isinstance(data.get("items"), list):
                    for i, item in enumerate(data["items"]):
                        if isinstance(item, dict):
                            manifests.append(Manifest(filename, doc_idx, item, positions, f"/items/{i}"))
                        else:
                            findings.append(Finding("INPUT_NOT_OBJECT", "parser", "ERROR",
                                                    f"List item {i} is not an object",
                                                    source={"file": filename, "document": doc_idx}))
                else:
                    manifests.append(Manifest(filename, doc_idx, data, positions))
        except Exception as exc:
            mark = getattr(exc, "problem_mark", None)
            findings.append(Finding("INPUT_PARSE_ERROR", "parser", "ERROR", str(exc),
                                    source={k: v for k, v in {"file": filename,
                                        "line": (mark.line + 1) if mark else None,
                                        "column": (mark.column + 1) if mark else None}.items() if v is not None}))
    for m in manifests:
        if not m.kind or not m.api_version:
            findings.append(Finding("INPUT_MISSING_GVK", "parser", "ERROR",
                                    "Manifest is missing kind or apiVersion", m.source(), m.resource))
    return manifests, findings


def prerelease_findings(manifests: list[Manifest], extra_groups: set[str]) -> list[Finding]:
    result = []
    for m in manifests:
        if m.kind_category(extra_groups) != "kubernetes":
            continue
        _, ver = group_and_version(m.api_version)
        if PRE_RELEASE.fullmatch(ver):
            result.append(Finding("K8S_PRERELEASE_API", "api-stability", "ERROR",
                                  f"Built-in Kubernetes API {m.api_version} is alpha/beta",
                                  m.source("/apiVersion"), m.resource, "/apiVersion"))
    return result


def write_manifest(path: Path, manifest: Manifest) -> dict[str, tuple[int, int]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(manifest.data, sort_keys=False, allow_unicode=True)
    path.write_text(text, encoding="utf-8")
    node = next(_yaml(text))
    return path_positions(node)
