"""Common findings API and stable output serialization."""
from __future__ import annotations
from dataclasses import dataclass, field as dc_field, asdict
from typing import Any

@dataclass
class Finding:
    rule: str
    scanner: str
    severity: str
    message: str
    source: dict[str, Any] | None = None
    resource: dict[str, Any] | None = None
    field: str | None = None
    affected_targets: list[str] = dc_field(default_factory=list)
    kubernetes_versions: list[str] = dc_field(default_factory=list)
    gateway_api_versions: list[str] = dc_field(default_factory=list)
    remediation: str | None = None
    reference: str | None = None
    detail: dict[str, Any] | None = None
    category: str = "violation"  # violation | scanner_error | info

    def json(self) -> dict[str, Any]:
        ret = asdict(self)
        return {k: v for k, v in ret.items() if v is not None and v != []}


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Merge only the same rule/message/path/resource across target versions."""
    result: dict[tuple, Finding] = {}
    for f in findings:
        s, r = f.source or {}, f.resource or {}
        key = (f.scanner, f.rule, f.severity, f.message, f.category,
               s.get("file"), s.get("document"), s.get("line"), s.get("column"),
               r.get("apiVersion"), r.get("kind"), r.get("namespace"), r.get("name"), f.field)
        if key not in result:
            result[key] = f
        else:
            existing = result[key]
            for attr in ("affected_targets", "kubernetes_versions", "gateway_api_versions"):
                setattr(existing, attr, sorted(set(getattr(existing, attr)) | set(getattr(f, attr))))
    return sorted(result.values(), key=lambda f: (
        (f.source or {}).get("file", ""), (f.source or {}).get("line", 0),
        f.rule, f.message))
