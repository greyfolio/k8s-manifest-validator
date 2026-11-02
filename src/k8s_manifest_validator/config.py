"""Strict but compact configuration, with both named target profiles and version maps."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any
import yaml

VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")

@dataclass(frozen=True)
class Target:
    name: str
    kubernetes: str
    gateway_api: tuple[str, ...] = ()

@dataclass
class Config:
    targets: list[Target]
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "k8s-manifest-validator")
    offline: bool = False
    gateway_bundles: dict[str, Path] = field(default_factory=dict)
    additional_builtin_groups: set[str] = field(default_factory=set)
    trivy_enabled: bool = True
    trivy_fail_on: str = "HIGH"
    trivy_compliance: str | None = None
    trivy_checks: list[str] = field(default_factory=list)
    kubeconform_bin: str = "kubeconform"
    trivy_bin: str = "trivy"
    timeout_seconds: int = 300

    @property
    def kubernetes_versions(self) -> list[str]:
        return sorted({t.kubernetes for t in self.targets}, key=lambda s: tuple(map(int, s.split('.'))))

    @property
    def gateway_versions(self) -> list[str]:
        return sorted({v for t in self.targets for v in t.gateway_api}, key=lambda s: tuple(map(int, s.split('.'))))

    def affected(self, category: str, version: str) -> list[str]:
        if category == "kubernetes":
            return sorted(t.name for t in self.targets if t.kubernetes == version)
        return sorted(t.name for t in self.targets if version in t.gateway_api)


def _version(value: Any, label: str) -> str:
    value = str(value)
    if not VERSION.fullmatch(value):
        raise ValueError(f"{label} must be a version such as '1.31' or '1.4.0': {value!r}")
    return value if value.count('.') == 2 else f"{value}.0"


def _gateway_versions(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("gatewayAPI must be a list of version strings (or a string)")
    return tuple(dict.fromkeys(_version(v, "Gateway API version") for v in value))


def load_config(path: Path, *, offline: bool = False, cache_dir: Path | None = None,
                no_trivy: bool = False) -> Config:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("configuration must be a YAML mapping")
    targets: list[Target] = []
    if "targets" in data:
        if not isinstance(data["targets"], list):
            raise ValueError("targets must be a list")
        for i, item in enumerate(data["targets"]):
            if not isinstance(item, dict):
                raise ValueError(f"targets[{i}] must be a mapping")
            kv = _version(item["kubernetes"], "Kubernetes version")
            targets.append(Target(str(item.get("name", f"k8s-{kv}-{i}")), kv,
                                  _gateway_versions(item.get("gatewayAPI"))))
    elif "kubernetes" in data:
        version_map = data["kubernetes"]["versions"]
        if not isinstance(version_map, dict):
            raise ValueError("kubernetes.versions must be a mapping")
        for k, v in version_map.items():
            kv = _version(k, "Kubernetes version")
            if not isinstance(v, dict):
                raise ValueError(f"kubernetes.versions.{k} must be a mapping")
            targets.append(Target(f"k8s-{kv}", kv, _gateway_versions(v.get("gatewayAPI"))))
    else:
        raise ValueError("configuration requires 'targets' or 'kubernetes.versions'")
    if not targets or len({t.name for t in targets}) != len(targets):
        raise ValueError("target profiles must be nonempty and have unique names")
    cache = cache_dir or Path(data.get("cacheDir", Path.home() / ".cache" / "k8s-manifest-validator"))
    if not cache.is_absolute():
        cache = (path.parent / cache).resolve()
    gateway_bundles = {}
    for version, bundle in (data.get("gatewayBundles") or {}).items():
        p = Path(bundle)
        gateway_bundles[_version(version, "Gateway API version")] = p if p.is_absolute() else (path.parent / p).resolve()
    tri = data.get("trivy") or {}
    severity = str(tri.get("failOn", "HIGH")).upper()
    if severity not in (*SEVERITIES[1:], "ANY", "NONE"):
        raise ValueError(f"invalid Trivy failOn: {severity}; use ANY, LOW, MEDIUM, HIGH, CRITICAL or NONE")
    compliance = tri.get("compliance")
    if compliance is not None and (not isinstance(compliance, str) or not compliance.strip()):
        raise ValueError("trivy.compliance must be a nonempty string")
    checks = tri.get("customChecks") or []
    if not isinstance(checks, list):
        raise ValueError("trivy.customChecks must be a list")
    checks = [str((path.parent / p).resolve()) if not Path(p).is_absolute() else str(p) for p in checks]
    opts = data.get("tools") or {}
    return Config(targets=targets, cache_dir=cache, offline=offline or bool(data.get("offline", False)),
                  gateway_bundles=gateway_bundles,
                  additional_builtin_groups=set(data.get("additionalBuiltinGroups") or []),
                  trivy_enabled=bool(tri.get("enabled", True)) and not no_trivy,
                  trivy_fail_on=severity, trivy_checks=checks, trivy_compliance=compliance,
                  kubeconform_bin=str(opts.get("kubeconform", "kubeconform")),
                  trivy_bin=str(opts.get("trivy", "trivy")),
                  timeout_seconds=int(opts.get("timeoutSeconds", 300)))
