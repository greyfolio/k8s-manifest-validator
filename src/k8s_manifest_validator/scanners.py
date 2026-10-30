"""Kubeconform and Trivy adapters, using normalized per-object YAML files."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import re
import subprocess
from .config import Config, SEVERITIES
from .inventory import Manifest, nearest_path, position_for, write_manifest
from .models import Finding
from .schemas import SCHEMA_TEMPLATE, SchemaCache, SchemaFetchError, SchemaMissingError


@dataclass
class TempFile:
    manifest: Manifest
    positions: dict[str, tuple[int, int]]


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(args, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False)


def _exception(scanner: str, exc: Exception, *, target: str | None = None) -> Finding:
    return Finding("SCANNER_FAILURE", scanner, "ERROR", f"{scanner} could not complete: {exc}",
                   detail={"target": target} if target else None, category="scanner_error")


def tool_version(binary: str, args: list[str], timeout: int = 15) -> str | None:
    try:
        result = _run([binary, *args], timeout)
        return ((result.stdout or result.stderr).strip().splitlines() or [None])[0]
    except (OSError, subprocess.TimeoutExpired):
        return None


def _manifest_paths(directory: Path, manifests: list[Manifest]) -> dict[str, TempFile]:
    mapping: dict[str, TempFile] = {}
    for idx, obj in enumerate(manifests):
        name = f"manifest-{idx:07d}.yaml"
        positions = write_manifest(directory / name, obj)
        mapping[name] = TempFile(obj, positions)
    return mapping


def _lookup_temp(mapping: dict[str, TempFile], name: str) -> TempFile | None:
    return mapping.get(Path(name.replace("\\", "/")).name)


def _resolve_pointer(manifest: Manifest, path: str, message: str) -> str:
    pointer = path if path.startswith("/") else "/" + path if path else ""
    # Kubeconform sometimes returns parent path for an unknown property.
    # Resolve it to the source line for the actual unknown field if possible.
    match = re.search(r"(?:additionalProperties|Additional property)\s*['\"]?([\w.-]+)['\"]?", message)
    if match:
        candidate = pointer.rstrip("/") + "/" + match.group(1)
        if position_for(manifest.positions, manifest.prefix + candidate)[0] is not None and \
                manifest.prefix + candidate in manifest.positions:
            return candidate
    return pointer


def _run_kubeconform(directory: Path, mapping: dict[str, TempFile], schema_directory: Path,
                     version: str, targets: list[str], category: str, config: Config, gateway_version: str | None = None) -> list[Finding]:
    if not mapping:
        return []
    template = str(schema_directory / SCHEMA_TEMPLATE)
    cmd = [config.kubeconform_bin, "-strict", "-summary", "-verbose", "-output", "json",
           "-kubernetes-version", version, "-schema-location", template, str(directory)]
    try:
        result = _run(cmd, config.timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [_exception("kubeconform", exc, target=f"{category}:{version}")]
    try:
        output = json.loads(result.stdout)
        if not isinstance(output, dict) or not isinstance(output.get("resources"), list):
            raise ValueError("missing resources array")
    except (ValueError, TypeError) as exc:
        return [_exception("kubeconform", ValueError(
            f"invalid JSON output (exit={result.returncode}): {result.stderr[:500]} {str(exc)}"),
            target=f"{category}:{version}")]
    findings = []
    seen = set()
    for resource in output["resources"]:
        status = str(resource.get("status", "")).upper()
        tmp = _lookup_temp(mapping, resource.get("filename", ""))
        if tmp is None:
            findings.append(_exception("kubeconform", ValueError(
                f"unmatched filename in output: {resource.get('filename')!r}")))
            continue
        seen.add(tmp.manifest.file + ":" + str(id(tmp)))
        if status in ("VALID", "EMPTY"):
            continue
        mf = tmp.manifest
        is_error = status in ("ERROR", "SKIPPED")
        errs = resource.get("validationErrors") or []
        if not errs:
            errs = [{"path": "", "msg": resource.get("msg") or f"Kubeconform status: {status}"}]
        for issue in errs:
            message = str(issue.get("msg") or resource.get("msg") or status)
            pointer = _resolve_pointer(mf, str(issue.get("path") or ""), message)
            if status == "SKIPPED":
                message = "Kubeconform skipped a resource that was expected to have a schema"
            f = Finding("K8S_SCHEMA_INVALID" if category == "kubernetes" else "GATEWAY_SCHEMA_INVALID",
                        "kubeconform", "ERROR", message, mf.source(pointer), mf.resource,
                        pointer or None, affected_targets=targets.copy(),
                        kubernetes_versions=[version] if category == "kubernetes" else [],
                        gateway_api_versions=[gateway_version] if category == "gateway" and gateway_version else [],
                        category="scanner_error" if is_error else "violation")
            findings.append(f)
    if len(seen) != len(mapping):
        findings.append(_exception("kubeconform", ValueError(
            f"output contained results for {len(seen)} of {len(mapping)} input manifests"),
            target=f"{category}:{version}"))
    if result.returncode not in (0, 1):
        findings.append(_exception("kubeconform", ValueError(
            f"exit={result.returncode}: {result.stderr[:500]}"), target=f"{category}:{version}"))
    return findings


def kubeconform_findings(manifests: list[Manifest], config: Config,
                         cache: SchemaCache, workspace: Path) -> list[Finding]:
    findings: list[Finding] = []
    builtin = [m for m in manifests if m.kind_category(config.additional_builtin_groups) == "kubernetes"
               and m.api_version and m.kind]
    gateway = [m for m in manifests if m.kind_category(config.additional_builtin_groups) == "gateway"
               and m.api_version and m.kind]
    for version in config.kubernetes_versions if builtin else []:
        selected = []
        for m in builtin:
            try:
                cache.kubernetes_schema(version, m.kind, m.api_version)
                selected.append(m)
            except SchemaMissingError as exc:
                findings.append(Finding("K8S_SCHEMA_UNAVAILABLE", "kubeconform", "ERROR",
                    f"No Kubernetes {version} schema for {m.api_version}/{m.kind}: {exc}",
                    m.source(), m.resource, affected_targets=config.affected("kubernetes", version),
                    kubernetes_versions=[version]))
            except SchemaFetchError as exc:
                findings.append(Finding("SCHEMA_FETCH_FAILURE", "schema-cache", "ERROR", str(exc),
                    m.source(), m.resource, affected_targets=config.affected("kubernetes", version),
                    kubernetes_versions=[version], category="scanner_error"))
        if selected:
            directory = workspace / ("kubernetes-" + version)
            mapping = _manifest_paths(directory, selected)
            findings.extend(_run_kubeconform(directory, mapping, cache.root / "kubernetes" / version,
                                              version, config.affected("kubernetes", version),
                                              "kubernetes", config))
    for gwversion in config.gateway_versions if gateway else []:
        affected = config.affected("gateway", gwversion)
        try:
            schemas = cache.gateway_schemas(gwversion)
        except SchemaFetchError as exc:
            findings.append(Finding("SCHEMA_FETCH_FAILURE", "schema-cache", "ERROR", str(exc),
                                    affected_targets=affected, gateway_api_versions=[gwversion],
                                    category="scanner_error"))
            continue
        selected = []
        for m in gateway:
            if (m.api_version, m.kind) not in schemas.gvks:
                findings.append(Finding("GATEWAY_GVK_UNAVAILABLE", "kubeconform", "ERROR",
                    f"{m.api_version}/{m.kind} is not served by Gateway API v{gwversion} Standard channel",
                    m.source(), m.resource, affected_targets=affected,
                    gateway_api_versions=[gwversion]))
            else:
                selected.append(m)
        if selected:
            directory = workspace / ("gateway-" + gwversion)
            mapping = _manifest_paths(directory, selected)
            # Kubeconform -kubernetes-version is irrelevant for schema selection here;
            # use a representative target Kubernetes version solely for CLI compatibility.
            k8sversion = next(t.kubernetes for t in config.targets if gwversion in t.gateway_api)
            findings.extend(_run_kubeconform(directory, mapping, schemas.directory,
                                             k8sversion, affected, "gateway", config, gateway_version=gwversion))
    if gateway:
        for target in config.targets:
            if target.gateway_api:
                continue
            for m in gateway:
                findings.append(Finding("GATEWAY_NOT_CONFIGURED", "kubeconform", "ERROR",
                    f"Gateway API resource present, but target {target.name!r} has no Gateway API bundle",
                    m.source(), m.resource, affected_targets=[target.name], category="violation"))
    return findings


def trivy_findings(manifests: list[Manifest], config: Config, workspace: Path) -> list[Finding]:
    if not config.trivy_enabled or not manifests:
        return []
    directory = workspace / "trivy-input"
    mapping = _manifest_paths(directory, [m for m in manifests if m.kind and m.api_version])
    if not mapping:
        return []
    command = [config.trivy_bin, "config", "--format", "json", "--exit-code", "0",
               "--scanners", "misconfig", "--quiet"]
    if config.offline:
        command.append("--skip-check-update")
    for check in config.trivy_checks:
        command += ["--config-check", check]
    command.append(str(directory))
    try:
        result = _run(command, config.timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [_exception("trivy", exc)]
    if result.returncode != 0:
        return [_exception("trivy", ValueError(
            f"exit={result.returncode}: {result.stderr[:600]}"))]
    try:
        output = json.loads(result.stdout)
        if not isinstance(output, dict):
            raise ValueError("Trivy output must be an object")
    except (ValueError, TypeError) as exc:
        return [_exception("trivy", ValueError(f"invalid JSON output: {exc}; {result.stderr[:300]}"))]
    findings = []
    for entry in output.get("Results") or []:
        tmp = _lookup_temp(mapping, entry.get("Target", ""))
        for issue in entry.get("Misconfigurations") or []:
            if tmp is None:
                findings.append(_exception("trivy", ValueError(f"unknown target: {entry.get('Target')}")))
                continue
            meta = issue.get("CauseMetadata") or issue.get("Metadata") or {}
            line = meta.get("StartLine")
            pointer = nearest_path(tmp.positions, line) if isinstance(line, int) and line > 0 else ""
            source = tmp.manifest.source(pointer)
            findings.append(Finding(
                str(issue.get("ID") or "TRIVY_MISCONFIGURATION"), "trivy",
                str(issue.get("Severity") or "UNKNOWN").upper(),
                str(issue.get("Message") or issue.get("Title") or "Trivy misconfiguration"),
                source, tmp.manifest.resource, pointer or None,
                affected_targets=sorted(t.name for t in config.targets),
                remediation=issue.get("Resolution"), reference=issue.get("PrimaryURL"),
                detail={"title": issue.get("Title"), "description": issue.get("Description")},
            ))
    return findings


def is_failure(finding: Finding, trivy_fail_on: str) -> bool:
    if finding.category == "scanner_error":
        return False
    if finding.scanner != "trivy":
        return True
    if trivy_fail_on == "NONE":
        return False
    # UNKNOWN remains reportable but is only fatal if the policy specifically selects UNKNOWN.
    if finding.severity == "UNKNOWN":
        return trivy_fail_on == "UNKNOWN"
    if trivy_fail_on == "UNKNOWN":
        return True
    return SEVERITIES.index(finding.severity) >= SEVERITIES.index(trivy_fail_on)
