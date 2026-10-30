"""Command-line driver: stdout is always machine-readable JSON."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sys
from . import __version__
from .config import load_config
from .inventory import load_manifests, prerelease_findings
from .models import Finding, merge_findings
from .scanners import (kubeconform_findings, trivy_findings, tool_version, is_failure)
from .schemas import SchemaCache


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Validate Kubernetes manifests and report unified JSON findings")
    p.add_argument("input", help="YAML/JSON file, directory (recursive), or '-' for stdin")
    p.add_argument("--config", "-c", type=Path, required=True, help="Configuration YAML")
    p.add_argument("--offline", action="store_true", help="No schema downloads; use local schema cache")
    p.add_argument("--cache-dir", type=Path, help="Override schema cache directory")
    p.add_argument("--no-trivy", action="store_true", help="Disable Trivy misconfiguration scan")
    p.add_argument("--output", "-o", type=Path, help="Save JSON to file instead of stdout")
    p.add_argument("--version", action="version", version=__version__)
    return p


def report(findings: list[Finding], *, manifests: int, targets: list[dict],
           fail_on: str, tool_versions: dict[str, str | None]) -> tuple[dict, int]:
    unique = merge_findings(findings)
    incomplete = any(f.category == "scanner_error" for f in unique)
    failed = any(is_failure(f, fail_on) for f in unique)
    status = "incomplete" if incomplete else "failed" if failed else "passed"
    return ({
        "schemaVersion": "1.0", "validatorVersion": __version__, "status": status,
        "targets": targets, "tools": tool_versions,
        "summary": {"manifests": manifests, "findings": len(unique),
                    "violations": sum(f.category == "violation" for f in unique),
                    "scannerErrors": sum(f.category == "scanner_error" for f in unique),
                    "failingFindings": sum(is_failure(f, fail_on) for f in unique)},
        "findings": [f.json() for f in unique],
    }, 2 if incomplete else 1 if failed else 0)


def run(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    findings: list[Finding] = []
    config = None
    manifests = []
    tools = {"kubeconform": None, "trivy": None}
    try:
        config = load_config(args.config, offline=args.offline, cache_dir=args.cache_dir,
                             no_trivy=args.no_trivy)
        manifests, parsing = load_manifests(args.input, config.additional_builtin_groups)
        findings.extend(parsing)
        valid = [m for m in manifests if m.kind and m.api_version]
        unstable = prerelease_findings(valid, config.additional_builtin_groups)
        for finding in unstable:
            finding.affected_targets = sorted(t.name for t in config.targets)
        findings.extend(unstable)
        if not manifests and not findings:
            findings.append(Finding("INPUT_EMPTY", "parser", "ERROR",
                                    "No Kubernetes manifests found in the supplied input",
                                    category="scanner_error"))
        cache = SchemaCache(config.cache_dir, config.offline, config.gateway_bundles)
        with TemporaryDirectory(prefix="k8s-validator-") as dirname:
            work = Path(dirname)
            if valid:
                requires_kubeconform = any(m.kind_category(config.additional_builtin_groups)
                                            in ("kubernetes", "gateway") for m in valid)
                if requires_kubeconform:
                    tools["kubeconform"] = tool_version(config.kubeconform_bin, ["-v"])
                if requires_kubeconform and tools["kubeconform"] is None:
                    findings.append(Finding("SCANNER_FAILURE", "kubeconform", "ERROR",
                        f"kubeconform not found or could not execute: {config.kubeconform_bin}",
                        category="scanner_error"))
                elif requires_kubeconform:
                    findings.extend(kubeconform_findings(valid, config, cache, work))
                if config.trivy_enabled:
                    tools["trivy"] = tool_version(config.trivy_bin, ["--version"])
                    if tools["trivy"] is None:
                        findings.append(Finding("SCANNER_FAILURE", "trivy", "ERROR",
                            f"trivy not found or could not execute: {config.trivy_bin}",
                            category="scanner_error"))
                    else:
                        findings.extend(trivy_findings(valid, config, work))
    except Exception as exc:
        # Configuration, input, IO or unexpected failures must not masquerade as passing scans.
        findings.append(Finding("VALIDATOR_FAILURE", "validator", "ERROR", str(exc),
                                category="scanner_error"))
    targets = [{"name": t.name, "kubernetes": t.kubernetes,
                "gatewayAPI": list(t.gateway_api)} for t in config.targets] if config else []
    output, status = report(findings, manifests=len(manifests), targets=targets,
                            fail_on=config.trivy_fail_on if config else "HIGH", tool_versions=tools)
    formatted = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(formatted, encoding="utf-8")
        except OSError as exc:
            print(f"Failed writing JSON output: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(formatted)
    return status


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
