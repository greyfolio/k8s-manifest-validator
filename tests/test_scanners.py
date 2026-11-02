import json
import subprocess
from pathlib import Path
from k8s_manifest_validator.config import Config, Target
from k8s_manifest_validator.inventory import load_manifests
from k8s_manifest_validator.models import Finding, merge_findings
from k8s_manifest_validator.schemas import SchemaCache
from k8s_manifest_validator.scanners import kubeconform_findings, trivy_findings, is_failure


def test_kubeconform_deduplicates_version_runs(manifest_file, gateway_bundle, config, monkeypatch, tmp_path):
    config.gateway_bundles = {"1.2.1": gateway_bundle, "1.3.0": gateway_bundle}
    manifests, _ = load_manifests(str(manifest_file), set())
    cache = SchemaCache(config.cache_dir, gateway_bundles=config.gateway_bundles)
    from k8s_manifest_validator import schemas, scanners
    monkeypatch.setattr(schemas, "_download", lambda url: b'{"type":"object"}')
    calls = []
    def fake_run(args, timeout):
        calls.append(args)
        src_dir = Path(args[-1])
        resources = []
        for file in src_dir.glob("*.yaml"):
            if src_dir.name == "gateway-1.2.1":
                resources.append({"filename": str(file), "kind": "HTTPRoute", "version": "gateway.networking.k8s.io/v1",
                                  "status": "INVALID", "msg": "Additional property invalid is not allowed",
                                  "validationErrors": [{"path": "/spec/rules/0", "msg": "additionalProperties 'matches' not allowed"}]})
            else:
                resources.append({"filename": str(file), "status": "VALID"})
        return subprocess.CompletedProcess(args, 1 if src_dir.name == "gateway-1.2.1" else 0,
                                           json.dumps({"resources": resources, "summary": {}}), "")
    monkeypatch.setattr(scanners, "_run", fake_run)
    result = kubeconform_findings(manifests, config, cache, tmp_path / "work")
    assert len(calls) == 4  # 2 distinct K8s + 2 distinct Gateway API versions
    assert len(result) == 1
    assert result[0].gateway_api_versions == ["1.2.1"]
    assert result[0].affected_targets == ["ocp-a"]
    assert result[0].source["line"] == 18  # Source location for spec.rules[0].matches


def test_unsupported_gateway_kind(manifest_file, gateway_bundle, config, monkeypatch, tmp_path):
    from k8s_manifest_validator import schemas, scanners
    manifests, _ = load_manifests(str(manifest_file), set())
    manifests[1].data["kind"] = "UDPRoute"
    config.gateway_bundles = {"1.2.1": gateway_bundle, "1.3.0": gateway_bundle}
    monkeypatch.setattr(schemas, "_download", lambda url: b'{"type":"object"}')
    monkeypatch.setattr(scanners, "_run", lambda a, t: subprocess.CompletedProcess(
        a, 0, json.dumps({"resources": [{"filename": str(x), "status": "VALID"}
                for x in Path(a[-1]).glob("*.yaml")]}), ""))
    findings = kubeconform_findings(manifests, config, SchemaCache(config.cache_dir,
        gateway_bundles=config.gateway_bundles), tmp_path / "work")
    assert len([f for f in findings if f.rule == "GATEWAY_GVK_UNAVAILABLE"]) == 2


def test_trivy_line_mapping(manifest_file, config, monkeypatch, tmp_path):
    from k8s_manifest_validator import scanners
    config.trivy_enabled = True
    manifests, _ = load_manifests(str(manifest_file), set())
    def fake_run(args, timeout):
        assert args[1] == "config"
        assert "--scanners" not in args  # `config` already scans misconfigurations.
        src = next(Path(args[-1]).glob("*.yaml"))
        payload = {"Results": [{"Target": str(src), "Misconfigurations": [
            {"ID": "AVD-KSV-0001", "Severity": "HIGH", "Message": "Bad securityContext",
             "CauseMetadata": {"StartLine": 11}, "Resolution": "Fix it"}]}]}
        return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
    monkeypatch.setattr(scanners, "_run", fake_run)
    findings = trivy_findings(manifests, config, tmp_path / "work")
    assert findings[0].source["file"] == str(manifest_file)
    assert findings[0].source["line"] > 0
    assert is_failure(findings[0], "HIGH")
    assert not is_failure(findings[0], "CRITICAL")


def test_tool_failures_are_incomplete(config, manifest_file, monkeypatch, tmp_path):
    from k8s_manifest_validator import scanners
    config.trivy_enabled = True
    manifests, _ = load_manifests(str(manifest_file), set())
    monkeypatch.setattr(scanners, "_run", lambda a, t: subprocess.CompletedProcess(a, 2, "", "test fail"))
    result = trivy_findings(manifests, config, tmp_path)
    assert result[0].category == "scanner_error"


def test_report_exit_code():
    from k8s_manifest_validator.cli import report
    f = Finding("x", "trivy", "LOW", "low", category="violation")
    report_obj, code = report([f], manifests=1, targets=[], fail_on="HIGH", tool_versions={})
    assert report_obj["status"] == "passed" and code == 0
    s = Finding("x", "schema-cache", "ERROR", "missing", category="scanner_error")
    report_obj, code = report([f, s], manifests=1, targets=[], fail_on="HIGH", tool_versions={})
    assert code == 2 and report_obj["status"] == "incomplete"


def test_no_gateway_objects_avoids_gateway_download(tmp_path, config, monkeypatch):
    from k8s_manifest_validator import scanners, schemas
    p = tmp_path / "pod.yaml"
    p.write_text('apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n')
    manifests, _ = load_manifests(str(p), set())
    monkeypatch.setattr(schemas, "_download", lambda url: b'{"type":"object"}')
    monkeypatch.setattr(scanners, "_run", lambda a, t: subprocess.CompletedProcess(
        a, 0, json.dumps({"resources": [{"filename": str(x), "status": "VALID"}
                for x in Path(a[-1]).glob("*.yaml")]}), ""))
    findings = kubeconform_findings(manifests, config, SchemaCache(config.cache_dir, offline=False), tmp_path / "work")
    assert not findings
    assert not (config.cache_dir / "gateway-api").exists()


def test_gateway_without_bundle_in_one_target(tmp_path, gateway_bundle, config, monkeypatch):
    from k8s_manifest_validator import scanners
    config.targets.append(Target("no-gateway", "1.32.0", ()))
    config.gateway_bundles = {"1.2.1": gateway_bundle, "1.3.0": gateway_bundle}
    p = tmp_path / "route.yaml"
    p.write_text('apiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\nmetadata: {name: demo}\n')
    manifests, _ = load_manifests(str(p), set())
    monkeypatch.setattr(scanners, "_run", lambda a, t: subprocess.CompletedProcess(
        a, 0, json.dumps({"resources": [{"filename": str(x), "status": "VALID"}
                for x in Path(a[-1]).glob("*.yaml")]}), ""))
    findings = kubeconform_findings(manifests, config, SchemaCache(config.cache_dir, offline=True,
                  gateway_bundles=config.gateway_bundles), tmp_path / "work")
    assert len(findings) == 1
    assert findings[0].rule == "GATEWAY_NOT_CONFIGURED"
    assert findings[0].affected_targets == ["no-gateway"]
