from io import StringIO
import sys
from k8s_manifest_validator.config import load_config
from k8s_manifest_validator.inventory import load_manifests, prerelease_findings
from k8s_manifest_validator.models import Finding, merge_findings


def test_config_profiles_and_mapping(tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text('targets:\n  - name: a\n    kubernetes: "1.31"\n    gatewayAPI: ["1.3", "1.4.0"]\n')
    c = load_config(p)
    assert c.kubernetes_versions == ["1.31.0"]
    assert c.gateway_versions == ["1.3.0", "1.4.0"]
    p.write_text('kubernetes:\n  versions:\n    "1.29":\n      gatewayAPI: ["1.2.1"]\n')
    c = load_config(p)
    assert c.affected("gateway", "1.2.1") == ["k8s-1.29.0"]


def test_multidoc_and_field_position(manifest_file):
    manifests, errors = load_manifests(str(manifest_file), set())
    assert not errors
    assert len(manifests) == 3
    assert manifests[1].source("/spec/rules/0/matches/0/path/value")["line"] == 21
    assert manifests[0].source("/spec/template/spec/containers/0/name")["line"] == 9
    assert manifests[2].kind_category(set()) == "custom"


def test_prerelease_only_builtin(tmp_path):
    p = tmp_path / "in.yaml"
    p.write_text('''apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: a
---
apiVersion: acme.example.com/v1alpha1
kind: Widget
metadata:
  name: b
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.acme.example.com
spec:
  versions:
  - name: v1alpha1
''')
    manifests, _ = load_manifests(str(p), set())
    findings = prerelease_findings(manifests, set())
    assert len(findings) == 1
    assert findings[0].resource["kind"] == "Ingress"
    assert findings[0].source["line"] == 1


def test_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", StringIO('apiVersion: v1\nkind: Pod\nmetadata: {name: a}\n'))
    m, e = load_manifests("-", set())
    assert len(m) == 1 and not e
    assert m[0].source()["file"] == "<stdin>"


def test_duplicate_yaml_fields(tmp_path):
    p = tmp_path / "broken.yaml"
    p.write_text('apiVersion: v1\nkind: Pod\nkind: Service\n')
    m, findings = load_manifests(str(p), set())
    assert not m
    assert findings[0].rule == "INPUT_PARSE_ERROR"
    assert findings[0].source["line"] == 3


def test_merge_version_only(config):
    a = Finding("X", "kubeconform", "ERROR", "bad", {"file": "a.yaml", "line": 2},
                affected_targets=["ocp-a"], gateway_api_versions=["1.2.1"])
    b = Finding("X", "kubeconform", "ERROR", "bad", {"file": "a.yaml", "line": 2},
                affected_targets=["ocp-b"], gateway_api_versions=["1.3.0"])
    merged = merge_findings([a, b])
    assert len(merged) == 1
    assert merged[0].affected_targets == ["ocp-a", "ocp-b"]
