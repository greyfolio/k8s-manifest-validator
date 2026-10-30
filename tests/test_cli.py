"""The complete CLI path with simulated Kubeconform subprocess output."""
import json
import subprocess
from pathlib import Path
import jsonschema
import yaml
from k8s_manifest_validator.cli import run
from k8s_manifest_validator import scanners


def test_gateway_standard_field_rejected_by_full_cli(tmp_path, gateway_bundle, monkeypatch, capsys):
    input_file = tmp_path / "http-route.yaml"
    input_file.write_text('''apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web
spec:
  rules:
    - experimentalField: not-in-standard
''')
    config = tmp_path / "config.yaml"
    config.write_text(f'''targets:
  - name: openshift-test
    kubernetes: "1.31"
    gatewayAPI: ["1.3.0"]
gatewayBundles:
  "1.3.0": "{gateway_bundle}"
cacheDir: "{tmp_path / 'cache'}"
trivy:
  enabled: false
''')

    def fake_run(args, timeout):
        # Observe the actual command and schema directory that our wrapper passes.
        assert "-strict" in args and "-verbose" in args and "-schema-location" in args
        schema_template = args[args.index("-schema-location") + 1]
        assert "gateway-api/1.3.0" in schema_template
        resources = []
        for filename in sorted(Path(args[-1]).glob("*.yaml")):
            doc = yaml.safe_load(filename.read_text())
            schema_path = Path(schema_template.replace("{{.ResourceKind}}", doc["kind"].lower())
                .replace("{{.Group}}", "gateway.networking.k8s.io")
                .replace("{{.ResourceAPIVersion}}", "v1"))
            schema = json.loads(schema_path.read_text())
            errors = sorted(jsonschema.Draft4Validator(schema).iter_errors(doc), key=str)
            resources.append({"filename": str(filename),
                "status": "INVALID" if errors else "VALID",
                "validationErrors": [{"path": "/" + "/".join(map(str, error.path)),
                                      "msg": error.message} for error in errors]})
        return subprocess.CompletedProcess(args, 1 if any(x["status"] == "INVALID" for x in resources) else 0,
                                           json.dumps({"resources": resources}), "")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr("k8s_manifest_validator.cli.tool_version", lambda *args: "kubeconform-test")
    code = run(["-c", str(config), "--offline", str(input_file)])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["status"] == "failed"
    finding = report["findings"][0]
    assert finding["rule"] == "GATEWAY_SCHEMA_INVALID"
    assert finding["affected_targets"] == ["openshift-test"]
    assert finding["gateway_api_versions"] == ["1.3.0"]
    assert finding["resource"]["name"] == "web"
    assert finding["source"]["line"] == 7


def test_missing_tools_produces_exit2(tmp_path, capsys, monkeypatch):
    manifest = tmp_path / "in.yaml"
    manifest.write_text('apiVersion: v1\nkind: Pod\nmetadata: {name: example}\n')
    config = tmp_path / "c.yaml"
    config.write_text('targets:\n  - name: x\n    kubernetes: "1.31.0"\ntrivy:\n  enabled: false\n')
    monkeypatch.setattr("k8s_manifest_validator.cli.tool_version", lambda *args: None)
    status = run(["-c", str(config), str(manifest)])
    payload = json.loads(capsys.readouterr().out)
    assert status == 2
    assert payload["findings"][0]["rule"] == "SCANNER_FAILURE"


def test_empty_directory_incomplete(tmp_path, capsys):
    config = tmp_path / "c.yaml"
    config.write_text('targets:\n  - name: x\n    kubernetes: "1.31.0"\n')
    empty = tmp_path / "empty"
    empty.mkdir()
    status = run(["-c", str(config), str(empty)])
    payload = json.loads(capsys.readouterr().out)
    assert status == 2
    assert payload["findings"][0]["rule"] == "INPUT_EMPTY"
