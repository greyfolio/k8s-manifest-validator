import json
import pytest
from k8s_manifest_validator.schemas import (SchemaCache, convert_crd_openapi,
    kube_filename, local_filename, SchemaFetchError, SchemaMissingError)


def test_kubernetes_schema_names():
    assert kube_filename("Deployment", "apps/v1") == "deployment-apps-v1.json"
    assert kube_filename("ConfigMap", "v1") == "configmap-v1.json"
    assert kube_filename("Ingress", "networking.k8s.io/v1") == "ingress-networking-v1.json"
    assert local_filename("Ingress", "networking.k8s.io/v1") == "ingress-networking.k8s.io-v1.json"


def test_gateway_bundle_local_and_offline(tmp_path, gateway_bundle):
    cache = SchemaCache(tmp_path / "cache", offline=True, gateway_bundles={"1.3.0": gateway_bundle})
    data = cache.gateway_schemas("1.3.0")
    assert ("gateway.networking.k8s.io/v1", "HTTPRoute") in data.gvks
    out = data.directory / "httproute-gateway.networking.k8s.io-v1.json"
    schema = json.loads(out.read_text())
    assert schema["properties"]["spec"]["additionalProperties"] is False
    assert "metadata" in schema["properties"]
    assert cache.gateway_schemas("1.3.0").sha256 == data.sha256
    with pytest.raises(SchemaFetchError):
        cache.gateway_schemas("1.4.0")


def test_kubernetes_cache_no_network(tmp_path, monkeypatch):
    from k8s_manifest_validator import schemas
    file = tmp_path / "cache" / "kubernetes" / "1.31.0" / "pod-v1-v1.json"
    file.parent.mkdir(parents=True)
    file.write_text('{"type":"object"}')
    cache = SchemaCache(tmp_path / "cache", offline=True)
    assert cache.kubernetes_schema("1.31.0", "Pod", "v1") == file
    with pytest.raises(SchemaFetchError):
        cache.kubernetes_schema("1.32.0", "Pod", "v1")
    cache = SchemaCache(tmp_path / "cache", offline=False)
    monkeypatch.setattr(schemas, "_download", lambda url: b'{"type":"object"}')
    assert cache.kubernetes_schema("1.32.0", "Pod", "v1").is_file()


def test_openapi_nullable_int_or_string():
    source = {"type": "object", "properties": {
        "port": {"x-kubernetes-int-or-string": True},
        "foo": {"type": "string", "nullable": True},
        "any": {"type": "object", "x-kubernetes-preserve-unknown-fields": True,
                "properties": {"known": {"type": "string"}}}}}
    schema = convert_crd_openapi(source)
    assert schema["properties"]["port"]["anyOf"] == [{"type":"integer"}, {"type":"string"}]
    assert schema["properties"]["foo"]["type"] == ["string", "null"]
    assert schema["properties"]["any"]["additionalProperties"] is True


def test_bad_channel_rejected(tmp_path, gateway_bundle):
    gateway_bundle.write_text(gateway_bundle.read_text().replace("channel: standard", "channel: experimental"))
    with pytest.raises(SchemaFetchError):
        SchemaCache(tmp_path / "c", gateway_bundles={"1.3.0": gateway_bundle}).gateway_schemas("1.3.0")
