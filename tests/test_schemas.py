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


def test_extract_openapi_definition_resolves_transitive_and_recursive_refs():
    from k8s_manifest_validator.schemas import extract_openapi_definition
    spec = {"definitions": {
        "Root": {"type": "object", "properties": {"spec": {"$ref": "#/definitions/Child"}}},
        "Child": {"type": "object", "properties": {"next": {"$ref": "#/definitions/Child"}}},
        "Unused": {"type": "object"},
    }}
    result = extract_openapi_definition(spec, "Root")
    assert result["properties"]["spec"]["$ref"] == "#/definitions/Child"
    assert set(result["definitions"]) == {"Root", "Child"}
    from jsonschema import Draft4Validator
    Draft4Validator.check_schema(result)
    assert Draft4Validator(result).is_valid({"spec": {"next": {}}})
    assert not Draft4Validator(result).is_valid({"spec": {"next": "bad"}})


def test_crd_schema_fallback_and_offline_cache(tmp_path, monkeypatch):
    from k8s_manifest_validator import schemas
    api = "apiextensions.k8s.io/v1"
    name = "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition"
    calls = []

    def download(url, max_bytes=32 * 1024 * 1024):
        calls.append(url)
        if "yannh/kubernetes-json-schema" in url:
            raise SchemaMissingError("HTTP 404")
        assert url.endswith("/v1.34.0/api/openapi-spec/swagger.json")
        return json.dumps({"definitions": {name: {"type": "object", "properties": {
            "spec": {"$ref": "#/definitions/Spec"}}},
            "Spec": {"type": "object", "required": ["group"],
                     "properties": {"group": {"type": "string"}}}}}).encode()

    monkeypatch.setattr(schemas, "_download", download)
    cache = SchemaCache(tmp_path / "cache")
    output = cache.kubernetes_schema("1.34.0", "CustomResourceDefinition", api)
    assert output.name == local_filename("CustomResourceDefinition", api)
    from jsonschema import Draft4Validator
    schema = json.loads(output.read_text())
    Draft4Validator.check_schema(schema)
    assert Draft4Validator(schema).is_valid({"spec": {"group": "example.com"}})
    assert not Draft4Validator(schema).is_valid({"spec": {"group": 123}})
    assert not Draft4Validator(schema).is_valid({"spec": {}})
    assert len(calls) == 2
    assert SchemaCache(tmp_path / "cache", offline=True).kubernetes_schema(
        "1.34.0", "CustomResourceDefinition", api) == output


def test_missing_other_schema_does_not_trigger_crd_fallback(tmp_path, monkeypatch):
    from k8s_manifest_validator import schemas
    def missing(url, max_bytes=32 * 1024 * 1024):
        raise SchemaMissingError("HTTP 404")
    monkeypatch.setattr(schemas, "_download", missing)
    with pytest.raises(SchemaMissingError):
        SchemaCache(tmp_path / "cache").kubernetes_schema("1.34.0", "Example", "example.com/v1")


def test_extract_openapi_definition_literal_ref_property_and_data():
    """Kubernetes JSONSchemaProps declares a field literally named '$ref'."""
    from jsonschema import Draft4Validator
    from k8s_manifest_validator.schemas import extract_openapi_definition

    spec = {"definitions": {
        "CRD": {"type": "object", "properties": {
            "schema": {"$ref": "#/definitions/JSONSchemaProps"}}},
        "JSONSchemaProps": {"type": "object", "properties": {
            "$ref": {"type": "string"},
            "properties": {"type": "object", "additionalProperties": {
                "$ref": "#/definitions/JSONSchemaProps"}},
            "example": {"type": "object", "default": {"$ref": "literal user data"}},
        }},
    }}
    result = extract_openapi_definition(spec, "CRD")
    assert set(result["definitions"]) == {"CRD", "JSONSchemaProps"}
    assert result["definitions"]["JSONSchemaProps"]["properties"]["$ref"] == {"type": "string"}
    Draft4Validator.check_schema(result)
    assert Draft4Validator(result).is_valid({"schema": {"$ref": "sample"}})
    assert not Draft4Validator(result).is_valid({"schema": {"$ref": 123}})


def test_extract_openapi_definition_nested_schema_locations():
    from k8s_manifest_validator.schemas import extract_openapi_definition

    spec = {"definitions": {
        "Root": {"allOf": [
            {"anyOf": [{"$ref": "#/definitions/A"}]},
            {"properties": {"items": {"type": "array", "items": {"$ref": "#/definitions/B"}}}},
            {"patternProperties": {"^x-": {"$ref": "#/definitions/C"}}},
            {"dependencies": {"someField": {"$ref": "#/definitions/D"}}},
        ]},
        "A": {"type": "string"},
        "B": {"type": "integer"},
        "C": {"type": "boolean"},
        "D": {"type": "object"},
    }}
    result = extract_openapi_definition(spec, "Root")
    assert set(result["definitions"]) == {"Root", "A", "B", "C", "D"}


def test_extract_openapi_definition_rejects_nonlocal_ref():
    from k8s_manifest_validator.schemas import extract_openapi_definition
    spec = {"definitions": {"Root": {"properties": {
        "spec": {"$ref": "https://example.com/schema.json"}}}}}
    with pytest.raises(ValueError, match="unsupported OpenAPI reference"):
        extract_openapi_definition(spec, "Root")


def test_crd_schema_fallback_with_literal_ref_property(tmp_path, monkeypatch):
    """Exercise the real schema cache's fallback path, without downloading."""
    from jsonschema import Draft4Validator
    from k8s_manifest_validator import schemas

    name = "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition"
    swagger = {"definitions": {
        name: {"type": "object", "properties": {
            "spec": {"$ref": "#/definitions/JSONSchemaProps"}}},
        "JSONSchemaProps": {"type": "object", "properties": {
            "$ref": {"type": "string"},
            "properties": {"type": "object", "additionalProperties": {
                "$ref": "#/definitions/JSONSchemaProps"}}}},
    }}
    def download(url, max_bytes=32 * 1024 * 1024):
        if "yannh/kubernetes-json-schema" in url:
            raise SchemaMissingError("HTTP 404")
        assert url.endswith("/v1.35.0/api/openapi-spec/swagger.json")
        return json.dumps(swagger).encode()
    monkeypatch.setattr(schemas, "_download", download)
    file = SchemaCache(tmp_path / "cache").kubernetes_schema(
        "1.35.0", "CustomResourceDefinition", "apiextensions.k8s.io/v1")
    result = json.loads(file.read_text())
    Draft4Validator.check_schema(result)
    assert "JSONSchemaProps" in result["definitions"]
    assert file.is_file()