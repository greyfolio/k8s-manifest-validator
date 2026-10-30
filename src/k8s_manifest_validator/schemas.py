"""Retrieve pinned schema files and turn Standard Gateway API CRDs into JSON Schema.

Kubernetes JSON Schemas come from yannh/kubernetes-json-schema and are cached by version/GVK.
Gateway CRD bundles are pinned to an explicit tagged GitHub release, never 'latest'.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
import json
import re
import yaml

GATEWAY_BUNDLE = "https://github.com/kubernetes-sigs/gateway-api/releases/download/v{version}/standard-install.yaml"
K8S_BASE = "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master"
SCHEMA_TEMPLATE = "{{.ResourceKind}}-{{.Group}}-{{.ResourceAPIVersion}}.json"
VALID_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


class SchemaFetchError(RuntimeError):
    pass


class SchemaMissingError(SchemaFetchError):
    """Upstream returned HTTP 404: an unsupported GVK or missing registry entry."""


def _download(url: str, max_bytes: int = 32 * 1024 * 1024) -> bytes:
    try:
        with urlopen(url, timeout=45) as response:
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise SchemaFetchError(f"schema download too large: {url}")
            return body
    except HTTPError as exc:
        if exc.code == 404:
            raise SchemaMissingError(f"schema does not exist (HTTP 404): {url}") from exc
        raise SchemaFetchError(f"HTTP {exc.code}: {url}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise SchemaFetchError(f"cannot fetch {url}: {exc}") from exc


def _write_atomic(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Verify complete content before replacing an existing cache entry.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(body)
    tmp.replace(path)


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def extract_openapi_definition(spec: dict, definition_name: str) -> dict:
    """Extract an OpenAPI v2 definition and its transitive local dependencies.

    Keep refs inside #/definitions so Kubeconform can resolve them entirely
    from this single file. Fail on unknown references instead of silently
    weakening validation.
    """
    definitions = spec["definitions"]
    included: dict[str, dict] = {}

    def visit(name: str) -> None:
        if name in included:
            return
        definition = definitions[name]  # A missing definition is an error.
        if not isinstance(definition, dict):
            raise TypeError(f"OpenAPI definition {name} is not an object")
        included[name] = definition

        def refs(node):
            """Visit only schema-valued keywords, not arbitrary objects.

            JSONSchemaProps declares a property literally named "$ref".
            The `properties` mapping is not itself a schema object.
            """
            if isinstance(node, list):
                 for value in node:
                     refs(value)
                return
            if not isinstance(node, dict):
                return

            ref = node.get("$ref")
            if ref is not None:
                prefix = "#/definitions/"
                if not isinstance(ref, str) or not ref.startswith(prefix):
                    raise ValueError(f"unsupported OpenAPI reference: {ref!r}")
                visit(ref[len(prefix):])

            # Mapping keys are property names, regexes, or definition names.
            for key in ("properties", "patternProperties", "definitions"):
                mapping = node.get(key)
                if isinstance(mapping, dict):
                    for schema in mapping.values():
                        refs(schema)

            for key in ("items", "additionalItems", "additionalProperties", "not"):
                refs(node.get(key))
            for key in ("allOf", "anyOf", "oneOf"):
                refs(node.get(key))
            dependencies = node.get("dependencies")
            if isinstance(dependencies, dict):
                for dependency in dependencies.values():
                    if isinstance(dependency, dict):
                        refs(dependency)
        refs(definition)

    visit(definition_name)
    root = deepcopy(included[definition_name])
    root["$schema"] = "http://json-schema.org/draft-04/schema#"
    root["definitions"] = included
    return root


def kube_filename(kind: str, api_version: str) -> str:
    """Match kubeconform/pkg/registry schemaPath() default registry filenames."""
    parts = api_version.split("/")
    version_parts = parts[0].split(".")
    suffix = "-" + version_parts[0].lower()
    if len(parts) > 1:
        suffix += "-" + parts[1].lower()
    return kind.lower() + suffix + ".json"


def local_filename(kind: str, api_version: str) -> str:
    if "/" in api_version:
        group, version = api_version.rsplit("/", 1)
    else:
        group, version = api_version, api_version
    return f"{kind.lower()}-{group}-{version}.json"


def convert_crd_openapi(schema: dict) -> dict:
    """Convert a Kubernetes structural OpenAPI v3 schema to JSON Schema draft 4.

    CEL and other Kubernetes admission semantics are NOT expressible in JSON Schema.
    x-kubernetes-int-or-string and nullable require special handling.
    """
    def convert(value):
        if isinstance(value, list):
            return [convert(v) for v in value]
        if not isinstance(value, dict):
            return value
        o = {k: convert(v) for k, v in value.items()
             if k not in ("nullable", "x-kubernetes-int-or-string", "x-kubernetes-validations")}
        if value.get("x-kubernetes-int-or-string"):
            # Avoid accidentally rejecting integers by a "type: string" annotation.
            o.pop("type", None)
            o["anyOf"] = [{"type": "integer"}, {"type": "string"}]
        if value.get("nullable"):
            typ = o.get("type")
            if typ:
                o["type"] = list(dict.fromkeys((typ if isinstance(typ, list) else [typ]) + ["null"]))
            elif "anyOf" in o:
                o["anyOf"].append({"type": "null"})
            else:
                o = {"anyOf": [o, {"type": "null"}]}
        # The CRD's Kubernetes structural schema enumerates permitted fields,
        # unless it explicitly permits arbitrary entries / preserved unknowns.
        if value.get("type") == "object" and "properties" in value and "additionalProperties" not in value:
            if not value.get("x-kubernetes-preserve-unknown-fields"):
                o["additionalProperties"] = False
        if value.get("x-kubernetes-preserve-unknown-fields") and "additionalProperties" not in o:
            o["additionalProperties"] = True
        return o

    s = convert(deepcopy(schema))
    s["$schema"] = "http://json-schema.org/draft-04/schema#"
    props = s.setdefault("properties", {})
    props.setdefault("apiVersion", {"type": "string"})
    props.setdefault("kind", {"type": "string"})
    # CRD metadata semantics are enforced by Kubernetes; don't reject valid labels etc.
    props.setdefault("metadata", {"type": "object"})
    s.setdefault("additionalProperties", False)
    return s


@dataclass
class GatewaySchemaSet:
    version: str
    directory: Path
    gvks: set[tuple[str, str]]
    sha256: str


class SchemaCache:
    def __init__(self, root: Path, offline: bool = False, gateway_bundles: dict[str, Path] | None = None):
        self.root = root
        self.offline = offline
        self.gateway_bundles = gateway_bundles or {}

    def kubernetes_schema(self, kubernetes_version: str, kind: str, api_version: str) -> Path:
        """Fetch one strict schema into deterministic local name; Kubeconform never uses HTTP."""
        if not VALID_VERSION.fullmatch(kubernetes_version):
            raise ValueError(f"invalid Kubernetes version: {kubernetes_version}")
        directory = self.root / "kubernetes" / kubernetes_version
        dest = directory / local_filename(kind, api_version)
        if dest.exists():
            return dest
        if self.offline:
            raise SchemaFetchError(f"uncached Kubernetes schema for {kind} {api_version} on {kubernetes_version}: {dest}")
        registry_file = kube_filename(kind, api_version)
        url = f"{K8S_BASE}/v{kubernetes_version}-standalone-strict/{registry_file}"
        try:
            body = _download(url)
        except SchemaMissingError:
            # The community registry omits CRDs even though they are a built-in API.
            # Build the schema from the official, version-pinned Kubernetes OpenAPI.
            if kind != "CustomResourceDefinition" or api_version != "apiextensions.k8s.io/v1":
                raise
            openapi_url = ("https://raw.githubusercontent.com/kubernetes/kubernetes/"
                           f"v{kubernetes_version}/api/openapi-spec/swagger.json")
            try:
                spec = json.loads(_download(openapi_url, max_bytes=64 * 1024 * 1024))
                schema = extract_openapi_definition(
                    spec,
                    "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition",
                )
            except (ValueError, TypeError, KeyError) as exc:
                raise SchemaFetchError(
                    f"cannot extract CRD schema from Kubernetes {kubernetes_version} OpenAPI: {exc}"
                ) from exc
            _write_atomic(dest, _json_bytes(schema))
            return dest
        try:
            parsed = json.loads(body)
            if not isinstance(parsed, dict):
                raise ValueError("schema is not an object")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SchemaFetchError(f"invalid JSON schema received from {url}: {exc}") from exc
        _write_atomic(dest, body)
        return dest

    def gateway_schemas(self, version: str) -> GatewaySchemaSet:
        if not VALID_VERSION.fullmatch(version):
            raise ValueError(f"invalid Gateway API version: {version}")
        directory = self.root / "gateway-api" / version
        bundle_path = directory / "standard-install.yaml"
        manifest_path = directory / "index.json"
        override = self.gateway_bundles.get(version)
        if override is not None:
            try:
                bundle = override.read_bytes()
            except OSError as exc:
                raise SchemaFetchError(f"cannot read gateway bundle {override}: {exc}") from exc
        elif bundle_path.exists():
            bundle = bundle_path.read_bytes()
        elif self.offline:
            raise SchemaFetchError(f"uncached Gateway API Standard bundle v{version}: {bundle_path}")
        else:
            bundle = _download(GATEWAY_BUNDLE.format(version=version))
        digest = sha256(bundle).hexdigest()
        if manifest_path.exists():
            try:
                index = json.loads(manifest_path.read_text(encoding="utf-8"))
                if index["sha256"] == digest:
                    gvks = {(entry["apiVersion"], entry["kind"]) for entry in index["schemas"]}
                    if all((directory / entry["filename"]).is_file() for entry in index["schemas"]):
                        return GatewaySchemaSet(version, directory, gvks, digest)
            except (KeyError, ValueError, OSError, TypeError):
                pass
        try:
            docs = list(yaml.safe_load_all(bundle))
        except yaml.YAMLError as exc:
            raise SchemaFetchError(f"invalid Gateway API CRD bundle v{version}: {exc}") from exc
        schemas = []
        gvks = set()
        for obj in docs:
            if not isinstance(obj, dict) or obj.get("kind") != "CustomResourceDefinition":
                continue
            spec = obj.get("spec") or {}
            group = spec.get("group")
            kind = (spec.get("names") or {}).get("kind")
            if group != "gateway.networking.k8s.io" or not kind:
                continue
            annotations = (obj.get("metadata") or {}).get("annotations") or {}
            if annotations.get("gateway.networking.k8s.io/channel", "standard") != "standard":
                raise SchemaFetchError(f"Gateway API v{version} bundle includes a non-standard CRD {kind}")
            for ver in spec.get("versions") or []:
                if not ver.get("served", False):
                    continue
                apiver = f"{group}/{ver['name']}"
                openapi = (ver.get("schema") or {}).get("openAPIV3Schema")
                if not isinstance(openapi, dict):
                    raise SchemaFetchError(f"Gateway API {kind} {apiver} has no OpenAPI schema")
                normalized = convert_crd_openapi(openapi)
                filename = local_filename(kind, apiver)
                schemas.append((filename, _json_bytes(normalized), apiver, kind))
                gvks.add((apiver, kind))
        if not schemas:
            raise SchemaFetchError(f"Gateway API bundle v{version} contains no Standard-channel schemas")
        directory.mkdir(parents=True, exist_ok=True)
        for filename, body, _, _ in schemas:
            _write_atomic(directory / filename, body)
        _write_atomic(manifest_path, _json_bytes({"version": version, "sha256": digest,
            "schemas": [{"filename": n, "apiVersion": a, "kind": k} for n, _, a, k in schemas]}))
        if override is None and not bundle_path.exists():
            _write_atomic(bundle_path, bundle)
        return GatewaySchemaSet(version, directory, gvks, digest)
