# Kubernetes manifest compatibility validator

A Python CLI that validates rendered Kubernetes YAML/JSON against **specific Kubernetes and Gateway API Standard-channel release schemas**, checks Kubernetes-owned alpha/beta API usage, and runs Trivy misconfiguration checks. Everything is normalized into one JSON report with source-file and resource metadata. It does **not** contact a Kubernetes cluster.

## Installation

Python 3.10+ is required:

```sh
python -m pip install -e .
```

Separately install `kubeconform` and `trivy` binaries on `PATH` (or point `tools.kubeconform` / `tools.trivy` at absolute paths). Recent Kubeconform releases are recommended because they expose `validationErrors` JSON paths. Example config is in `examples/config.yaml`. The example profiles are **illustrative**, not verified OpenShift-version mappings.

## Usage

```sh
k8s-manifest-validator -c examples/config.yaml ./rendered-manifests/
k8s-manifest-validator -c examples/config.yaml ./deployment.yaml -o results.json
helmfile template | k8s-manifest-validator -c examples/config.yaml -
k8s-manifest-validator -c examples/config.yaml --offline --no-trivy - < all.yaml
```

Inputs may be `-` (stdin), a file, or a directory recursively containing `.yaml`, `.yml`, and `.json` files. Multi-document YAML and Kubernetes `kind: List` documents are supported. Output is **always JSON** on stdout (unless `-o` is set); no diagnostic text is written to stdout.

Exit statuses: **0** all checks passed according to the Trivy threshold; **1** one or more policy/schema violations; **2** validation incomplete due to a scanner/config/download/input problem. Trivy findings below the configured threshold are still reported.

## Configuration

```yaml
targets:
  - name: cluster-a
    kubernetes: "1.31.0"
    gatewayAPI: ["1.2.1", "1.3.0"]
  - name: cluster-b
    kubernetes: "1.32.0"
    gatewayAPI: ["1.3.0"]
trivy:
  enabled: true
  failOn: ANY # ANY, LOW, MEDIUM, HIGH, CRITICAL or NONE
  compliance: k8s-pss-restricted-0.1 # Optional; omit to run all checks
  # customChecks: ["./policies"]
# cacheDir: ./.schema-cache
# offline: false
# additionalBuiltinGroups: ["example.k8s.io"]
# gatewayBundles:
#   "1.3.0": ./vendor/standard-install.yaml
# tools:
#   kubeconform: /usr/local/bin/kubeconform
#   trivy: trivy
#   timeoutSeconds: 300
```

`trivy.compliance` selects a Trivy compliance profile (for example,
`k8s-pss-restricted-0.1` for Pod Security Standards Restricted). Omit it to scan
with all default checks. Profile names and versions depend on the installed Trivy
checks bundle. Findings retain their source locations in either mode.

`failOn: ANY` fails on every Trivy finding, including severity `UNKNOWN`.
Severity thresholds (`LOW` through `CRITICAL`) fail at or above that level and
exclude `UNKNOWN`; `NONE` reports findings without failing on them. Replace the
old `failOn: UNKNOWN` setting with `ANY`; `UNKNOWN` is no longer accepted as a
policy value. The default remains `HIGH`.

Alternatively, an older, compact map format is supported:

```yaml
kubernetes:
  versions:
    "1.31":
      gatewayAPI: ["1.2.1", "1.3.0"]
    "1.32":
      gatewayAPI: ["1.3.0"]
```

**The version pairs are user-selected deployment targets**, not an implied guarantee that every pairing is supported by a given platform. For OpenShift, determine the actually installed Gateway API CRD bundle and choose that version (or provide a vendor bundle override).

## What runs

1. A YAML inventory records original file, document number, GVK, namespace, name, and field-to-line mapping. Non-Kubernetes custom APIs are excluded from built-in schema checks.
2. Each distinct Kubernetes version validates only Kubernetes-owned resource objects. Each distinct Gateway API release validates only `gateway.networking.k8s.io` resources. A Kubernetes version used by multiple targets is scanned once; a Gateway API release used by multiple targets is scanned once. Findings are associated with **all affected target names**.
3. `apiVersion` fields with `alpha` or `beta` are flagged **only** for built-in Kubernetes API groups. A CRD's *defined* versions and custom-resource API versions are not flagged. Gateway API resources are assessed by the Standard-channel release schemas, even if they use an upstream `v1beta1` GVK.
4. Trivy `config` runs against one normalized copy of each parsed manifest; findings include severity, remediation, references and original source locations where recoverable.

### Schema caching and offline runs

- On the first online run, each required built-in Kubernetes GVK schema is downloaded from the [yannh Kubernetes JSON Schema registry](https://github.com/yannh/kubernetes-json-schema) **strict**, version-specific directory, then stored under `~/.cache/k8s-manifest-validator/kubernetes/VERSION/`.
- Each Gateway API release uses that release's upstream [`standard-install.yaml`](https://gateway-api.sigs.k8s.io/docs/concepts/versioning/) from GitHub Releases, or an explicitly supplied vendor-local bundle. The CLI extracts all *served* GVKs and converts their structural `openAPIV3Schema` into JSON Schema in `~/.cache/k8s-manifest-validator/gateway-api/VERSION/`, with an index and bundle SHA256.
- The `--offline` flag **prevents all schema downloads**. Cache misses are explicitly marked as incomplete validation (exit 2). Trivy is passed `--skip-check-update` in offline mode; its checks must already be installed/cached. To run totally offline, first warm the schema and Trivy check caches in a connected environment.
- No schema fallback between Gateway API versions/channels is permitted. Missing Gateway GVKs in a successfully loaded bundle are compatibility violations. Missing Kubernetes GVK schemas (HTTP 404) are reported as unavailable, while download errors are *scanner errors*.
- The built-in schema registry is maintained on a mutable `master` branch. A cached file is reused for reproducibility, but for stronger provenance prepopulate and archive the schema cache along with the report. Vendor bundle overrides allow exact platform CRDs.

### Output shape

```json
{
  "schemaVersion": "1.0",
  "validatorVersion": "0.1.0",
  "status": "failed",
  "targets": [{"name": "cluster-a", "kubernetes": "1.31.0", "gatewayAPI": ["1.2.1"]}],
  "tools": {"kubeconform": "v0.x.x", "trivy": "Version: 0.x.x"},
  "summary": {"manifests": 1, "findings": 1, "violations": 1, "scannerErrors": 0, "failingFindings": 1},
  "findings": [{
    "rule": "GATEWAY_SCHEMA_INVALID", "scanner": "kubeconform", "severity": "ERROR",
    "message": "additionalProperties 'example' not allowed",
    "source": {"file": "route.yaml", "document": 1, "line": 14, "column": 5},
    "resource": {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "name": "frontend", "namespace": ""},
    "field": "/spec/example", "affected_targets": ["cluster-a"],
    "gateway_api_versions": ["1.2.1"], "category": "violation"
  }]
}
```

For field locations, the tool uses the Kubeconform field path or the normalized-Trivy-line-to-original-field map. When not enough information is provided, it reports the closest known enclosing field or object. Filenames and document numbers always refer to the input, not generated temporary files.

## Limitations / caveats

- Schema validation is not admission validation. CEL rules, controller capabilities, Cross-resource Gateway API semantics and some other Kubernetes checks are **not executed**. Standard-channel is **not** the same as Gateway API Core-only support.
- The Gateway API CRD converter supports Kubernetes `nullable`, `x-kubernetes-int-or-string`, `x-kubernetes-preserve-unknown-fields` and strict property checking. Other Kubernetes-specific OpenAPI/CEL extensions are not fully enforced; consult the release bundle directly if an edge case matters. Some CRD OpenAPI constructs may require improving the converter.
- `trivy config` checks misconfigurations; it does **not** scan container images for package vulnerabilities. Trivy's cached check bundle version is managed by Trivy, not pinned by this tool.
- Kubernetes-owned API classification uses a maintained allowlist of API groups plus `additionalBuiltinGroups`; an unusual future built-in API group needs adding. Third-party CRD instances are excluded from Kubeconform by default (but still scanned by Trivy).
- Only rendered manifests are analyzed. Helm chart template source locations cannot be recovered from rendered YAML; line numbers point into the rendered input files/stream.
- Multiple validators can report similar issues; deduplication deliberately merges only identical findings and their affected version targets.

## Test

```sh
python -m pip install -e '.[dev]'
pytest -q
```

The test suite uses small Gateway API CRD fixtures and mocked process output so it can run without the external tools or internet access. It does **not** replace an end-to-end smoke test with real Kubeconform/Trivy binaries and live schema downloads. 
