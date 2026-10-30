from pathlib import Path
import pytest
from k8s_manifest_validator.config import Config, Target


@pytest.fixture
def config(tmp_path):
    return Config(
        targets=[Target("ocp-a", "1.31.0", ("1.2.1",)),
                 Target("ocp-b", "1.31.0", ("1.3.0",)),
                 Target("native", "1.32.0", ("1.3.0",))],
        cache_dir=tmp_path / "cache", trivy_enabled=False,
    )


@pytest.fixture
def manifest_file(tmp_path):
    p = tmp_path / "manifests.yaml"
    p.write_text("""apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: test
          image: nginx
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web
spec:
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
---
apiVersion: acme.example.com/v1beta1
kind: Widget
metadata:
  name: widget
""", encoding="utf-8")
    return p


@pytest.fixture
def gateway_bundle(tmp_path):
    p = tmp_path / "standard-install.yaml"
    p.write_text("""apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: httproutes.gateway.networking.k8s.io
  annotations:
    gateway.networking.k8s.io/channel: standard
spec:
  group: gateway.networking.k8s.io
  names:
    kind: HTTPRoute
    plural: httproutes
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                rules:
                  type: array
                  items:
                    type: object
                    properties:
                      matches:
                        type: array
                        items:
                          type: object
                          properties:
                            path:
                              type: object
                              properties:
                                type:
                                  type: string
                                value:
                                  type: string
""", encoding="utf-8")
    return p
