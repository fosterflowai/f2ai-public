#!/usr/bin/env python3
"""Reconcile a Deployment Pod template to exact runtime-source metadata.

The reconciler deliberately reads only Kubernetes object metadata for Secret
and ConfigMap sources. It never requests, returns, or logs source data, UIDs,
resourceVersions, endpoint addresses, or health response bodies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import selectors
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, NamedTuple, Sequence


DNS_SUBDOMAIN = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$"
)
DNS_LABEL = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
HEALTH_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")
SUPPORTED_KINDS = frozenset({"Secret", "ConfigMap"})
ANNOTATION_PREFIX = "fosterflow.ai/runtime-source-"
MAX_CONVERGENCE_ATTEMPTS = 3
ROLLOUT_TIMEOUT_SECONDS = 600
PROXY_START_TIMEOUT_SECONDS = 15
METADATA_REQUEST_TIMEOUT_SECONDS = 30
MAX_PARTIAL_METADATA_BYTES = 262_144
PARTIAL_METADATA_ACCEPT = (
    "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
)
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PROXY_LISTEN = re.compile(r"^Starting to serve on 127\.0\.0\.1:(?P<port>[0-9]{1,5})$")


class ValidationError(ValueError):
    """Raised before kubectl when an action input is unsafe or ambiguous."""


class ReconcileError(RuntimeError):
    """Raised when live state cannot be reconciled without ambiguity."""


class SourceRef(NamedTuple):
    kind: str
    name: str


class SourceSnapshot(NamedTuple):
    uid: str
    resource_version: str


class ReconcileResult(NamedTuple):
    changed: bool
    attempts: int


Runner = Callable[..., subprocess.CompletedProcess[str]]
SourceReader = Callable[[str, SourceRef], SourceSnapshot]


def _validate_subdomain(value: str, field: str) -> str:
    if not isinstance(value, str) or DNS_SUBDOMAIN.fullmatch(value) is None:
        raise ValidationError(f"invalid {field}")
    if any(len(label) > 63 or not DNS_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValidationError(f"invalid {field}")
    return value


def _validate_namespace(value: str) -> str:
    if not isinstance(value, str) or DNS_LABEL.fullmatch(value) is None:
        raise ValidationError("invalid namespace")
    return value


def _validate_service_port(value: str) -> str:
    text = str(value)
    if text.isdecimal():
        number = int(text)
        if number < 1 or number > 65535:
            raise ValidationError("invalid service-port")
        return str(number)
    if DNS_LABEL.fullmatch(text) is None:
        raise ValidationError("invalid service-port")
    return text


def _validate_health_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 256
        or HEALTH_PATH.fullmatch(value) is None
        or "//" in value
        or any(segment in {".", ".."} for segment in value.split("/"))
    ):
        raise ValidationError("invalid health-path")
    return value


def _validate_expected_replicas(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValidationError("invalid expected-replicas")
    return value


def parse_sources(value: str) -> tuple[SourceRef, ...]:
    if not isinstance(value, str):
        raise ValidationError("invalid sources")
    parsed: list[SourceRef] = []
    seen: set[SourceRef] = set()
    for raw_line in value.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.count("/") != 1:
            raise ValidationError("invalid typed source")
        kind, name = line.split("/", 1)
        if kind not in SUPPORTED_KINDS:
            raise ValidationError("invalid typed source kind")
        source = SourceRef(kind, _validate_subdomain(name, "source name"))
        if source in seen:
            raise ValidationError("duplicate typed source")
        seen.add(source)
        parsed.append(source)
    if not parsed:
        raise ValidationError("at least one typed source is required")
    return tuple(parsed)


def annotation_key(kind: str, namespace: str, name: str) -> str:
    source_identity = f"{kind.lower()}/{namespace}/{name}".encode("utf-8")
    source_id = hashlib.sha256(source_identity).hexdigest()[:16]
    return f"{ANNOTATION_PREFIX}{source_id}"


def _fingerprint(
    source: SourceRef, namespace: str, snapshot: SourceSnapshot
) -> str:
    material = (
        f"{source.kind}/{namespace}/{source.name}/"
        f"{snapshot.uid}/{snapshot.resource_version}"
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _run(
    runner: Runner,
    argv: Sequence[str],
    *,
    failure: str,
) -> str:
    command = list(argv)
    try:
        completed = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=ROLLOUT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReconcileError(failure) from error
    if completed.returncode != 0:
        raise ReconcileError(failure)
    return completed.stdout


class _KubectlMetadataProxy:
    """Expose the authenticated API on loopback for strict content negotiation."""

    def __init__(self, popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen):
        self._popen = popen
        self._process: subprocess.Popen[str] | None = None

    def __enter__(self) -> str:
        try:
            process = self._popen(
                [
                    "kubectl",
                    "proxy",
                    "--address=127.0.0.1",
                    "--port=0",
                    r"--accept-hosts=^127\.0\.0\.1$",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except OSError as error:
            raise ReconcileError("metadata-only API proxy failed") from error
        self._process = process
        if process.stdout is None:
            self._stop()
            raise ReconcileError("metadata-only API proxy failed")

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + PROXY_START_TIMEOUT_SECONDS
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                events = selector.select(max(0.0, deadline - time.monotonic()))
                if not events:
                    break
                line = process.stdout.readline().strip()
                match = PROXY_LISTEN.fullmatch(line)
                if match is None:
                    continue
                port = int(match.group("port"))
                if 1 <= port <= 65535:
                    return f"http://127.0.0.1:{port}"
                break
        finally:
            selector.close()
        self._stop()
        raise ReconcileError("metadata-only API proxy failed")

    def _stop(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        finally:
            if process.stdout is not None:
                process.stdout.close()

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self._stop()


def _read_partial_metadata(
    base_url: str,
    namespace: str,
    source: SourceRef,
    *,
    opener: Callable[..., object] | None = None,
) -> SourceSnapshot:
    resource = "secrets" if source.kind == "Secret" else "configmaps"
    path = "/api/v1/namespaces/{namespace}/{resource}/{name}".format(
        namespace=urllib.parse.quote(namespace, safe=""),
        resource=resource,
        name=urllib.parse.quote(source.name, safe=""),
    )
    request = urllib.request.Request(
        f"{base_url}{path}",
        headers={"Accept": PARTIAL_METADATA_ACCEPT},
        method="GET",
    )
    effective_opener = opener if opener is not None else NO_PROXY_OPENER.open
    try:
        with effective_opener(
            request, timeout=METADATA_REQUEST_TIMEOUT_SECONDS
        ) as response:
            payload = response.read(MAX_PARTIAL_METADATA_BYTES + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise ReconcileError("source partial metadata lookup failed") from error
    if not isinstance(payload, bytes) or len(payload) > MAX_PARTIAL_METADATA_BYTES:
        raise ReconcileError("source partial metadata lookup failed")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReconcileError("source partial metadata lookup failed") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"apiVersion", "kind", "metadata"}
        or document.get("apiVersion") != "meta.k8s.io/v1"
        or document.get("kind") != "PartialObjectMetadata"
    ):
        raise ReconcileError("source partial metadata lookup failed")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise ReconcileError("source partial metadata lookup failed")
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    if not isinstance(uid, str) or not uid or not isinstance(resource_version, str) or not resource_version:
        raise ReconcileError("source partial metadata lookup failed")
    return SourceSnapshot(uid, resource_version)


def _read_sources(
    source_reader: SourceReader, namespace: str, sources: Sequence[SourceRef]
) -> dict[SourceRef, SourceSnapshot]:
    snapshots: dict[SourceRef, SourceSnapshot] = {}
    for source in sources:
        try:
            snapshot = source_reader(namespace, source)
        except Exception as error:
            raise ReconcileError("source metadata lookup failed") from error
        if (
            not isinstance(snapshot, tuple)
            or len(snapshot) != 2
            or not all(isinstance(value, str) and value for value in snapshot)
        ):
            raise ReconcileError("source metadata lookup failed")
        snapshots[source] = SourceSnapshot(snapshot[0], snapshot[1])
    return snapshots


def _load_json(output: str, failure: str) -> dict:
    try:
        value = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise ReconcileError(failure) from error
    if not isinstance(value, dict):
        raise ReconcileError(failure)
    return value


def _read_deployment(runner: Runner, namespace: str, deployment: str) -> dict:
    output = _run(
        runner,
        ["kubectl", "-n", namespace, "get", f"deployment/{deployment}", "-o", "json"],
        failure="deployment read failed",
    )
    return _load_json(output, "deployment read failed")


def _read_service(runner: Runner, namespace: str, service: str) -> dict:
    output = _run(
        runner,
        ["kubectl", "-n", namespace, "get", f"service/{service}", "-o", "json"],
        failure="service read failed",
    )
    return _load_json(output, "service read failed")


def _add_named_ref(
    references: set[SourceRef], kind: str, value: object
) -> None:
    if isinstance(value, dict):
        name = value.get("name")
        if isinstance(name, str) and name:
            references.add(SourceRef(kind, name))


def _runtime_source_refs(deployment: dict) -> set[SourceRef]:
    pod_spec = (
        ((deployment.get("spec") or {}).get("template") or {}).get("spec") or {}
    )
    if not isinstance(pod_spec, dict):
        raise ReconcileError("deployment runtime source coverage is invalid")
    references: set[SourceRef] = set()
    containers: list[object] = []
    for field in ("initContainers", "containers"):
        values = pod_spec.get(field) or []
        if not isinstance(values, list):
            raise ReconcileError("deployment runtime source coverage is invalid")
        containers.extend(values)
    for container in containers:
        if not isinstance(container, dict):
            raise ReconcileError("deployment runtime source coverage is invalid")
        for env_from in container.get("envFrom") or []:
            if not isinstance(env_from, dict):
                raise ReconcileError("deployment runtime source coverage is invalid")
            _add_named_ref(references, "Secret", env_from.get("secretRef"))
            _add_named_ref(references, "ConfigMap", env_from.get("configMapRef"))
        for env in container.get("env") or []:
            if not isinstance(env, dict):
                raise ReconcileError("deployment runtime source coverage is invalid")
            value_from = env.get("valueFrom") or {}
            if not isinstance(value_from, dict):
                raise ReconcileError("deployment runtime source coverage is invalid")
            _add_named_ref(references, "Secret", value_from.get("secretKeyRef"))
            _add_named_ref(references, "ConfigMap", value_from.get("configMapKeyRef"))
    volumes = pod_spec.get("volumes") or []
    if not isinstance(volumes, list):
        raise ReconcileError("deployment runtime source coverage is invalid")
    for volume in volumes:
        if not isinstance(volume, dict):
            raise ReconcileError("deployment runtime source coverage is invalid")
        secret = volume.get("secret")
        if isinstance(secret, dict):
            _add_named_ref(references, "Secret", {"name": secret.get("secretName")})
        _add_named_ref(references, "ConfigMap", volume.get("configMap"))
        projected = volume.get("projected")
        if isinstance(projected, dict):
            sources = projected.get("sources") or []
            if not isinstance(sources, list):
                raise ReconcileError("deployment runtime source coverage is invalid")
            for projection in sources:
                if not isinstance(projection, dict):
                    raise ReconcileError("deployment runtime source coverage is invalid")
                _add_named_ref(references, "Secret", projection.get("secret"))
                _add_named_ref(references, "ConfigMap", projection.get("configMap"))
    for pull_secret in pod_spec.get("imagePullSecrets") or []:
        _add_named_ref(references, "Secret", pull_secret)
    return references


def _validate_source_coverage(
    deployment: dict, source_refs: Sequence[SourceRef]
) -> None:
    if _runtime_source_refs(deployment) != set(source_refs):
        raise ReconcileError("deployment runtime source coverage mismatch")


def _int_or_string_equals(value: object, expected: int) -> bool:
    return value == expected or value == str(expected)


def _validate_deployment_contract(deployment: dict, expected_replicas: int) -> None:
    spec = deployment.get("spec") or {}
    strategy = spec.get("strategy") or {}
    rolling = strategy.get("rollingUpdate") or {}
    if (
        spec.get("replicas") != expected_replicas
        or strategy.get("type") != "RollingUpdate"
        or not _int_or_string_equals(rolling.get("maxUnavailable"), 0)
        or not _int_or_string_equals(rolling.get("maxSurge"), 1)
    ):
        raise ReconcileError("deployment contract is unsafe")


def _validate_deployment_status(deployment: dict, expected_replicas: int) -> None:
    metadata = deployment.get("metadata") or {}
    status = deployment.get("status") or {}
    if (
        status.get("observedGeneration") != metadata.get("generation")
        or status.get("replicas") != expected_replicas
        or status.get("updatedReplicas") != expected_replicas
        or status.get("readyReplicas") != expected_replicas
        or status.get("availableReplicas") != expected_replicas
    ):
        raise ReconcileError("deployment rollout is not fully ready")


def _current_annotations(deployment: dict) -> dict[str, str]:
    annotations = (
        ((deployment.get("spec") or {}).get("template") or {})
        .get("metadata", {})
        .get("annotations", {})
    )
    if not isinstance(annotations, dict):
        raise ReconcileError("deployment annotations are invalid")
    return {str(key): str(value) for key, value in annotations.items()}


def _desired_annotations(
    namespace: str,
    snapshots: dict[SourceRef, SourceSnapshot],
) -> dict[str, str]:
    return {
        annotation_key(source.kind, namespace, source.name): _fingerprint(
            source, namespace, snapshot
        )
        for source, snapshot in snapshots.items()
    }


def _has_drift(current: dict[str, str], desired: dict[str, str]) -> bool:
    managed_keys = {key for key in current if key.startswith(ANNOTATION_PREFIX)}
    return managed_keys != set(desired) or any(
        current.get(key) != value for key, value in desired.items()
    )


def _patch_annotations(
    runner: Runner,
    namespace: str,
    deployment_name: str,
    deployment: dict,
    desired: dict[str, str],
) -> None:
    resource_version = (deployment.get("metadata") or {}).get("resourceVersion")
    if not isinstance(resource_version, str) or not resource_version:
        raise ReconcileError("deployment resourceVersion is missing")
    current = _current_annotations(deployment)
    annotation_patch: dict[str, str | None] = dict(desired)
    for key in current:
        if key.startswith(ANNOTATION_PREFIX) and key not in desired:
            annotation_patch[key] = None
    patch = {
        "metadata": {"resourceVersion": resource_version},
        "spec": {"template": {"metadata": {"annotations": annotation_patch}}},
    }
    _run(
        runner,
        [
            "kubectl",
            "-n",
            namespace,
            "patch",
            f"deployment/{deployment_name}",
            "--type=merge",
            "--patch",
            json.dumps(patch, separators=(",", ":"), sort_keys=True),
        ],
        failure="deployment annotation patch failed",
    )


def _wait_rollout(runner: Runner, namespace: str, deployment: str) -> None:
    _run(
        runner,
        [
            "kubectl",
            "-n",
            namespace,
            "rollout",
            "status",
            f"deployment/{deployment}",
            f"--timeout={ROLLOUT_TIMEOUT_SECONDS}s",
        ],
        failure="deployment rollout failed",
    )


def _validate_service_selector(deployment: dict, service: dict) -> None:
    deployment_selector = ((deployment.get("spec") or {}).get("selector") or {}).get(
        "matchLabels"
    )
    service_selector = (service.get("spec") or {}).get("selector")
    if (
        not isinstance(deployment_selector, dict)
        or not deployment_selector
        or not isinstance(service_selector, dict)
        or service_selector != deployment_selector
    ):
        raise ReconcileError("service selector does not match deployment selector")


def _validate_endpoints(
    runner: Runner,
    namespace: str,
    service_name: str,
    deployment: dict,
    expected_replicas: int,
) -> None:
    service = _read_service(runner, namespace, service_name)
    _validate_service_selector(deployment, service)
    output = _run(
        runner,
        [
            "kubectl",
            "-n",
            namespace,
            "get",
            "endpointslice",
            "-l",
            f"kubernetes.io/service-name={service_name}",
            "-o",
            "json",
        ],
        failure="EndpointSlice read failed",
    )
    document = _load_json(output, "EndpointSlice read failed")
    ready_pod_uids: set[str] = set()
    for item in document.get("items") or []:
        for endpoint in item.get("endpoints") or []:
            conditions = endpoint.get("conditions") or {}
            if (
                conditions.get("ready") is not True
                or conditions.get("terminating") is True
                or conditions.get("serving") is False
            ):
                continue
            target = endpoint.get("targetRef") or {}
            uid = target.get("uid") if isinstance(target, dict) else None
            if (
                isinstance(uid, str)
                and uid
                and target.get("kind") == "Pod"
                and target.get("namespace") == namespace
            ):
                ready_pod_uids.add(uid)
    if len(ready_pod_uids) != expected_replicas:
        raise ReconcileError("service must have exactly the expected ready endpoints")


def _validate_health(
    runner: Runner,
    namespace: str,
    service: str,
    service_port: str,
    health_path: str,
) -> None:
    proxy_path = (
        f"/api/v1/namespaces/{namespace}/services/"
        f"http:{service}:{service_port}/proxy{health_path}"
    )
    _run(
        runner,
        ["kubectl", "get", "--raw", proxy_path],
        failure="service health check failed",
    )


def _validate_runtime(
    runner: Runner,
    namespace: str,
    deployment_name: str,
    service: str,
    service_port: str,
    health_path: str,
    desired: dict[str, str],
    source_refs: Sequence[SourceRef],
    expected_replicas: int,
) -> dict:
    deployment = _read_deployment(runner, namespace, deployment_name)
    _validate_deployment_contract(deployment, expected_replicas)
    _validate_source_coverage(deployment, source_refs)
    _validate_deployment_status(deployment, expected_replicas)
    if _has_drift(_current_annotations(deployment), desired):
        raise ReconcileError("deployment source annotation drift remains")
    _validate_endpoints(
        runner, namespace, service, deployment, expected_replicas
    )
    _validate_health(runner, namespace, service, service_port, health_path)
    return deployment


def reconcile(
    *,
    namespace: str,
    deployment: str,
    service: str,
    service_port: str,
    health_path: str,
    sources: str,
    check_only: bool,
    max_convergence_attempts: int,
    expected_replicas: int,
    runner: Runner = subprocess.run,
    source_reader: SourceReader | None = None,
) -> ReconcileResult:
    namespace = _validate_namespace(namespace)
    deployment = _validate_subdomain(deployment, "deployment")
    service = _validate_subdomain(service, "service")
    service_port = _validate_service_port(service_port)
    health_path = _validate_health_path(health_path)
    source_refs = parse_sources(sources)
    expected_replicas = _validate_expected_replicas(expected_replicas)
    if not isinstance(check_only, bool):
        raise ValidationError("invalid check-only")
    if (
        isinstance(max_convergence_attempts, bool)
        or not isinstance(max_convergence_attempts, int)
        or max_convergence_attempts < 1
        or max_convergence_attempts > MAX_CONVERGENCE_ATTEMPTS
    ):
        raise ValidationError("invalid max-convergence-attempts")

    if source_reader is None:
        with _KubectlMetadataProxy() as base_url:
            return _reconcile_validated(
                namespace=namespace,
                deployment=deployment,
                service=service,
                service_port=service_port,
                health_path=health_path,
                source_refs=source_refs,
                check_only=check_only,
                max_convergence_attempts=max_convergence_attempts,
                expected_replicas=expected_replicas,
                runner=runner,
                source_reader=lambda source_namespace, source: _read_partial_metadata(
                    base_url, source_namespace, source
                ),
            )
    return _reconcile_validated(
        namespace=namespace,
        deployment=deployment,
        service=service,
        service_port=service_port,
        health_path=health_path,
        source_refs=source_refs,
        check_only=check_only,
        max_convergence_attempts=max_convergence_attempts,
        expected_replicas=expected_replicas,
        runner=runner,
        source_reader=source_reader,
    )


def _reconcile_validated(
    *,
    namespace: str,
    deployment: str,
    service: str,
    service_port: str,
    health_path: str,
    source_refs: Sequence[SourceRef],
    check_only: bool,
    max_convergence_attempts: int,
    expected_replicas: int,
    runner: Runner,
    source_reader: SourceReader,
) -> ReconcileResult:

    changed = False
    for attempt in range(1, max_convergence_attempts + 1):
        before = _read_sources(source_reader, namespace, source_refs)
        desired = _desired_annotations(namespace, before)
        current_deployment = _read_deployment(runner, namespace, deployment)
        _validate_deployment_contract(current_deployment, expected_replicas)
        _validate_source_coverage(current_deployment, source_refs)
        drift = _has_drift(_current_annotations(current_deployment), desired)

        if check_only and drift:
            raise ReconcileError("runtime source annotation drift detected")
        if drift:
            _patch_annotations(
                runner,
                namespace,
                deployment,
                current_deployment,
                desired,
            )
            changed = True
        # The manifest apply may be rolling a new image even when the runtime
        # source fingerprints are already current.
        _wait_rollout(runner, namespace, deployment)

        validated_deployment = _validate_runtime(
            runner,
            namespace,
            deployment,
            service,
            service_port,
            health_path,
            desired,
            source_refs,
            expected_replicas,
        )
        after = _read_sources(source_reader, namespace, source_refs)
        final_deployment = _read_deployment(runner, namespace, deployment)
        _validate_deployment_contract(final_deployment, expected_replicas)
        _validate_source_coverage(final_deployment, source_refs)
        _validate_deployment_status(final_deployment, expected_replicas)
        if _has_drift(_current_annotations(final_deployment), desired):
            continue
        validated_rv = (validated_deployment.get("metadata") or {}).get(
            "resourceVersion"
        )
        final_rv = (final_deployment.get("metadata") or {}).get("resourceVersion")
        if after == before and isinstance(final_rv, str) and final_rv == validated_rv:
            return ReconcileResult(changed=changed, attempts=attempt)

    raise ReconcileError("runtime sources did not converge within the bounded attempts")


def _parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("must be true or false")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconcile a Deployment to exact Secret/ConfigMap metadata."
    )
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--service-port", required=True)
    parser.add_argument("--health-path", required=True)
    parser.add_argument("--sources", required=True)
    parser.add_argument("--expected-replicas", required=True, type=int)
    parser.add_argument("--check-only", required=True, type=_parse_bool)
    parser.add_argument("--max-convergence-attempts", required=True, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        result = reconcile(
            namespace=arguments.namespace,
            deployment=arguments.deployment,
            service=arguments.service,
            service_port=arguments.service_port,
            health_path=arguments.health_path,
            sources=arguments.sources,
            check_only=arguments.check_only,
            max_convergence_attempts=arguments.max_convergence_attempts,
            expected_replicas=arguments.expected_replicas,
        )
    except (ValidationError, ReconcileError) as error:
        print(f"runtime-source rollout failed: {error}", file=sys.stderr)
        return 1
    print(
        "runtime-source rollout complete: "
        f"changed={str(result.changed).lower()} attempts={result.attempts}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
