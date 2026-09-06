from __future__ import annotations

# test_gate: layer=unit runner=local_agent code_under_test=local_worktree target=local effect=read data_scope=local cost=none

import contextlib
import hashlib
import http.server
import importlib.util
import inspect
import io
import json
import os
import subprocess
import threading
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACTION_DIR = ROOT / ".github" / "actions" / "gke-runtime-source-rollout"
IMPLEMENTATION = Path(
    os.environ.get(
        "F2AI_RUNTIME_SOURCE_ROLLOUT_IMPLEMENTATION",
        ACTION_DIR / "runtime_source_rollout.py",
    )
)
ACTION = Path(
    os.environ.get(
        "F2AI_RUNTIME_SOURCE_ROLLOUT_ACTION",
        ACTION_DIR / "action.yml",
    )
)
SECRET_SENTINEL = "synthetic-secret-value-that-must-never-appear"


def load_subject():
    spec = importlib.util.spec_from_file_location("runtime_source_rollout", IMPLEMENTATION)
    if spec is None or spec.loader is None:
        raise AssertionError("runtime-source rollout implementation is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fingerprint(kind: str, namespace: str, name: str, uid: str, rv: str) -> str:
    material = f"{kind}/{namespace}/{name}/{uid}/{rv}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class FakeKubectl:
    def __init__(self, snapshots, *, deployment_annotations=None):
        self.snapshots = snapshots
        self.deployment_annotations = dict(deployment_annotations or {})
        self.commands: list[list[str]] = []
        self.patches: list[dict] = []
        self._source_reads = 0
        self.fail_source = False
        self.ready_endpoints = 2
        self.health_output = SECRET_SENTINEL
        self.spec_replicas = 2
        self.status_replicas = 2
        self.status_updated_replicas = 2
        self.status_ready_replicas = 2
        self.status_available_replicas = 2
        self.deployment_status_sequence: list[dict[str, int]] = []
        self.max_unavailable = 0
        self.max_surge = 1
        self.endpoint_port = 80
        self.deployment_selector = {"app.kubernetes.io/instance": "f2ai-account"}
        self.service_selector = dict(self.deployment_selector)
        self.runtime_refs = {
            "Secret/env-secrets",
            "ConfigMap/env-configs",
            "Secret/gcp-service-account",
        }
        self.deployment_resource_versions = ["deployment-rv"]
        self._deployment_reads = 0

    def read_source(self, namespace, source):
        if namespace != "app" or self.fail_source:
            raise RuntimeError(SECRET_SENTINEL)
        snapshot_index = min(
            self._source_reads // len(self.snapshots[0]), len(self.snapshots) - 1
        )
        uid, rv = self.snapshots[snapshot_index][f"{source.kind}/{source.name}"]
        self._source_reads += 1
        return load_subject().SourceSnapshot(uid, rv)

    def pod_spec(self):
        env_from = []
        volumes = []
        if "Secret/env-secrets" in self.runtime_refs:
            env_from.append({"secretRef": {"name": "env-secrets"}})
        if "ConfigMap/env-configs" in self.runtime_refs:
            env_from.append({"configMapRef": {"name": "env-configs"}})
        if "Secret/gcp-service-account" in self.runtime_refs:
            volumes.append(
                {"name": "gcp", "secret": {"secretName": "gcp-service-account"}}
            )
        for ref in sorted(
            self.runtime_refs
            - {
                "Secret/env-secrets",
                "ConfigMap/env-configs",
                "Secret/gcp-service-account",
            }
        ):
            kind, name = ref.split("/", 1)
            reference_key = "secretRef" if kind == "Secret" else "configMapRef"
            env_from.append({reference_key: {"name": name}})
        return {
            "containers": [
                {
                    "name": "f2ai-account",
                    "envFrom": env_from,
                    "env": [
                        {
                            "name": "identity_internal_token",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "name": "env-secrets",
                                    "key": "identity_internal_token",
                                }
                            },
                        }
                    ],
                }
            ],
            "volumes": volumes,
        }

    def __call__(self, argv, **kwargs):
        self.assert_safe_invocation(argv, kwargs)
        command = list(argv)
        self.commands.append(command)

        if "get" in command and any(
            token.startswith("Secret/") or token.startswith("ConfigMap/")
            for token in command
        ):
            if self.fail_source:
                return subprocess.CompletedProcess(command, 1, "", SECRET_SENTINEL)
            ref = next(
                token
                for token in command
                if token.startswith("Secret/") or token.startswith("ConfigMap/")
            )
            snapshot_index = min(
                self._source_reads // len(self.snapshots[0]), len(self.snapshots) - 1
            )
            uid, rv = self.snapshots[snapshot_index][ref]
            self._source_reads += 1
            return subprocess.CompletedProcess(command, 0, f"{uid}\t{rv}", "")

        if "get" in command and any(token.startswith("deployment/") for token in command):
            deployment_read_index = self._deployment_reads
            rv_index = min(
                deployment_read_index,
                len(self.deployment_resource_versions) - 1,
            )
            deployment_rv = self.deployment_resource_versions[rv_index]
            self._deployment_reads += 1
            status = {
                "observedGeneration": 9,
                "replicas": self.status_replicas,
                "updatedReplicas": self.status_updated_replicas,
                "readyReplicas": self.status_ready_replicas,
                "availableReplicas": self.status_available_replicas,
            }
            if self.deployment_status_sequence:
                status.update(
                    self.deployment_status_sequence[
                        min(
                            deployment_read_index,
                            len(self.deployment_status_sequence) - 1,
                        )
                    ]
                )
            body = {
                "metadata": {"resourceVersion": deployment_rv, "generation": 9},
                "spec": {
                    "replicas": self.spec_replicas,
                    "selector": {"matchLabels": self.deployment_selector},
                    "strategy": {
                        "type": "RollingUpdate",
                        "rollingUpdate": {
                            "maxUnavailable": self.max_unavailable,
                            "maxSurge": self.max_surge,
                        },
                    },
                    "template": {
                        "metadata": {
                            "annotations": self.deployment_annotations,
                            "labels": self.deployment_selector,
                        },
                        "spec": self.pod_spec(),
                    },
                },
                "status": status,
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(body), "")

        if "patch" in command:
            payload = json.loads(command[command.index("--patch") + 1])
            self.patches.append(payload)
            for key, value in payload["spec"]["template"]["metadata"][
                "annotations"
            ].items():
                if value is None:
                    self.deployment_annotations.pop(key, None)
                else:
                    self.deployment_annotations[key] = value
            return subprocess.CompletedProcess(command, 0, "patched", "")

        if "endpointslice" in command:
            endpoints = [
                {
                    "addresses": [f"192.0.2.{index + 1}"],
                    "conditions": {"ready": True, "serving": True, "terminating": False},
                    "targetRef": {
                        "kind": "Pod",
                        "namespace": "app",
                        "name": f"f2ai-account-{index + 1}",
                        "uid": f"pod-uid-{index + 1}",
                    },
                }
                for index in range(self.ready_endpoints)
            ]
            body = {
                "items": [
                    {
                        "ports": [{"name": "http", "port": self.endpoint_port}],
                        "endpoints": endpoints,
                    }
                ]
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(body), "")

        if "get" in command and any(token.startswith("service/") for token in command):
            body = {"spec": {"selector": self.service_selector}}
            return subprocess.CompletedProcess(command, 0, json.dumps(body), "")

        if "--raw" in command:
            return subprocess.CompletedProcess(command, 0, self.health_output, "")

        raise AssertionError(f"unexpected kubectl argv: {command!r}")

    def assert_safe_invocation(self, argv, kwargs):
        if not isinstance(argv, (list, tuple)):
            raise AssertionError("subprocess invocation must use an argv array")
        if kwargs.get("shell"):
            raise AssertionError("shell execution is forbidden")
        joined = " ".join(str(part) for part in argv)
        if ".data" in joined or SECRET_SENTINEL in joined:
            raise AssertionError("secret data must never appear in kubectl commands")


def snapshot(*, env=("uid-env", "10"), config=("uid-config", "20"), gcp=("uid-gcp", "30")):
    return {
        "Secret/env-secrets": env,
        "ConfigMap/env-configs": config,
        "Secret/gcp-service-account": gcp,
    }


class RuntimeSourceRolloutTest(unittest.TestCase):
    def setUp(self):
        self.subject = load_subject()
        self.sources = "\n".join(
            [
                "Secret/env-secrets",
                "ConfigMap/env-configs",
                "Secret/gcp-service-account",
            ]
        )

    def current_annotations(self, value_snapshot):
        annotations = {}
        for ref, (uid, rv) in value_snapshot.items():
            kind, name = ref.split("/", 1)
            key = self.subject.annotation_key(kind, "app", name)
            annotations[key] = fingerprint(kind, "app", name, uid, rv)
        return annotations

    def test_partial_metadata_transport_sends_strict_accept_without_fallback(self):
        requests = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps(
                    {
                        "apiVersion": "meta.k8s.io/v1",
                        "kind": "PartialObjectMetadata",
                        "metadata": {"uid": "uid-env", "resourceVersion": "10"},
                    }
                ).encode("utf-8")

        def opener(request, **kwargs):
            requests.append((request, kwargs))
            return Response()

        result = self.subject._read_partial_metadata(
            "http://127.0.0.1:43210",
            "app",
            self.subject.SourceRef("Secret", "env-secrets"),
            opener=opener,
        )

        self.assertEqual(("uid-env", "10"), tuple(result))
        request, options = requests[0]
        self.assertEqual(
            "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
            request.get_header("Accept"),
        )
        self.assertNotIn(",", request.get_header("Accept"))
        self.assertTrue(request.full_url.endswith("/api/v1/namespaces/app/secrets/env-secrets"))
        self.assertGreater(options["timeout"], 0)

    def test_partial_metadata_transport_rejects_full_secret_fallback(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps(
                    {
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {"uid": "uid-env", "resourceVersion": "10"},
                        "data": {"must-not-enter": SECRET_SENTINEL},
                    }
                ).encode("utf-8")

        with self.assertRaisesRegex(self.subject.ReconcileError, "partial metadata"):
            self.subject._read_partial_metadata(
                "http://127.0.0.1:43210",
                "app",
                self.subject.SourceRef("Secret", "env-secrets"),
                opener=lambda *_args, **_kwargs: Response(),
            )

    def test_partial_metadata_default_transport_ignores_ambient_proxies(self):
        expected_accept = (
            "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
        )

        class Handler(http.server.BaseHTTPRequestHandler):
            received_accept = None

            def do_GET(self):
                type(self).received_accept = self.headers.get("Accept")
                payload = json.dumps(
                    {
                        "apiVersion": "meta.k8s.io/v1",
                        "kind": "PartialObjectMetadata",
                        "metadata": {"uid": "uid-env", "resourceVersion": "10"},
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.dict(
                os.environ,
                {
                    "HTTP_PROXY": "http://127.0.0.1:1",
                    "HTTPS_PROXY": "http://127.0.0.1:1",
                    "NO_PROXY": "",
                    "no_proxy": "",
                },
            ):
                result = self.subject._read_partial_metadata(
                    f"http://127.0.0.1:{server.server_port}",
                    "app",
                    self.subject.SourceRef("Secret", "env-secrets"),
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(("uid-env", "10"), tuple(result))
        self.assertEqual(expected_accept, Handler.received_accept)

    def test_account_source_annotation_keys_are_stable_and_non_disclosing(self):
        self.assertEqual(
            {
                "Secret/env-secrets": "fosterflow.ai/runtime-source-4141a6e4c87c7482",
                "ConfigMap/env-configs": "fosterflow.ai/runtime-source-707e1539a5bd6364",
                "Secret/gcp-service-account": "fosterflow.ai/runtime-source-724707e9845e089d",
            },
            {
                ref: self.subject.annotation_key(*ref.split("/", 1)[:1], "app", ref.split("/", 1)[1])
                for ref in snapshot()
            },
        )

    def run_rollout(
        self,
        fake,
        *,
        check_only=False,
        namespace="app",
        sources=None,
        expected_replicas=2,
    ):
        arguments = dict(
            namespace=namespace,
            deployment="f2ai-account",
            service="f2ai-account",
            service_port="80",
            health_path="/health",
            sources=self.sources if sources is None else sources,
            check_only=check_only,
            max_convergence_attempts=3,
            runner=fake,
        )
        if "expected_replicas" in inspect.signature(self.subject.reconcile).parameters:
            arguments["expected_replicas"] = expected_replicas
        if "source_reader" in inspect.signature(self.subject.reconcile).parameters:
            arguments["source_reader"] = fake.read_source
        return self.subject.reconcile(**arguments)

    def assert_no_rollout_watch(self, fake):
        self.assertFalse(
            any("rollout" in command for command in fake.commands),
            "the action must not use kubectl rollout status",
        )

    def test_same_source_snapshot_is_idempotent_but_waits_for_image_rollout(self):
        value_snapshot = snapshot()
        fake = FakeKubectl(
            [value_snapshot, value_snapshot],
            deployment_annotations=self.current_annotations(value_snapshot),
        )

        result = self.run_rollout(fake)

        self.assertFalse(result.changed)
        self.assertEqual([], fake.patches)
        self.assert_no_rollout_watch(fake)

    def test_wait_rollout_polls_exact_deployment_status_without_rollout_watch(self):
        fake = FakeKubectl([snapshot()])
        fake.deployment_status_sequence = [
            {
                "replicas": 3,
                "updatedReplicas": 2,
                "readyReplicas": 1,
                "availableReplicas": 1,
            },
            {
                "replicas": 2,
                "updatedReplicas": 2,
                "readyReplicas": 2,
                "availableReplicas": 2,
            },
        ]
        clock = iter((0.0, 1.0, 2.0))
        sleeps = []

        self.subject._wait_rollout(
            fake,
            "app",
            "f2ai-account",
            2,
            monotonic=lambda: next(clock),
            sleeper=sleeps.append,
        )

        self.assertEqual([5], sleeps)
        self.assert_no_rollout_watch(fake)

    def test_wait_rollout_fails_at_its_bounded_deadline(self):
        fake = FakeKubectl([snapshot()])
        fake.status_ready_replicas = 1
        clock = iter((0.0, float(self.subject.ROLLOUT_TIMEOUT_SECONDS)))

        with self.assertRaisesRegex(
            self.subject.ReconcileError, "deployment rollout failed"
        ):
            self.subject._wait_rollout(
                fake,
                "app",
                "f2ai-account",
                2,
                monotonic=lambda: next(clock),
                sleeper=lambda _seconds: self.fail("deadline must not sleep"),
            )

        self.assert_no_rollout_watch(fake)

    def test_each_typed_source_change_updates_only_pod_template_annotations(self):
        for changed_ref in snapshot():
            with self.subTest(changed_ref=changed_ref):
                current = snapshot()
                stale = snapshot()
                old_uid, old_rv = stale[changed_ref]
                stale[changed_ref] = (old_uid, f"old-{old_rv}")
                fake = FakeKubectl(
                    [current, current],
                    deployment_annotations=self.current_annotations(stale),
                )

                result = self.run_rollout(fake)

                self.assertTrue(result.changed)
                self.assertEqual(1, len(fake.patches))
                self.assert_no_rollout_watch(fake)
                patch = fake.patches[0]
                self.assertEqual({"resourceVersion": "deployment-rv"}, patch["metadata"])
                self.assertEqual(
                    {"metadata": {"annotations": self.current_annotations(current)}},
                    patch["spec"]["template"],
                )
                self.assertEqual(
                    {"metadata", "spec"}, set(patch), "patch may change annotations only"
                )

    def test_delete_and_recreate_uid_change_triggers_even_when_rv_matches(self):
        old = snapshot(env=("uid-old", "10"))
        recreated = snapshot(env=("uid-new", "10"))
        fake = FakeKubectl(
            [recreated, recreated],
            deployment_annotations=self.current_annotations(old),
        )

        result = self.run_rollout(fake)

        self.assertTrue(result.changed)
        self.assertEqual(1, len(fake.patches))

    def test_mid_rollout_source_change_reconciles_again_to_latest_snapshot(self):
        first = snapshot()
        second = snapshot(config=("uid-config", "21"))
        fake = FakeKubectl(
            [first, second, second, second],
            deployment_annotations={},
        )

        result = self.run_rollout(fake)

        self.assertTrue(result.changed)
        self.assertEqual(2, result.attempts)
        self.assertEqual(2, len(fake.patches))
        self.assert_no_rollout_watch(fake)
        self.assertEqual(self.current_annotations(second), fake.deployment_annotations)

    def test_fourth_snapshot_drift_fails_closed_after_three_attempts(self):
        first = snapshot()
        second = snapshot(env=("uid-env", "11"))
        third = snapshot(env=("uid-env", "12"))
        fourth = snapshot(env=("uid-env", "13"))
        fake = FakeKubectl(
            [first, second, second, third, third, fourth],
            deployment_annotations={},
        )

        with self.assertRaisesRegex(self.subject.ReconcileError, "did not converge"):
            self.run_rollout(fake)

        self.assertEqual(3, len(fake.patches))
        self.assert_no_rollout_watch(fake)

    def test_check_only_fails_on_drift_without_patch(self):
        value_snapshot = snapshot()
        fake = FakeKubectl([value_snapshot, value_snapshot], deployment_annotations={})

        with self.assertRaisesRegex(self.subject.ReconcileError, "drift"):
            self.run_rollout(fake, check_only=True)

        self.assertEqual([], fake.patches)
        self.assert_no_rollout_watch(fake)

    def test_sources_must_exactly_cover_all_pod_runtime_refs(self):
        cases = [
            ({"Secret/env-secrets", "ConfigMap/env-configs"}, self.sources),
            (
                {
                    "Secret/env-secrets",
                    "ConfigMap/env-configs",
                    "Secret/gcp-service-account",
                    "ConfigMap/untracked-runtime-config",
                },
                self.sources,
            ),
            (
                {
                    "Secret/env-secrets",
                    "ConfigMap/env-configs",
                    "Secret/gcp-service-account",
                },
                "Secret/env-secrets\nConfigMap/env-configs",
            ),
        ]
        for runtime_refs, declared_sources in cases:
            with self.subTest(runtime_refs=runtime_refs, sources=declared_sources):
                fake = FakeKubectl([snapshot()], deployment_annotations={})
                fake.runtime_refs = runtime_refs
                with self.assertRaisesRegex(
                    self.subject.ReconcileError, "runtime source coverage"
                ):
                    self.run_rollout(fake, sources=declared_sources)
                self.assertEqual([], fake.patches)

    def test_stale_managed_annotation_is_deleted_without_touching_other_annotations(self):
        value_snapshot = snapshot()
        expected = self.current_annotations(value_snapshot)
        stale_key = "fosterflow.ai/runtime-source-deadbeefdeadbeef"
        existing = {
            **expected,
            stale_key: "stale-fingerprint",
            "kubectl.kubernetes.io/restartedAt": "preserve-me",
        }
        fake = FakeKubectl([value_snapshot, value_snapshot], deployment_annotations=existing)

        result = self.run_rollout(fake)

        self.assertTrue(result.changed)
        patch_annotations = fake.patches[0]["spec"]["template"]["metadata"][
            "annotations"
        ]
        self.assertIsNone(patch_annotations[stale_key])
        self.assertNotIn("kubectl.kubernetes.io/restartedAt", patch_annotations)
        self.assertEqual("preserve-me", fake.deployment_annotations["kubectl.kubernetes.io/restartedAt"])

    def test_deployment_safety_contract_fails_closed_before_patch(self):
        cases = [
            ("spec_replicas", 1),
            ("max_unavailable", 1),
            ("max_surge", 0),
        ]
        for attribute, unsafe_value in cases:
            with self.subTest(attribute=attribute):
                fake = FakeKubectl([snapshot()], deployment_annotations={})
                setattr(fake, attribute, unsafe_value)
                with self.assertRaisesRegex(self.subject.ReconcileError, "deployment contract"):
                    self.run_rollout(fake)
                self.assertEqual([], fake.patches)

    def test_one_replica_contract_validates_spec_status_and_one_ready_backend(self):
        if "expected_replicas" not in inspect.signature(self.subject.reconcile).parameters:
            self.fail("runtime-source rollout API is missing expected_replicas")
        value_snapshot = snapshot()
        fake = FakeKubectl(
            [value_snapshot, value_snapshot],
            deployment_annotations=self.current_annotations(value_snapshot),
        )
        fake.spec_replicas = 1
        fake.status_replicas = 1
        fake.status_updated_replicas = 1
        fake.status_ready_replicas = 1
        fake.status_available_replicas = 1
        fake.ready_endpoints = 1

        result = self.run_rollout(fake, expected_replicas=1)

        self.assertFalse(result.changed)
        self.assert_no_rollout_watch(fake)

    def test_each_status_count_must_equal_expected_replicas(self):
        for attribute, status_key in (
            ("status_replicas", "replicas"),
            ("status_updated_replicas", "updatedReplicas"),
            ("status_ready_replicas", "readyReplicas"),
            ("status_available_replicas", "availableReplicas"),
        ):
            with self.subTest(attribute=attribute):
                value_snapshot = snapshot()
                fake = FakeKubectl(
                    [value_snapshot, value_snapshot],
                    deployment_annotations=self.current_annotations(value_snapshot),
                )
                fake.deployment_status_sequence = [{}, {}, {status_key: 1}]

                with self.assertRaisesRegex(
                    self.subject.ReconcileError, "fully ready"
                ):
                    self.run_rollout(fake, expected_replicas=2)

    def test_expected_replicas_must_be_a_positive_non_bool_integer(self):
        if "expected_replicas" not in inspect.signature(self.subject.reconcile).parameters:
            self.fail("runtime-source rollout API is missing expected_replicas validation")
        for invalid in (0, -1, True, False, 1.0, "1", None):
            with self.subTest(expected_replicas=invalid):
                fake = FakeKubectl([snapshot()])

                with self.assertRaisesRegex(
                    self.subject.ValidationError, "expected-replicas"
                ):
                    self.run_rollout(fake, expected_replicas=invalid)

                self.assertEqual([], fake.commands)

    def test_endpoint_contract_requires_exactly_two_ready_nonterminating_backends(self):
        value_snapshot = snapshot()
        fake = FakeKubectl(
            [value_snapshot, value_snapshot],
            deployment_annotations=self.current_annotations(value_snapshot),
        )
        fake.ready_endpoints = 1

        with self.assertRaisesRegex(self.subject.ReconcileError, "ready endpoints"):
            self.run_rollout(fake)

    def test_one_dual_stack_pod_does_not_count_as_two_backends(self):
        value_snapshot = snapshot()
        fake = FakeKubectl(
            [value_snapshot, value_snapshot],
            deployment_annotations=self.current_annotations(value_snapshot),
        )
        fake.ready_endpoints = 2

        original_call = fake.__call__

        def one_dual_stack_backend(argv, **kwargs):
            result = original_call(argv, **kwargs)
            if "endpointslice" not in list(argv):
                return result
            document = json.loads(result.stdout)
            endpoints = document["items"][0]["endpoints"]
            endpoints[1]["targetRef"] = dict(endpoints[0]["targetRef"])
            endpoints[0]["addresses"] = ["192.0.2.1", "2001:db8::1"]
            endpoints[1]["addresses"] = ["192.0.2.1", "2001:db8::1"]
            return subprocess.CompletedProcess(list(argv), 0, json.dumps(document), "")

        fake.__call__ = one_dual_stack_backend
        # Special methods are resolved on the type; expose the wrapper through
        # the runner argument explicitly for this adversarial case.
        arguments = dict(
                namespace="app",
                deployment="f2ai-account",
                service="f2ai-account",
                service_port="80",
                health_path="/health",
                sources=self.sources,
                check_only=False,
                max_convergence_attempts=3,
                runner=one_dual_stack_backend,
            )
        if "expected_replicas" in inspect.signature(self.subject.reconcile).parameters:
            arguments["expected_replicas"] = 2
        if "source_reader" in inspect.signature(self.subject.reconcile).parameters:
            arguments["source_reader"] = fake.read_source
        with self.assertRaisesRegex(self.subject.ReconcileError, "ready endpoints"):
            self.subject.reconcile(**arguments)

    def test_service_selector_must_exactly_match_deployment_selector(self):
        value_snapshot = snapshot()
        fake = FakeKubectl(
            [value_snapshot, value_snapshot],
            deployment_annotations=self.current_annotations(value_snapshot),
        )
        fake.service_selector = {"app.kubernetes.io/instance": "another-app"}

        with self.assertRaisesRegex(self.subject.ReconcileError, "service selector"):
            self.run_rollout(fake)

    def test_service_port_does_not_need_to_equal_endpointslice_target_port(self):
        value_snapshot = snapshot()
        fake = FakeKubectl(
            [value_snapshot, value_snapshot],
            deployment_annotations=self.current_annotations(value_snapshot),
        )
        fake.endpoint_port = 8080

        result = self.run_rollout(fake)

        self.assertFalse(result.changed)
        self.assert_no_rollout_watch(fake)

    def test_final_deployment_change_retries_before_success(self):
        value_snapshot = snapshot()
        fake = FakeKubectl(
            [value_snapshot, value_snapshot, value_snapshot, value_snapshot],
            deployment_annotations=self.current_annotations(value_snapshot),
        )
        fake.deployment_resource_versions = [
            "rv-1",
            "rv-1",
            "rv-1",
            "rv-concurrent",
            "rv-concurrent",
            "rv-concurrent",
            "rv-concurrent",
            "rv-concurrent",
        ]

        result = self.run_rollout(fake)

        self.assertEqual(2, result.attempts)
        self.assertFalse(result.changed)
        self.assert_no_rollout_watch(fake)

    def test_missing_source_fails_without_leaking_command_output(self):
        fake = FakeKubectl([snapshot()])
        fake.fail_source = True
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaisesRegex(self.subject.ReconcileError, "source metadata"):
                self.run_rollout(fake)

        transcript = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(SECRET_SENTINEL, transcript)
        self.assertNotIn("uid-env", transcript)
        self.assertNotIn("resourceVersion", transcript)

    def test_malicious_names_and_paths_are_rejected_before_subprocess(self):
        attacks = [
            {"namespace": "app;touch-pwned"},
            {"deployment": "f2ai-account$(id)"},
            {"service": "f2ai-account`id`"},
            {"service_port": "80;id"},
            {"health_path": "/health\n--raw=/api/v1/secrets"},
            {"sources": "Secret/env-secrets;id"},
            {"sources": "secret/env-secrets"},
            {"sources": "Secret/env-secrets\nSecret/env-secrets"},
            {"max_convergence_attempts": 0},
            {"max_convergence_attempts": 4},
        ]
        for override in attacks:
            with self.subTest(override=override):
                fake = FakeKubectl([snapshot()])
                arguments = {
                    "namespace": "app",
                    "deployment": "f2ai-account",
                    "service": "f2ai-account",
                    "service_port": "80",
                    "health_path": "/health",
                    "sources": self.sources,
                    "check_only": False,
                    "max_convergence_attempts": 3,
                    "runner": fake,
                }
                if "expected_replicas" in inspect.signature(self.subject.reconcile).parameters:
                    arguments["expected_replicas"] = 2
                if "source_reader" in inspect.signature(self.subject.reconcile).parameters:
                    arguments["source_reader"] = fake.read_source
                arguments.update(override)
                with self.assertRaises(self.subject.ValidationError):
                    self.subject.reconcile(**arguments)
                self.assertEqual([], fake.commands)

    def test_commands_and_success_output_never_expose_source_metadata_or_secret_data(self):
        value_snapshot = snapshot()
        fake = FakeKubectl([value_snapshot, value_snapshot], deployment_annotations={})
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = self.run_rollout(fake)

        self.assertTrue(result.changed)
        transcript = stdout.getvalue() + stderr.getvalue()
        for forbidden in (SECRET_SENTINEL, "uid-env", "uid-config", "uid-gcp", ".data"):
            self.assertNotIn(forbidden, transcript)
        for command in fake.commands:
            rendered = " ".join(command)
            self.assertNotIn(SECRET_SENTINEL, rendered)
            self.assertNotIn(".data", rendered)


class CompositeActionContractTest(unittest.TestCase):
    def test_action_exposes_only_the_frozen_inputs_and_passes_values_via_environment(self):
        text = ACTION.read_text(encoding="utf-8")
        expected = {
            "namespace",
            "deployment",
            "service",
            "service-port",
            "health-path",
            "sources",
            "expected-replicas",
            "check-only",
            "max-convergence-attempts",
        }
        declared = {
            line.strip()[:-1]
            for line in text.splitlines()
            if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":")
        }
        self.assertEqual(expected, declared)
        self.assertIn("using: composite", text)
        self.assertIn("python3 \"${{ github.action_path }}/runtime_source_rollout.py\"", text)
        for name in expected:
            self.assertIn(f"${{{{ inputs.{name} }}}}", text)
        run_block = text.split("run: |", 1)[1]
        self.assertNotIn("${{ inputs.", run_block)
        expected_replicas_block = text.split("  expected-replicas:", 1)[1].split(
            "\n  check-only:", 1
        )[0]
        self.assertIn('default: "2"', expected_replicas_block)


class CommandLineContractTest(unittest.TestCase):
    def test_cli_passes_expected_replicas_to_the_python_api(self):
        subject = load_subject()
        if "expected_replicas" not in inspect.signature(subject.reconcile).parameters:
            self.fail("runtime-source rollout CLI is missing expected_replicas")
        expected_result = subject.ReconcileResult(changed=False, attempts=1)
        argv = [
            "--namespace",
            "app",
            "--deployment",
            "f2ai-udp",
            "--service",
            "f2ai-udp",
            "--service-port",
            "80",
            "--health-path",
            "/health",
            "--sources",
            "Secret/env-secrets",
            "--expected-replicas",
            "1",
            "--check-only",
            "true",
            "--max-convergence-attempts",
            "1",
        ]

        with mock.patch.object(
            subject, "reconcile", return_value=expected_result
        ) as reconcile:
            self.assertEqual(0, subject.main(argv))

        self.assertEqual(1, reconcile.call_args.kwargs["expected_replicas"])


if __name__ == "__main__":
    unittest.main()
