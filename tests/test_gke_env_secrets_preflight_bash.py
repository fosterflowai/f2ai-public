from __future__ import annotations

# test_gate: layer=component runner=local_agent code_under_test=local_worktree target=local effect=write data_scope=local cost=none

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "gke-env-secrets-preflight.yml"


class GkeEnvSecretsPreflightBashTest(unittest.TestCase):
    def workflow_run_script(self) -> str:
        text = WORKFLOW.read_text(encoding="utf-8")
        marker = "        run: |\n"
        self.assertIn(marker, text)
        return textwrap.dedent(text.split(marker, 1)[1])

    def run_workflow(
        self,
        namespace: str,
        *,
        required_keys: str = "required.key",
        required_named_keys: str = "",
        named_secret_json: str = '{"data":{"STRIPE_WEBHOOK_SECRET":"named-sentinel"}}',
        workload_identity_email: str = "preflight@example.invalid",
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            invocation_log = temp_root / "kubectl-argv.log"
            kubectl = temp_root / "kubectl"
            kubectl.write_text(
                "#!/bin/sh\n"
                "for argument in \"$@\"; do\n"
                "  printf '%s\\n' \"${argument}\" >> \"${KUBECTL_ARGV_LOG}\"\n"
                "done\n"
                "printf '%s\\n' '__CALL_END__' >> \"${KUBECTL_ARGV_LOG}\"\n"
                "if [ \"${3:-}\" = 'serviceaccount' ]; then\n"
                "  printf '%s' \"${FAKE_WI_EMAIL}\"\n"
                "elif [ \"${4:-}\" = 'f2ai-account-stripe' ]; then\n"
                "  printf '%s' \"${FAKE_NAMED_SECRET_JSON}\"\n"
                "else\n"
                "  printf '%s' "
                "'{\"data\":{\"required.key\":\"cHJlc2VudA==\"}}'\n"
                "fi\n",
                encoding="utf-8",
            )
            kubectl.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{temp_root}{os.pathsep}{environment['PATH']}",
                    "KUBECTL_ARGV_LOG": str(invocation_log),
                    "NAMESPACE": namespace,
                    "REQUIRED_KEYS": required_keys,
                    "REQUIRED_NAMED_KEYS": required_named_keys,
                    "SHOPIFY_NONCE_MIN_BYTES": "0",
                    "GCP_SA_KEYS": "",
                    "WI_EMAIL": workload_identity_email,
                    "FAKE_WI_EMAIL": workload_identity_email,
                    "FAKE_NAMED_SECRET_JSON": named_secret_json,
                }
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", self.workflow_run_script()],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            lines = (
                invocation_log.read_text(encoding="utf-8").splitlines()
                if invocation_log.exists()
                else []
            )
        calls: list[list[str]] = []
        current: list[str] = []
        for line in lines:
            if line == "__CALL_END__":
                calls.append(current)
                current = []
            else:
                current.append(line)
        self.assertEqual([], current, "fake kubectl argv log must end cleanly")
        return completed, calls

    def test_invalid_namespaces_fail_before_kubectl_is_invoked(self) -> None:
        invalid_namespaces = (
            "--v=9",
            "--context=attacker",
            "-app",
            "line\nbreak",
            "a" * 64,
        )
        failures = []
        for namespace in invalid_namespaces:
            completed, calls = self.run_workflow(namespace)
            if completed.returncode == 0 or calls:
                failures.append(
                    {
                        "namespace": repr(namespace),
                        "returncode": completed.returncode,
                        "kubectl_call_count": len(calls),
                    }
                )
        self.assertEqual([], failures)

    def test_valid_namespaces_use_equals_form_and_complete(self) -> None:
        failures = []
        for namespace in ("app", "a" * 63):
            completed, calls = self.run_workflow(namespace)
            expected_calls = [
                [
                    f"--namespace={namespace}",
                    "get",
                    "secret",
                    "env-secrets",
                    "-o",
                    "json",
                ],
                [
                    f"--namespace={namespace}",
                    "get",
                    "serviceaccount",
                    "gcp-impersonator",
                    "-o",
                    "jsonpath={.metadata.annotations.iam\\.gke\\.io/gcp-service-account}",
                ],
            ]
            if completed.returncode != 0 or calls != expected_calls:
                failures.append(
                    {
                        "namespace_length": len(namespace),
                        "returncode": completed.returncode,
                        "kubectl_calls": calls,
                        "stderr": completed.stderr,
                    }
                )
        self.assertEqual([], failures)

    def test_named_secret_reference_uses_exact_argv_without_emitting_value(self) -> None:
        sentinel = "NAMED_SECRET_VALUE_MUST_NOT_BE_EMITTED"
        completed, calls = self.run_workflow(
            "app",
            required_keys="",
            required_named_keys="f2ai-account-stripe/STRIPE_WEBHOOK_SECRET",
            named_secret_json=(
                '{"data":{"STRIPE_WEBHOOK_SECRET":"' + sentinel + '"}}'
            ),
            workload_identity_email="",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stdout)
        self.assertNotIn(sentinel, completed.stderr)
        self.assertEqual(
            [
                [
                    "--namespace=app",
                    "get",
                    "secret",
                    "f2ai-account-stripe",
                    "-o",
                    "json",
                ]
            ],
            calls,
        )

    def test_invalid_named_secret_reference_fails_before_kubectl(self) -> None:
        for reference in ("-option/KEY", "valid/$(id)", "missing-slash"):
            completed, calls = self.run_workflow(
                "app",
                required_keys="",
                required_named_keys=reference,
                workload_identity_email="",
            )
            self.assertNotEqual(0, completed.returncode, reference)
            self.assertEqual([], calls, reference)

    def test_missing_named_key_fails_without_emitting_other_values(self) -> None:
        sentinel = "UNRELATED_SECRET_VALUE_MUST_NOT_BE_EMITTED"
        completed, calls = self.run_workflow(
            "app",
            required_keys="",
            required_named_keys="f2ai-account-stripe/STRIPE_WEBHOOK_SECRET",
            named_secret_json='{"data":{"OTHER":"' + sentinel + '"}}',
            workload_identity_email="",
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertNotIn(sentinel, completed.stderr)
        self.assertEqual(1, len(calls))


if __name__ == "__main__":
    unittest.main()
