from __future__ import annotations

# test_gate: layer=component runner=local_agent code_under_test=local_worktree target=local effect=read data_scope=local cost=none

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
BUILD_WORKFLOWS = (
    WORKFLOW_ROOT / "gcp-build-and-deploy-jdk17-multi-module.yml",
    WORKFLOW_ROOT / "gcp-build-and-deploy-jdk17-single-module.yml",
)
PREFLIGHT = WORKFLOW_ROOT / "gke-env-secrets-preflight.yml"
ACTION_REF = re.compile(r"(?m)^\s*-?\s*uses:\s*[^\s@]+@(?P<ref>[^\s#]+)")


class ReusableReleaseSupplyChainContractTest(unittest.TestCase):
    def workflow_texts(self) -> list[tuple[Path, str]]:
        return [(path, path.read_text(encoding="utf-8")) for path in BUILD_WORKFLOWS]

    def test_every_action_reference_is_an_exact_commit(self) -> None:
        for path in (*BUILD_WORKFLOWS, PREFLIGHT):
            text = path.read_text(encoding="utf-8")
            refs = ACTION_REF.findall(text)
            self.assertGreater(len(refs), 0, path.name)
            for ref in refs:
                self.assertRegex(ref, r"^[0-9a-f]{40}$", (path.name, ref))

    def test_maven_build_cannot_accept_free_form_arguments_or_skip_tests(self) -> None:
        for path, text in self.workflow_texts():
            self.assertIn("LEGACY_MVN_ARGS", text, path.name)
            self.assertIn("free-form MVN_ARGS is not supported", text, path.name)
            self.assertNotIn("-DskipTests", text, path.name)
            self.assertNotIn("-Dmaven.test.skip", text, path.name)
            self.assertNotRegex(
                text,
                r"(?m)^\s*run:.*\$\{\{\s*inputs\.MVN_ARGS\s*\}\}",
                path.name,
            )
            self.assertIn(
                "mvn --batch-mode -U -s mvn-settings.xml clean install --no-transfer-progress",
                text,
                path.name,
            )

    def test_build_publishes_one_labeled_attested_digest_without_latest(self) -> None:
        for path, text in self.workflow_texts():
            self.assertNotIn(":latest", text, path.name)
            self.assertIn("id: build-and-push", text, path.name)
            self.assertIn("provenance: mode=max", text, path.name)
            self.assertIn("sbom: true", text, path.name)
            self.assertIn("org.opencontainers.image.revision", text, path.name)
            self.assertIn("org.opencontainers.image.source", text, path.name)
            self.assertIn("org.opencontainers.image.version", text, path.name)
            self.assertIn("steps.build-and-push.outputs.digest", text, path.name)
            self.assertIn("image_digest:", text, path.name)
            self.assertIn("image_ref:", text, path.name)
            self.assertIn('image_ref = f"{repository}@{digest}"', text, path.name)

    def test_trivy_is_exact_versioned_and_fails_on_high_or_critical(self) -> None:
        expected_action = (
            "aquasecurity/trivy-action@"
            "ed142fd0673e97e23eac54620cfb913e5ce36c25"
        )
        for path, text in self.workflow_texts():
            self.assertIn(expected_action, text, path.name)
            self.assertIn("version: v0.70.0", text, path.name)
            self.assertIn("image-ref: ${{ steps.immutable.outputs.image_ref }}", text, path.name)
            self.assertIn("severity: HIGH,CRITICAL", text, path.name)
            self.assertIn("exit-code: '1'", text, path.name)
            self.assertIn("ignore-unfixed: false", text, path.name)

    def test_deploy_uses_digest_and_verifies_deployment_and_pod_readback(self) -> None:
        required_fragments = (
            "DEPLOYMENT:",
            "CONTAINER:",
            "ROLLOUT_TIMEOUT_SECONDS:",
            "images: ${{ needs.build-push-gcr.outputs.image_ref }}",
            "kubectl",
            "rollout",
            "observedGeneration",
            "updatedReplicas",
            "readyReplicas",
            "availableReplicas",
            "containerStatuses",
            "imageID",
            "expected immutable image",
            "zero replicas",
        )
        for path, text in self.workflow_texts():
            for fragment in required_fragments:
                self.assertIn(fragment, text, (path.name, fragment))
            self.assertIn("unique Deployment", text, path.name)
            self.assertIn("unique matching container", text, path.name)

    def test_jobs_use_bounded_permissions_and_non_persisted_checkouts(self) -> None:
        for path, text in self.workflow_texts():
            self.assertGreaterEqual(text.count("contents: read"), 2, path.name)
            self.assertEqual(1, text.count("packages: read"), path.name)
            self.assertGreaterEqual(text.count("persist-credentials: false"), 2, path.name)
            self.assertNotIn("contents: write", text, path.name)
            self.assertNotIn("packages: write", text, path.name)
            self.assertNotIn("id-token: write", text, path.name)
        self.assertIn("permissions: {}", PREFLIGHT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
