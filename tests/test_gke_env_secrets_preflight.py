from __future__ import annotations

# test_gate: layer=component runner=local_agent code_under_test=local_worktree target=local effect=read data_scope=local cost=none

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "gke-env-secrets-preflight.yml"


class GkeEnvSecretsPreflightTest(unittest.TestCase):
    def test_reusable_workflow_uses_jsonpath_fail_closed_without_printing_secret_bytes(
        self,
    ) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_call", text)
        self.assertIn("required_keys", text)
        self.assertIn("jsonpath", text)
        self.assertNotIn("go-template", text)
        self.assertIn("google-github-actions/auth@7c6bc770", text)
        self.assertIn("google-github-actions/get-gke-credentials@3da1e46a", text)
        self.assertIn("Required secret configuration is missing", text)
        self.assertNotRegex(text, r"echo\s+[\"']?\$\{?encoded")
        self.assertNotRegex(text, r"echo\s+[\"'].*\.data")
        self.assertNotIn("echo ${encoded", text)
        self.assertNotIn("echo \"$encoded", text)


if __name__ == "__main__":
    unittest.main()
