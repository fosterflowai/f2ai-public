from __future__ import annotations

# test_gate: layer=component runner=local_agent code_under_test=local_worktree target=local effect=read data_scope=local cost=none

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github" / "workflows" / "gcp-build-and-deploy-jdk17-multi-module.yml",
    ROOT / ".github" / "workflows" / "gcp-build-and-deploy-jdk17-single-module.yml",
)


class MavenGithubPackagesAuthTest(unittest.TestCase):
    def test_maven_step_injects_actions_github_token(self) -> None:
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("packages: read", text, path.name)
            self.assertIn("GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}", text, path.name)
            # The repo-scoped GITHUB_TOKEN cannot read another repo's packages
            # (app-framework's f2ai-boms), so the org PAT wins when supplied
            # and the Actions token remains the fallback.
            self.assertIn(
                "GITHUB_PACKAGES_TOKEN: "
                "${{ secrets.PACKAGES_READ_PAT || secrets.GITHUB_TOKEN }}",
                text,
                path.name,
            )
            self.assertIn(
                "GITHUB_PACKAGES_USERNAME: ${{ github.actor }}",
                text,
                path.name,
            )
            self.assertIn("Run mvn clean install", text, path.name)

    def test_reusable_workflows_declare_the_optional_packages_pat(self) -> None:
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("PACKAGES_READ_PAT:", text, path.name)


if __name__ == "__main__":
    unittest.main()
