from __future__ import annotations

# test_gate: layer=component runner=local_agent code_under_test=local_worktree target=local effect=read data_scope=local cost=none

import io
import json
import re
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "gke-env-secrets-preflight.yml"


class GkeEnvSecretsPreflightTest(unittest.TestCase):
    def workflow_text(self) -> str:
        return WORKFLOW.read_text(encoding="utf-8")

    def namespace_validation(self) -> str:
        text = self.workflow_text()
        self.assertIn("# NAMESPACE_VALIDATION_START", text)
        self.assertIn("# NAMESPACE_VALIDATION_END", text)
        return text.split("# NAMESPACE_VALIDATION_START", 1)[1].split(
            "# NAMESPACE_VALIDATION_END", 1
        )[0]

    def namespace_is_valid(self, namespace: str) -> bool:
        validation = self.namespace_validation()
        match = re.search(
            r'\[\[ ! "\$\{NAMESPACE\}" =~ (?P<pattern>\^[^\n]+\$) \]\]',
            validation,
        )
        self.assertIsNotNone(match, "namespace regex must remain extractable")
        return (
            1 <= len(namespace) <= 63
            and re.fullmatch(match.group("pattern"), namespace) is not None
        )

    def embedded_secret_parser(self) -> str:
        text = self.workflow_text()
        self.assertIn("# SECRET_JSON_PARSER_START", text)
        self.assertIn("# SECRET_JSON_PARSER_END", text)
        block = text.split("# SECRET_JSON_PARSER_START", 1)[1].split(
            "# SECRET_JSON_PARSER_END", 1
        )[0]
        match = re.search(
            r"(?ms)python3 -c '\n(?P<body>.*?)^\s*' \"\$\{key\}\"",
            block,
        )
        self.assertIsNotNone(match, "embedded JSON parser must remain executable")
        return textwrap.dedent(match.group("body"))

    def run_embedded_secret_parser(self, key: str, document: object) -> tuple[int, str]:
        source = self.embedded_secret_parser()
        previous_argv = sys.argv
        previous_stdin = sys.stdin
        previous_stdout = sys.stdout
        output = io.StringIO()
        try:
            sys.argv = ["embedded-secret-parser", key]
            sys.stdin = io.StringIO(json.dumps(document))
            sys.stdout = output
            try:
                exec(compile(source, "<embedded-secret-parser>", "exec"), {})
            except SystemExit as error:
                status = error.code if isinstance(error.code, int) else 1
            else:
                status = 0
        finally:
            sys.argv = previous_argv
            sys.stdin = previous_stdin
            sys.stdout = previous_stdout
        return status, output.getvalue()

    def test_reusable_workflow_uses_jsonpath_fail_closed_without_printing_secret_bytes(
        self,
    ) -> None:
        text = self.workflow_text()
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

    def test_required_secret_lookup_uses_validated_key_and_json_dictionary_index(self) -> None:
        text = self.workflow_text()
        parser = self.embedded_secret_parser()
        self.assertNotIn("jsonpath_escape", text)
        self.assertNotIn('jsonpath="{.data.${escaped}}"', text)
        self.assertIn("kubectl", text)
        self.assertIn("-o json", text)
        self.assertIn("json.load(sys.stdin)", parser)
        self.assertIn("data.get(key)", parser)
        self.assertIn("1 <= len(key) <= 253", parser)
        self.assertIn("[A-Za-z0-9._-]{1,253}", parser)

    def test_legal_kubernetes_secret_keys_are_exact_dictionary_lookups(self) -> None:
        encoded = "c3ludGhldGljLXZhbHVl"
        keys = (
            "service-account.json",
            ".dockerconfigjson",
            "SHOPIFY_NONCE_SECRET",
            "a_b-c.d",
            "a" * 253,
        )
        for key in keys:
            status, output = self.run_embedded_secret_parser(
                key,
                {"data": {key: encoded, "other": "must-not-be-selected"}},
            )
            self.assertEqual(0, status, key[:32])
            self.assertEqual(encoded, output, key[:32])

    def test_malicious_or_oversized_keys_fail_before_dictionary_lookup(self) -> None:
        sentinel = "SECRET_VALUE_MUST_NOT_BE_PRINTED"
        keys = (
            "",
            'key}{\"injected\":\"path',
            "key[0]",
            "key/child",
            "$(id)",
            "line\nbreak",
            "a" * 254,
        )
        for key in keys:
            status, output = self.run_embedded_secret_parser(
                key,
                {"data": {key: sentinel, "safe": sentinel}},
            )
            self.assertNotEqual(0, status, repr(key[:32]))
            self.assertEqual("", output, repr(key[:32]))
            self.assertNotIn(sentinel, output, repr(key[:32]))

    def test_missing_or_empty_secret_values_fail_closed_without_output(self) -> None:
        cases = (
            {},
            {"data": {}},
            {"data": {"required.key": ""}},
            {"data": {"required.key": None}},
            {"data": "not-a-dictionary"},
        )
        for document in cases:
            status, output = self.run_embedded_secret_parser(
                "required.key", document
            )
            self.assertNotEqual(0, status, repr(document))
            self.assertEqual("", output, repr(document))

    def test_namespace_is_validated_before_all_equals_form_kubectl_calls(self) -> None:
        text = self.workflow_text()
        validation = self.namespace_validation()
        kubectl_arguments = re.findall(r"\bkubectl (?P<arguments>[^\n]+)", text)
        self.assertGreaterEqual(len(kubectl_arguments), 2)
        self.assertNotIn("kubectl -n ", text)
        self.assertNotIn('kubectl --namespace "${NAMESPACE}"', text)
        for arguments in kubectl_arguments:
            self.assertTrue(
                arguments.startswith('--namespace="${NAMESPACE}" '), arguments
            )
        self.assertIn('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', text)
        self.assertIn('[ "${#NAMESPACE}" -lt 1 ]', validation)
        self.assertIn('[ "${#NAMESPACE}" -gt 63 ]', text)
        self.assertIn("exit 1", validation)
        self.assertLess(
            text.index("# NAMESPACE_VALIDATION_END"), text.index("kubectl ")
        )

    def test_invalid_namespaces_fail_before_kubectl_is_invoked(self) -> None:
        invalid_namespaces = (
            "--v=9",
            "--context=attacker",
            "-app",
            "line\nbreak",
            "a" * 64,
        )
        self.assertEqual(
            [],
            [namespace for namespace in invalid_namespaces if self.namespace_is_valid(namespace)],
        )

    def test_valid_namespaces_use_equals_form_and_complete(self) -> None:
        self.assertEqual(
            [True, True],
            [self.namespace_is_valid(namespace) for namespace in ("app", "a" * 63)],
        )


if __name__ == "__main__":
    unittest.main()
