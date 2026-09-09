from __future__ import annotations

# test_gate: layer=unit runner=local_agent code_under_test=local_worktree target=local effect=read data_scope=local cost=none

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import selectors
import subprocess
import traceback
import unittest
from unittest import mock

IMPLEMENTATION = Path(__file__).resolve().parents[1] / '.github/actions/gke-runtime-source-rollout/runtime_source_rollout.py'
SENTINEL = 'synthetic-private-token-never-log-this'
READY = b'Starting to serve on 127.0.0.1:43127\n'
REAL_SELECTOR = selectors.DefaultSelector


class PipeChild:
    """Controlled child lifecycle with real pipes; never executes a command."""
    def __init__(self, frames, kwargs):
        self.frames = list(frames)
        self.returncode = None
        self.writers = {}
        for name in ('stdout', 'stderr'):
            if kwargs.get(name) == subprocess.PIPE:
                read_fd, write_fd = os.pipe()
                stream = os.fdopen(read_fd, 'r' if kwargs.get('text') else 'rb', buffering=-1 if kwargs.get('text') else 0)
                setattr(self, name, stream)
                self.writers[name] = write_fd
            else:
                setattr(self, name, None)

    def advance(self):
        if not self.frames:
            return False
        frame = self.frames.pop(0)
        for stream, payload in frame.items():
            if stream == 'exit':
                self.returncode = payload
                self.close_writers()
            elif stream in self.writers:
                os.write(self.writers[stream], payload)
        return True

    def close_writers(self):
        for fd in self.writers.values():
            os.close(fd)
        self.writers.clear()

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15
        self.close_writers()

    def kill(self):
        self.returncode = -9
        self.close_writers()

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired('fixture-child', timeout)
        return self.returncode


class MetadataProxyContractTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('metadata_proxy_subject', IMPLEMENTATION)
        self.subject = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.subject)
        self.children = []
        self.calls = []
        self.now = 0.0
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(self.cleanup_children)
        self.stack.enter_context(contextlib.redirect_stdout(self.stdout))
        self.stack.enter_context(contextlib.redirect_stderr(self.stderr))
        self.stack.enter_context(mock.patch.object(self.subject.time, 'monotonic', lambda: self.now))
        self.stack.enter_context(mock.patch.object(self.subject.time, 'sleep', self.advance_time))
        self.stack.enter_context(mock.patch.object(self.subject.selectors, 'DefaultSelector', self.selector))

    def advance_time(self, seconds):
        self.now += seconds

    def selector(self):
        selector = REAL_SELECTOR()
        real_select = selector.select
        def select(timeout=None):
            child = self.children[-1]
            changed = child.advance()
            ready = real_select(0)
            self.now += 0.001 if changed or ready else timeout
            return ready
        selector.select = select
        return selector

    def cleanup_children(self):
        for child in self.children:
            child.close_writers()
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()

    def factory(self, attempts):
        def popen(argv, **kwargs):
            self.calls.append(argv)
            frames = attempts[min(len(self.calls) - 1, len(attempts) - 1)]
            if isinstance(frames, Exception):
                raise frames
            child = PipeChild(frames, kwargs)
            self.children.append(child)
            return child
        return popen

    def assert_clean(self):
        for child in self.children:
            self.assertIsNotNone(child.poll(), 'every attempt must be reaped')
            self.assertTrue(child.stdout.closed)
            if child.stderr is not None:
                self.assertTrue(child.stderr.closed)
            self.assertFalse(child.writers)

    def failure(self, attempts):
        with self.assertRaises(self.subject.ReconcileError) as caught:
            with self.subject._KubectlMetadataProxy(self.factory(attempts)):
                self.fail('invalid readiness must never enter the context')
        formatted = ''.join(traceback.format_exception(caught.exception))
        output = self.stdout.getvalue() + self.stderr.getvalue() + formatted
        self.assertNotIn(SENTINEL, output)
        self.assertNotIn('https://private.example', output)
        self.assert_clean()
        return str(caught.exception), output

    def test_valid_loopback_child_is_stopped_on_context_exit(self):
        with self.subject._KubectlMetadataProxy(self.factory([[{'stdout': READY}]])) as url:
            self.assertEqual('http://127.0.0.1:43127', url)
            self.assertIsNone(self.children[0].poll())
            self.assertEqual(['kubectl', 'proxy', '--address=127.0.0.1', '--port=0',
                              r'--accept-hosts=^127\.0\.0\.1$'], self.calls[0])
        self.assert_clean()

    def test_buffered_banner_and_readiness_in_one_write_do_not_timeout(self):
        with self.subject._KubectlMetadataProxy(self.factory([
            [{'stdout': SENTINEL.encode() + b'\nnotice\n' + READY}]
        ])) as url:
            self.assertEqual('http://127.0.0.1:43127', url)
        self.assertNotIn(SENTINEL, self.stdout.getvalue() + self.stderr.getvalue())
        self.assert_clean()

    def test_readiness_on_stderr_is_accepted_without_logging_the_stream(self):
        with self.subject._KubectlMetadataProxy(self.factory([
            [{'stderr': SENTINEL.encode() + b'\n' + READY}]
        ])) as url:
            self.assertEqual('http://127.0.0.1:43127', url)
        self.assertNotIn(SENTINEL, self.stdout.getvalue() + self.stderr.getvalue())
        self.assert_clean()

    def test_transient_exit_recovers_on_second_attempt_and_reports_safe_retry(self):
        failed = [{'stderr': b'address already in use ' + SENTINEL.encode()}, {'exit': 17}]
        with self.subject._KubectlMetadataProxy(self.factory([failed, [{'stdout': READY}]])):
            self.assertEqual(2, len(self.calls))
            self.assertEqual(17, self.children[0].returncode)
            self.assertTrue(self.children[0].stdout.closed)
        output = self.stderr.getvalue()
        for expected in ('attempt=1/3', 'reason=exited', 'exit_code=17', 'hint=address-in-use'):
            self.assertIn(expected, output)
        self.assertNotIn(SENTINEL, output)
        self.assert_clean()

    def test_all_exits_fail_closed_after_three_attempts_with_safe_plugin_hint(self):
        error = f'exec: executable gke-gcloud-auth-plugin failed {SENTINEL} https://private.example'.encode()
        message, output = self.failure([[{'stderr': error}, {'exit': 7}]])
        self.assertEqual(3, len(self.calls))
        for expected in ('attempt=3/3', 'reason=exited', 'exit_code=7'):
            self.assertIn(expected, message)
        self.assertIn('hint=credential-plugin', output)

    def test_spawn_error_does_not_expose_exception_chain(self):
        message, _ = self.failure([OSError(SENTINEL)])
        self.assertEqual(3, len(self.calls))
        self.assertIn('reason=spawn-error', message)

    def test_unterminated_output_cannot_block_the_startup_deadline(self):
        # Bytes are deliberately split. New nonblocking reads finish under a virtual
        # deadline; the old readline is guarded by a fixture read failure, not a hang.
        child_factory = self.factory([[{'stdout': SENTINEL.encode()}]])
        def guarded_factory(argv, **kwargs):
            child = child_factory(argv, **kwargs)
            if kwargs.get('text'):
                child.stdout = mock.Mock(wraps=child.stdout)
                child.stdout.readline.side_effect = AssertionError('blocking readline cannot enforce a deadline')
            return child
        with self.assertRaises(self.subject.ReconcileError) as caught:
            with self.subject._KubectlMetadataProxy(guarded_factory):
                self.fail('unterminated output must not enter context')
        self.assertEqual(3, len(self.calls))
        self.assertIn('reason=timeout', str(caught.exception))
        self.assertLessEqual(self.now, 183)
        self.assert_clean()

    def test_invalid_bind_addresses_and_ports_never_count_as_ready(self):
        attempts = [[{'stdout': value}] for value in (
            b'Starting to serve on 0.0.0.0:43127\n',
            b'Starting to serve on 127.0.0.1:0\n',
            b'Starting to serve on 127.0.0.1:65536\n')]
        message, _ = self.failure(attempts)
        self.assertEqual(3, len(self.calls))
        self.assertIn('reason=timeout', message)
        self.assertLessEqual(self.now, 183)

    def test_large_stderr_does_not_deadlock_or_leak_before_valid_stdout(self):
        frames = [{'stderr': SENTINEL.encode() * 20} for _ in range(500)]
        frames.append({'stdout': READY})
        with self.subject._KubectlMetadataProxy(self.factory([frames])) as url:
            self.assertEqual('http://127.0.0.1:43127', url)
        self.assertEqual('', self.stdout.getvalue() + self.stderr.getvalue())
        self.assert_clean()

    def test_context_failure_still_reaps_the_proxy(self):
        with self.assertRaisesRegex(ValueError, 'fixture failure'):
            with self.subject._KubectlMetadataProxy(self.factory([[{'stdout': READY}]])):
                raise ValueError('fixture failure')
        self.assert_clean()

    def test_default_startup_policy_is_bounded_and_allows_slow_auth_initialization(self):
        self.assertEqual(60, self.subject.PROXY_START_TIMEOUT_SECONDS)
        self.assertEqual(3, self.subject.PROXY_START_MAX_ATTEMPTS)
        self.assertEqual(1, self.subject.PROXY_RETRY_DELAY_SECONDS)


if __name__ == '__main__':
    unittest.main()
