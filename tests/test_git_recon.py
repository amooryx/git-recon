import io
import os
import subprocess
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import git_recon


class GitReconTests(unittest.TestCase):
    class FakeProcess:
        def __init__(self, output=b"", returncode=0, stdout=None):
            self.stdout = stdout if stdout is not None else io.BytesIO(output)
            self.returncode = returncode
            self.killed = False

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9
            if hasattr(self.stdout, "release"):
                self.stdout.release.set()

    class BlockingPipe:
        def __init__(self):
            self.release = threading.Event()

        def read(self, size):
            self.release.wait()
            return b""

        def close(self):
            self.release.set()

    def make_context(self, target):
        ctx = SimpleNamespace(target=target, findings=[], errors=[])
        ctx.finding = lambda *args, **kwargs: ctx.findings.append((args, kwargs))
        ctx.err = lambda message: ctx.errors.append(message)
        return ctx

    def test_classifies_likely_secret_paths_and_examples(self):
        self.assertEqual(
            git_recon._tracked_file_finding("deploy/.env.production"),
            ("high", "Potential environment secrets are tracked"),
        )
        self.assertEqual(
            git_recon._tracked_file_finding("keys/id_ed25519"),
            ("medium", "Potential private key or keystore is tracked"),
        )
        self.assertIsNone(git_recon._tracked_file_finding(".env.example"))
        self.assertIsNone(git_recon._tracked_file_finding("src/app.py"))

    def test_scans_nul_delimited_tracked_names_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            outputs = [
                b".env\0.env.example\0dir/name\nwith-newline\0bad-\xff.pem\0src/app.py\0",
            ]
            process = self.FakeProcess(outputs[0])
            with patch(
                "git_recon.subprocess.run",
                return_value=subprocess.CompletedProcess(["git"], 0),
            ) as git_run, patch(
                "git_recon.subprocess.Popen", return_value=process
            ) as git_popen, patch(
                "git_recon._READ_CHUNK_SIZE", 7
            ):
                result = git_recon.run(ctx)

        self.assertEqual(result, 0)
        self.assertEqual(len(ctx.findings), 2)
        self.assertEqual(ctx.findings[0][1]["path"], ".env")
        self.assertNotIn("\n", ctx.findings[1][1]["path"])
        git_run.assert_called_once()
        args, kwargs = git_popen.call_args
        self.assertEqual(args[0][3:], ["ls-files", "--cached", "-z"])
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)

    def test_rejects_remote_targets_without_running_git(self):
        for target in (
            "https://example.invalid/repo",
            r"\\server\share\repo",
            "//server/share/repo",
        ):
            with self.subTest(target=target):
                ctx = self.make_context(target)
                with patch("git_recon.subprocess.run") as git_run, patch(
                    "git_recon.subprocess.Popen"
                ) as git_popen:
                    result = git_recon.run(ctx)

                self.assertEqual(result, 2)
                self.assertIn("network targets are not contacted", ctx.errors[0])
                git_run.assert_not_called()
                git_popen.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows drive-type API")
    def test_rejects_mapped_network_drives(self):
        ctx = self.make_context("Z:\\repo")
        with patch("ctypes.WinDLL") as win_dll, patch(
            "git_recon.subprocess.run"
        ) as git_run:
            win_dll.return_value.GetDriveTypeW.return_value = 4
            result = git_recon.run(ctx)

        self.assertEqual(result, 2)
        self.assertIn("network targets are not contacted", ctx.errors[0])
        git_run.assert_not_called()

    def test_stops_when_index_output_exceeds_configured_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            process = self.FakeProcess(b".env\0.env.local\0", returncode=None)
            with patch(
                "git_recon.subprocess.run",
                return_value=subprocess.CompletedProcess(["git"], 0),
            ), patch("git_recon.subprocess.Popen", return_value=process), patch(
                "git_recon._MAX_TRACKED_PATHS", 1
            ):
                result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("tracked-path scan limit", ctx.errors[0])
        self.assertEqual(ctx.findings, [])
        self.assertTrue(process.killed)

    def test_stops_when_index_output_exceeds_byte_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            process = self.FakeProcess(b".env\0")
            with patch(
                "git_recon.subprocess.run",
                return_value=subprocess.CompletedProcess(["git"], 0),
            ), patch("git_recon.subprocess.Popen", return_value=process), patch(
                "git_recon._MAX_INDEX_BYTES", 2
            ):
                result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("byte scan limit", ctx.errors[0])
        self.assertEqual(ctx.findings, [])

    def test_times_out_when_index_reader_stalls(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            process = self.FakeProcess(
                returncode=None, stdout=self.BlockingPipe()
            )
            with patch(
                "git_recon.subprocess.run",
                return_value=subprocess.CompletedProcess(["git"], 0),
            ), patch("git_recon.subprocess.Popen", return_value=process), patch(
                "git_recon._SCAN_TIMEOUT", 0.02
            ):
                result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("exceeded 0.02 seconds", ctx.errors[0])
        self.assertEqual(ctx.findings, [])
        self.assertTrue(process.killed)

    def test_reports_malformed_repository_without_exposing_git_output(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            failure = subprocess.CalledProcessError(
                128, ["git"], stderr=b"malformed repository details"
            )
            with patch("git_recon.subprocess.run", side_effect=failure):
                result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("not a readable local Git repository", ctx.errors[0])
        self.assertNotIn("malformed repository details", ctx.errors[0])

    def test_times_out_during_repository_validation(self):
        ctx = self.make_context("C:\\slow-repository")
        with patch(
            "git_recon.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["git"], 10),
        ) as git_run:
            result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("repository validation exceeded", ctx.errors[0])
        git_run.assert_called_once()

    def test_reports_malformed_index_without_exposing_git_output(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            with patch(
                "git_recon.subprocess.run",
                return_value=subprocess.CompletedProcess(["git"], 0),
            ), patch(
                "git_recon.subprocess.Popen",
                return_value=self.FakeProcess(returncode=128),
            ):
                result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("could not read repository index", ctx.errors[0])


if __name__ == "__main__":
    unittest.main()
