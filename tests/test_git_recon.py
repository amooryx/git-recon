import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import git_recon


class GitReconTests(unittest.TestCase):
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
                b"",
                b".env\0.env.example\0dir/name\nwith-newline\0bad-\xff.pem\0src/app.py\0",
            ]
            calls = []

            def git_run(args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, outputs.pop(0), b"")

            with patch("git_recon.subprocess.run", side_effect=git_run):
                result = git_recon.run(ctx)

        self.assertEqual(result, 0)
        self.assertEqual(len(ctx.findings), 2)
        self.assertEqual(ctx.findings[0][1]["path"], ".env")
        self.assertNotIn("\n", ctx.findings[1][1]["path"])
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(args[0] == "git" for args in calls))
        self.assertEqual(calls[1][3:], ["ls-files", "--cached", "-z"])

    def test_rejects_remote_targets_without_running_git(self):
        ctx = self.make_context("https://example.invalid/repo")
        with patch("git_recon.subprocess.run") as git_run:
            result = git_recon.run(ctx)

        self.assertEqual(result, 2)
        self.assertIn("network targets are not contacted", ctx.errors[0])
        git_run.assert_not_called()

    def test_reports_malformed_repository_without_exposing_git_output(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            failure = subprocess.CalledProcessError(
                128, ["git"], stderr=b"malformed repository details"
            )
            with patch("git_recon.subprocess.run", side_effect=failure):
                result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("not a readable Git repository", ctx.errors[0])
        self.assertNotIn("malformed repository details", ctx.errors[0])

    def test_reports_malformed_index_without_exposing_git_output(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = self.make_context(directory)
            failure = subprocess.CalledProcessError(
                128, ["git"], stderr=b"malformed index details"
            )
            with patch(
                "git_recon.subprocess.run",
                side_effect=[
                    subprocess.CompletedProcess(["git"], 0, b"", b""),
                    failure,
                ],
            ):
                result = git_recon.run(ctx)

        self.assertEqual(result, 1)
        self.assertIn("could not read repository index", ctx.errors[0])
        self.assertNotIn("malformed index details", ctx.errors[0])


if __name__ == "__main__":
    unittest.main()
