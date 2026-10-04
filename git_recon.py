import os
import subprocess
from pathlib import Path, PurePosixPath

import rclib


_SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")
_PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa"}
_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")


def _tracked_file_finding(path):
    name = PurePosixPath(path).name.casefold()
    if name == ".env" or (
        name.startswith(".env.")
        and not name.endswith(_SAFE_ENV_SUFFIXES)
    ):
        return "high", "Potential environment secrets are tracked"
    if name in _PRIVATE_KEY_NAMES or name.endswith(_KEY_SUFFIXES):
        return "medium", "Potential private key or keystore is tracked"
    return None


def _display_path(path):
    return path.encode("unicode_escape").decode("ascii")


def _decode_git_path(raw_path):
    try:
        return os.fsdecode(raw_path)
    except UnicodeDecodeError:
        return raw_path.decode("utf-8", errors="backslashreplace")


def run(ctx):
    target = ctx.target
    if "://" in target:
        ctx.err("only local repository paths are supported; network targets are not contacted")
        return 2

    repo = Path(target).expanduser()
    try:
        if not repo.is_dir():
            ctx.err(f"not a local directory: {_display_path(str(repo))}")
            return 2

        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        ctx.err("Git executable was not found; install Git and retry")
        return 1
    except (OSError, RuntimeError, ValueError):
        ctx.err(f"could not access local repository: {_display_path(str(repo))}")
        return 1
    except subprocess.CalledProcessError:
        ctx.err(f"not a readable Git repository: {_display_path(str(repo))}")
        return 1

    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "--cached", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        ctx.err("Git executable was not found; install Git and retry")
        return 1
    except (OSError, RuntimeError, ValueError):
        ctx.err(f"could not read repository index: {_display_path(str(repo))}")
        return 1
    except subprocess.CalledProcessError:
        ctx.err(f"could not read repository index: {_display_path(str(repo))}")
        return 1

    tracked_paths = result.stdout.split(b"\0")
    for raw_path in tracked_paths:
        if not raw_path:
            continue
        path = _decode_git_path(raw_path)
        finding = _tracked_file_finding(path)
        if finding:
            severity, title = finding
            display_path = _display_path(path)
            ctx.finding(title, severity, detail=display_path, path=display_path)
    return 0


if __name__ == "__main__":
    rclib.main(
        "git-recon",
        "Find likely secret-bearing filenames in a local Git repository",
        run,
    )
