import os
import queue
import subprocess
import threading
import time
from pathlib import Path, PurePosixPath
from pathlib import PureWindowsPath

import rclib


_REPOSITORY_CHECK_TIMEOUT = 10
_SCAN_TIMEOUT = 30
_MAX_INDEX_BYTES = 16 * 1024 * 1024
_MAX_TRACKED_PATHS = 100_000
_READ_CHUNK_SIZE = 8192
_SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")
_PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa"}
_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")


class _ScanError(Exception):
    pass


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


def _is_remote_target(target):
    windows_path = PureWindowsPath(target)
    if "://" in target or windows_path.drive.startswith("\\\\"):
        return True
    if os.name != "nt":
        return False

    drive = windows_path.drive or PureWindowsPath(os.getcwd()).drive
    if not drive:
        return False
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        return get_drive_type(drive + "\\") == 4
    except (AttributeError, OSError, ValueError) as exc:
        raise RuntimeError("could not verify that the target drive is local") from exc


def _read_tracked_paths(repo):
    try:
        process = subprocess.Popen(
            ["git", "-C", str(repo), "ls-files", "--cached", "-z"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        raise _ScanError("could not start Git to read the repository index") from exc

    chunks = queue.Queue(maxsize=8)
    cancelled = threading.Event()

    def publish(item):
        while not cancelled.is_set():
            try:
                chunks.put(item, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def read_output():
        try:
            while True:
                chunk = process.stdout.read(_READ_CHUNK_SIZE)
                if not chunk:
                    break
                if not publish(chunk):
                    return
        except (OSError, ValueError) as exc:
            publish(exc)
        finally:
            publish(None)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    deadline = time.monotonic() + _SCAN_TIMEOUT
    buffer = bytearray()
    total_bytes = 0
    path_count = 0

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _ScanError(f"repository index scan exceeded {_SCAN_TIMEOUT} seconds")
            try:
                item = chunks.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if item is None:
                break
            if isinstance(item, (OSError, ValueError)):
                raise _ScanError("could not read repository index output") from item

            total_bytes += len(item)
            if total_bytes > _MAX_INDEX_BYTES:
                raise _ScanError(
                    f"repository index exceeds the {_MAX_INDEX_BYTES}-byte scan limit"
                )
            buffer.extend(item)
            paths = buffer.split(b"\0")
            buffer = bytearray(paths.pop())
            for raw_path in paths:
                if not raw_path:
                    continue
                if time.monotonic() >= deadline:
                    raise _ScanError(
                        f"repository index scan exceeded {_SCAN_TIMEOUT} seconds"
                    )
                path_count += 1
                if path_count > _MAX_TRACKED_PATHS:
                    raise _ScanError(
                        f"repository exceeds the {_MAX_TRACKED_PATHS}-tracked-path scan limit"
                    )
                yield _decode_git_path(bytes(raw_path))

        if buffer:
            raise _ScanError("Git returned an incomplete repository index path")
        try:
            return_code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise _ScanError(
                f"repository index scan exceeded {_SCAN_TIMEOUT} seconds"
            ) from exc
        if return_code:
            raise _ScanError("could not read repository index")
    finally:
        cancelled.set()
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout:
            process.stdout.close()
        reader.join(timeout=1)


def run(ctx):
    target = ctx.target
    try:
        remote_target = _is_remote_target(target)
    except RuntimeError as exc:
        ctx.err(str(exc))
        return 1
    if remote_target:
        ctx.err("only local repository paths are supported; network targets are not contacted")
        return 2

    try:
        repo = Path(target).expanduser()
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_REPOSITORY_CHECK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        ctx.err(f"repository validation exceeded {_REPOSITORY_CHECK_TIMEOUT} seconds")
        return 1
    except FileNotFoundError:
        ctx.err("Git executable was not found; install Git and retry")
        return 1
    except (OSError, RuntimeError, ValueError):
        ctx.err(f"could not access local repository: {_display_path(target)}")
        return 1
    except subprocess.CalledProcessError:
        ctx.err(f"not a readable local Git repository: {_display_path(target)}")
        return 1

    try:
        findings = []
        for path in _read_tracked_paths(repo):
            finding = _tracked_file_finding(path)
            if finding:
                severity, title = finding
                findings.append((title, severity, _display_path(path)))
    except _ScanError as exc:
        ctx.err(str(exc))
        return 1
    except FileNotFoundError:
        ctx.err("Git executable was not found; install Git and retry")
        return 1
    except (OSError, RuntimeError, ValueError) as exc:
        ctx.err(f"could not read repository index: {type(exc).__name__}")
        return 1
    for title, severity, display_path in findings:
        ctx.finding(title, severity, detail=display_path, path=display_path)
    return 0


if __name__ == "__main__":
    rclib.main(
        "git-recon",
        "Find likely secret-bearing filenames in a local Git repository",
        run,
    )
