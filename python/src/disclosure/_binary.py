"""Locate (and, if needed, download) the platform-native ``disclosure`` binary.

Proof-of-concept strategy: fetch the prebuilt release archive from GitHub on
first use, verify it against the release ``checksums.txt``, and cache the
extracted binary. A production version would instead bundle the binary inside
platform-specific wheels (Simon Willison, "Distributing Go binaries"), which
avoids any download at runtime.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path

# The upstream release this PoC wraps. Overridable for local testing.
DISCLOSURE_VERSION = os.environ.get("DISCLOSURE_VERSION", "1.0.0")

_RELEASE_URL = (
    "https://github.com/chaoss/disclosure/releases/download/v{version}/{asset}"
)


class BinaryResolutionError(RuntimeError):
    """Raised when the disclosure binary cannot be located or fetched."""


def _target() -> tuple[str, str]:
    """Return (goos, goarch) matching GoReleaser's asset naming."""
    system = platform.system().lower()
    goos = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(system)
    if goos is None:
        raise BinaryResolutionError(f"unsupported OS: {platform.system()!r}")

    machine = platform.machine().lower()
    goarch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)
    if goarch is None:
        raise BinaryResolutionError(f"unsupported architecture: {platform.machine()!r}")

    return goos, goarch


def _cache_dir() -> Path:
    override = os.environ.get("DISCLOSURE_CACHE_DIR")
    if override:
        base = Path(override)
    elif platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "disclosure-cli" / DISCLOSURE_VERSION


def _binary_name(goos: str) -> str:
    return "disclosure.exe" if goos == "windows" else "disclosure"


def _download(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (trusted GitHub host)
            return resp.read()
    except Exception as exc:
        raise BinaryResolutionError(f"failed to download {url}: {exc}") from exc


def _expected_sha256(goos: str, goarch: str) -> str:
    """Look up the archive's checksum from the release ``checksums.txt``.

    Fails closed: if ``checksums.txt`` cannot be downloaded (``_download``
    raises) or does not list this archive, raise rather than let an unverified
    binary be cached and executed.
    """
    url = _RELEASE_URL.format(
        version=DISCLOSURE_VERSION, asset="checksums.txt"
    )
    archive = f"disclosure_{DISCLOSURE_VERSION}_{goos}_{goarch}.tar.gz"
    try:
        text = _download(url).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BinaryResolutionError("checksums.txt is not valid UTF-8") from exc
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == archive:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
                raise BinaryResolutionError(f"invalid SHA-256 checksum for {archive}")
            return parts[0].lower()
    raise BinaryResolutionError(
        f"no checksum listed for {archive} in checksums.txt; "
        f"refusing to run an unverified binary"
    )


def _fetch(goos: str, goarch: str, dest: Path) -> None:
    archive = f"disclosure_{DISCLOSURE_VERSION}_{goos}_{goarch}.tar.gz"
    url = _RELEASE_URL.format(version=DISCLOSURE_VERSION, asset=archive)
    blob = _download(url)

    # Verify before extracting/caching. _expected_sha256 fails closed, so a
    # missing or unreachable checksums.txt aborts the fetch rather than
    # silently running an unverified download.
    expected = _expected_sha256(goos, goarch)
    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise BinaryResolutionError(
            f"checksum mismatch for {archive}: expected {expected}, got {actual}"
        )

    name = _binary_name(goos)
    temporary = None
    try:
        with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
            member = tf.getmember(name)
            if not member.isfile() or member.size == 0:
                raise BinaryResolutionError(f"{name} is not a non-empty regular file in {archive}")
            with tf.extractfile(member) as extracted:
                dest.parent.mkdir(parents=True, exist_ok=True)
                # Stage in the destination directory so replacement stays on
                # one filesystem. Never expose a partially written cache file.
                with tempfile.NamedTemporaryFile(
                    dir=dest.parent, prefix=f".{name}-", delete=False,
                ) as output:
                    temporary = Path(output.name)
                    shutil.copyfileobj(extracted, output)
            temporary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            os.replace(temporary, dest)
    except (OSError, tarfile.TarError, KeyError) as exc:
        raise BinaryResolutionError(f"failed to install {name}: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def binary_path() -> Path:
    """Return the path to a runnable disclosure binary, fetching it if needed.

    An already-installed ``disclosure`` on ``PATH`` is not used: pinning to a
    known release keeps the wrapper's behaviour reproducible.
    """
    goos, goarch = _target()
    path = _cache_dir() / _binary_name(goos)
    try:
        # Do not follow a cache symlink or silently replace an unusable cache.
        # Report its location so callers can remove it and retry deliberately.
        if path.is_symlink():
            raise BinaryResolutionError(f"cached binary {path} is a symlink; remove it and retry")
        if not path.exists():
            _fetch(goos, goarch, path)
        if not path.is_file() or path.stat().st_size == 0:
            raise BinaryResolutionError(f"cached binary {path} is not a non-empty regular file; remove it and retry")
        if os.name != "nt" and not os.access(path, os.X_OK):
            raise BinaryResolutionError(f"cached binary {path} is not executable; remove it and retry")
    except OSError as exc:
        raise BinaryResolutionError(f"cannot access cached binary {path}: {exc}") from exc
    return path
