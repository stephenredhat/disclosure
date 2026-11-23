"""Offline regression tests for binary resolution, downloads, and CLI errors."""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tarfile
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import disclosure  # noqa: E402
from disclosure import __main__ as cli  # noqa: E402
from disclosure import _binary  # noqa: E402


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def unexpected_network(*args, **kwargs):
        raise AssertionError("tests must not access the network")

    monkeypatch.setattr(_binary.urllib.request, "urlopen", unexpected_network)


def cached_path(tmp_path, monkeypatch):
    monkeypatch.setenv("DISCLOSURE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(_binary, "_target", lambda: ("linux", "amd64"))
    path = _binary._cache_dir() / "disclosure"
    path.parent.mkdir(parents=True)
    return path


def test_main_returns_2_when_cached_binary_is_not_runnable(tmp_path, monkeypatch, capsys):
    path = cached_path(tmp_path, monkeypatch)
    path.write_bytes(b"")

    assert cli.main() == 2
    assert "disclosure:" in capsys.readouterr().err


@pytest.mark.parametrize("error", [OSError("exec format error"), PermissionError("denied")])
def test_main_returns_2_when_process_cannot_start(monkeypatch, capsys, error):
    monkeypatch.setattr(cli, "binary_path", lambda: Path("/fake/disclosure"))

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli.subprocess, "run", fail)
    assert cli.main() == 2
    assert str(error) in capsys.readouterr().err


@pytest.mark.parametrize("stage", ["resolution", "execution"])
def test_main_returns_2_for_unexpected_wrapper_errors(monkeypatch, capsys, stage):
    def fail(*args, **kwargs):
        raise RuntimeError("unexpected wrapper failure")

    monkeypatch.setattr(cli, "binary_path", fail if stage == "resolution" else lambda: Path("fake"))
    if stage == "execution":
        monkeypatch.setattr(cli.subprocess, "run", fail)
    assert cli.main() == 2
    assert "unexpected wrapper failure" in capsys.readouterr().err


@pytest.mark.parametrize("returncode", [0, 1, 2, 7])
def test_main_preserves_child_exit_codes_and_arguments(monkeypatch, returncode):
    monkeypatch.setattr(cli, "binary_path", lambda: Path("fake-disclosure"))
    monkeypatch.setattr(sys, "argv", ["disclosure", "text", "--format=json"])
    calls = []

    def run(args):
        calls.append(args)
        return subprocess.CompletedProcess(args, returncode)

    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli.main() == returncode
    assert calls == [["fake-disclosure", "text", "--format=json"]]


def test_main_maps_child_signal_to_error(monkeypatch):
    monkeypatch.setattr(cli, "binary_path", lambda: Path("fake"))
    monkeypatch.setattr(cli.subprocess, "run", lambda args: subprocess.CompletedProcess(args, -9))
    assert cli.main() == 2


def test_library_reports_process_start_failure(monkeypatch):
    monkeypatch.setattr(disclosure, "binary_path", lambda: Path("fake"))

    def fail(*args, **kwargs):
        raise OSError("exec format error")

    monkeypatch.setattr(disclosure.subprocess, "run", fail)
    with pytest.raises(_binary.BinaryResolutionError, match="exec format error"):
        disclosure.run(["version"])


def test_library_reports_child_signal(monkeypatch):
    monkeypatch.setattr(disclosure, "binary_path", lambda: Path("fake"))
    monkeypatch.setattr(
        disclosure.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, -9, "", ""),
    )
    with pytest.raises(disclosure.DisclosureError) as exc:
        disclosure.run(["version"])
    assert exc.value.returncode == -9


@pytest.mark.parametrize("returncode", [0, 1])
def test_library_builds_scan_arguments_and_accepts_findings(monkeypatch, returncode):
    monkeypatch.setattr(disclosure, "binary_path", lambda: Path("fake"))
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, returncode, '{"findings": []}', "")

    monkeypatch.setattr(disclosure.subprocess, "run", run)
    assert disclosure.scan(
        "/repo", commit_range="a..b", min_confidence="high", confidence_levels="high=100",
    ) == {"findings": []}
    assert calls == [(
        ["fake", "scan", "--range=a..b", "--min-confidence=high",
         "--confidence-levels=high=100", "/repo", "--format=json"],
        {"input": None, "capture_output": True, "text": True},
    )]


def test_library_default_scan_and_text_modes(monkeypatch):
    monkeypatch.setattr(disclosure, "binary_path", lambda: Path("fake"))
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs["input"]))
        return subprocess.CompletedProcess(args, 0, "[]", "")

    monkeypatch.setattr(disclosure.subprocess, "run", run)
    assert disclosure.scan() == []
    assert disclosure.text("I used AI") == []
    assert disclosure.text(input_file="body.txt") == []
    assert disclosure.text() == []
    with pytest.raises(ValueError, match="either"):
        disclosure.text("content", input_file="body.txt")
    assert calls == [
        (["fake", "scan", "--format=json"], None),
        (["fake", "text", "--format=json"], "I used AI"),
        (["fake", "text", "--input=body.txt", "--format=json"], None),
        (["fake", "text", "--format=json"], ""),
    ]


def test_library_error_and_version(monkeypatch):
    monkeypatch.setattr(disclosure, "binary_path", lambda: Path("fake"))
    monkeypatch.setattr(
        disclosure.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 2, "", "scanner failed"),
    )
    with pytest.raises(disclosure.DisclosureError, match="scanner failed") as exc:
        disclosure.scan()
    assert exc.value.returncode == 2
    assert exc.value.stderr == "scanner failed"
    monkeypatch.setattr(
        disclosure.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "1.0.0\n", ""),
    )
    assert disclosure.version() == "1.0.0"


def test_binary_path_reuses_valid_cache(tmp_path, monkeypatch):
    path = cached_path(tmp_path, monkeypatch)
    path.write_bytes(b"cached binary")
    path.chmod(0o755)
    monkeypatch.setattr(_binary, "_fetch", lambda *args: pytest.fail("unexpected fetch"))
    assert _binary.binary_path() == path


@pytest.mark.parametrize("kind", ["empty", "directory", "not_executable"])
def test_binary_path_rejects_unusable_cache(tmp_path, monkeypatch, kind):
    if kind == "not_executable" and os.name == "nt":
        pytest.skip("Windows does not use POSIX execute permissions")
    path = cached_path(tmp_path, monkeypatch)
    if kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"" if kind == "empty" else b"binary")
        path.chmod(0o644)
    with pytest.raises(_binary.BinaryResolutionError, match="cached binary"):
        _binary.binary_path()


def test_binary_path_rejects_symlink(tmp_path, monkeypatch):
    path = cached_path(tmp_path, monkeypatch)
    try:
        path.symlink_to(tmp_path / "absent-target")
    except OSError:
        pytest.skip("symlinks unavailable on this platform")
    with pytest.raises(_binary.BinaryResolutionError, match="cached binary"):
        _binary.binary_path()


def test_binary_path_fetches_missing_binary(tmp_path, monkeypatch):
    path = cached_path(tmp_path, monkeypatch)
    calls = []

    def fetch(goos, goarch, dest):
        calls.append((goos, goarch, dest))
        dest.write_bytes(b"new binary")
        dest.chmod(0o755)

    monkeypatch.setattr(_binary, "_fetch", fetch)
    assert _binary.binary_path() == path
    assert calls == [("linux", "amd64", path)]


def test_binary_path_wraps_cache_access_error(tmp_path, monkeypatch):
    path = cached_path(tmp_path, monkeypatch)

    def fail(self):
        raise PermissionError("cache access denied")

    monkeypatch.setattr(Path, "is_symlink", fail)
    with pytest.raises(_binary.BinaryResolutionError, match="cache access denied"):
        _binary.binary_path()


def archive_bytes(name="disclosure", content=b"verified binary", member_type=tarfile.REGTYPE):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.type = member_type
        if member_type == tarfile.REGTYPE:
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        else:
            member.linkname = "other"
            archive.addfile(member)
    return buffer.getvalue()


def install_downloads(monkeypatch, archive, checksum=None):
    digest = checksum if checksum is not None else hashlib.sha256(archive).hexdigest()
    asset = f"disclosure_{_binary.DISCLOSURE_VERSION}_linux_amd64.tar.gz"
    calls = []

    def download(url):
        calls.append(url)
        if url.endswith("checksums.txt"):
            return f"{digest}  {asset}\n".encode()
        assert url.endswith(asset)
        return archive

    monkeypatch.setattr(_binary, "_download", download)
    return calls


def test_fetch_verifies_and_installs_binary(tmp_path, monkeypatch):
    payload = b"verified binary"
    calls = install_downloads(monkeypatch, archive_bytes(content=payload))
    dest = tmp_path / "cache" / "disclosure"
    _binary._fetch("linux", "amd64", dest)
    assert dest.read_bytes() == payload
    if os.name != "nt":
        assert os.access(dest, os.X_OK)
    assert len(calls) == 2
    assert sorted(p.name for p in dest.parent.iterdir()) == ["disclosure"]


def test_fetch_rejects_tampered_archive(tmp_path, monkeypatch):
    original = archive_bytes(content=b"original binary")
    tampered = archive_bytes(content=b"tampered binary")
    install_downloads(monkeypatch, tampered, hashlib.sha256(original).hexdigest())
    dest = tmp_path / "disclosure"
    with pytest.raises(_binary.BinaryResolutionError, match="checksum mismatch"):
        _binary._fetch("linux", "amd64", dest)
    assert not dest.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "missing", "empty", "invalid"])
def test_fetch_rejects_unusable_archive_members(tmp_path, monkeypatch, kind):
    if kind == "invalid":
        archive = b"not a tar archive"
    elif kind == "missing":
        archive = archive_bytes(name="other")
    elif kind == "empty":
        archive = archive_bytes(content=b"")
    else:
        archive = archive_bytes(member_type={
            "symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "directory": tarfile.DIRTYPE,
        }[kind])
    install_downloads(monkeypatch, archive)
    dest = tmp_path / "disclosure"
    with pytest.raises(_binary.BinaryResolutionError):
        _binary._fetch("linux", "amd64", dest)
    assert not dest.exists()


def test_fetch_installs_atomically(tmp_path, monkeypatch):
    payload = b"complete binary"
    install_downloads(monkeypatch, archive_bytes(content=payload))
    dest = tmp_path / "cache" / "disclosure"
    replace = os.replace
    calls = []

    def check_replace(source, target):
        assert Path(source).parent == dest.parent
        assert Path(source).read_bytes() == payload
        assert not dest.exists()
        calls.append((source, target))
        replace(source, target)

    monkeypatch.setattr(_binary.os, "replace", check_replace)
    _binary._fetch("linux", "amd64", dest)
    assert len(calls) == 1
    assert dest.read_bytes() == payload


def test_fetch_cleans_up_failed_install(tmp_path, monkeypatch):
    install_downloads(monkeypatch, archive_bytes())
    dest = tmp_path / "cache" / "disclosure"

    def fail(*args):
        raise OSError("disk failure")

    monkeypatch.setattr(_binary.os, "replace", fail)
    with pytest.raises(_binary.BinaryResolutionError, match="disk failure"):
        _binary._fetch("linux", "amd64", dest)
    assert list(dest.parent.iterdir()) == []


def test_fetch_failure_preserves_existing_cache(tmp_path, monkeypatch):
    install_downloads(monkeypatch, archive_bytes(), checksum="0" * 64)
    dest = tmp_path / "disclosure"
    dest.write_bytes(b"existing cache")
    with pytest.raises(_binary.BinaryResolutionError, match="checksum mismatch"):
        _binary._fetch("linux", "amd64", dest)
    assert dest.read_bytes() == b"existing cache"


def test_download_reads_response(monkeypatch):
    calls = []

    def urlopen(url, timeout):
        calls.append((url, timeout))
        return io.BytesIO(b"release bytes")

    monkeypatch.setattr(_binary.urllib.request, "urlopen", urlopen)
    assert _binary._download("https://example.invalid/asset") == b"release bytes"
    assert calls == [("https://example.invalid/asset", 30)]


def test_download_wraps_network_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(_binary.urllib.request, "urlopen", fail)
    with pytest.raises(_binary.BinaryResolutionError, match="offline"):
        _binary._download("https://example.invalid/asset")


@pytest.mark.parametrize("manifest", [b"\xff", b"bad  {asset}\n"])
def test_expected_sha256_rejects_malformed_manifest(monkeypatch, manifest):
    asset = f"disclosure_{_binary.DISCLOSURE_VERSION}_linux_amd64.tar.gz"
    manifest = manifest.replace(b"{asset}", asset.encode())
    monkeypatch.setattr(_binary, "_download", lambda url: manifest)
    with pytest.raises(_binary.BinaryResolutionError):
        _binary._expected_sha256("linux", "amd64")


@pytest.mark.parametrize("system,machine,expected", [
    ("Linux", "x86_64", ("linux", "amd64")),
    ("Darwin", "aarch64", ("darwin", "arm64")),
    ("Windows", "AMD64", ("windows", "amd64")),
    ("Linux", "arm64", ("linux", "arm64")),
])
def test_target_supported_platforms(monkeypatch, system, machine, expected):
    monkeypatch.setattr(_binary.platform, "system", lambda: system)
    monkeypatch.setattr(_binary.platform, "machine", lambda: machine)
    assert _binary._target() == expected


@pytest.mark.parametrize("system,machine", [("Plan9", "amd64"), ("Linux", "mips")])
def test_target_rejects_unsupported_platforms(monkeypatch, system, machine):
    monkeypatch.setattr(_binary.platform, "system", lambda: system)
    monkeypatch.setattr(_binary.platform, "machine", lambda: machine)
    with pytest.raises(_binary.BinaryResolutionError):
        _binary._target()


def test_windows_binary_name():
    assert _binary._binary_name("windows") == "disclosure.exe"


def test_cache_directory_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("DISCLOSURE_CACHE_DIR", raising=False)
    monkeypatch.setattr(_binary.platform, "system", lambda: "Linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert _binary._cache_dir() == tmp_path / "xdg" / "disclosure-cli" / _binary.DISCLOSURE_VERSION
    monkeypatch.setattr(_binary.platform, "system", lambda: "Windows")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "windows"))
    assert _binary._cache_dir() == tmp_path / "windows" / "disclosure-cli" / _binary.DISCLOSURE_VERSION
