# disclosure (Python wrapper) — proof of concept

A thin Python wrapper around the [CHAOSS `disclosure`](https://github.com/chaoss/disclosure)
CLI, so it can be installed from PyPI and used from Python.

> **Status: proof of concept.** This wraps the prebuilt `disclosure` binary; it
> is not an in-process binding. Published to **TestPyPI** only for now, to prove
> the approach is useful before deciding on a permanent home and maintenance
> plan (see [issue #82](https://github.com/chaoss/disclosure/issues/82)).

## How it works

On first use the package downloads the prebuilt `disclosure` binary for your
platform from the GitHub release, verifies it against the release
`checksums.txt`, and caches it (under `~/.cache/disclosure-cli/` by default).
- Downloads: verify the archive checksum before extraction.
- Cache installation: write the complete binary to a temporary file, then
  replace the destination atomically.
- Existing cache: reject empty files, symlinks, and non-executable POSIX files.
  Errors identify the cache path; remove the unusable file and retry.
- CLI errors: return `2` for wrapper failures, including process-start failures;
  preserve the scanner's `0` and `1` results.

This is the simplest thing that works everywhere from a single wheel. A
production version would instead **bundle the binary in platform-specific
wheels** (per Simon Willison's "Distributing Go binaries" write-up that Andrew
linked in [issue #82](https://github.com/chaoss/disclosure/issues/82)),
removing the runtime download.

## Use it as a CLI

```sh
uvx disclosure scan --format=json          # run without installing
# or
pip install disclosure
disclosure scan /path/to/repo
```

## Use it from Python

```python
import disclosure

report = disclosure.scan("/path/to/repo", min_confidence="medium")
print(report)                              # already a dict

findings = disclosure.text("I used Claude to write this")
print(disclosure.version())
```

`scan()` and `text()` return the parsed JSON report as a Python object.

## Install from TestPyPI

```sh
pip install --index-url https://test.pypi.org/simple/ disclosure
```

If the name `disclosure` is already taken on the target index, the package is
published as `disclosure-cli`; then run it with
`uvx --from disclosure-cli disclosure ...`.

## Publishing the PoC (maintainer notes)

```sh
cd python
python -m build
python -m twine upload --repository testpypi dist/*
```

The wrapped binary version is pinned by `DISCLOSURE_VERSION` in
`src/disclosure/_binary.py` (currently `1.0.0`). Override it at runtime with the
`DISCLOSURE_VERSION` env var for local testing.

## Tests

- Install test dependencies: `python -m pip install -e "./python[test]"`.
- Run from the repository root: `python -m pytest python/tests`.
- Test suite: mocked downloads and local stub binaries; no release downloads.
- Coverage gate: at least 90% combined statement and branch coverage for the
  Python wrapper. Test dependencies are not runtime dependencies.
- GitHub Actions: Python 3.9 and 3.14 on Linux; Python 3.14 on macOS and Windows.
- CI results: available after the workflow runs; local results do not establish
  that every operating-system/Python combination passes.
