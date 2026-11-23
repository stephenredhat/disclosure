"""Console entry point: forward all arguments to the disclosure binary.

``disclosure <args>`` and ``python -m disclosure <args>`` both behave exactly
like invoking the native CLI, including stdin/stdout piping and exit codes.
"""

from __future__ import annotations

import subprocess
import sys

from ._binary import binary_path


def main() -> int:
    try:
        binary = binary_path()
        # Inherit stdio so pipes and TTY output work.
        returncode = subprocess.run([str(binary), *sys.argv[1:]]).returncode
        if returncode < 0:
            print(f"disclosure: scanner terminated by signal {-returncode}", file=sys.stderr)
            return 2
        return returncode
    except Exception as exc:
        # Top-level CLI boundary: wrapper failures must not escape as Python's
        # exit code 1, which the scanner reserves for a successful AI finding.
        print(f"disclosure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
