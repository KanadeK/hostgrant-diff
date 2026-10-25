"""CLI for offline manifest comparisons."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import MAX_BYTES, InputError, compare, load_manifest


def _read(filename):
    if filename == "-":
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
    else:
        with Path(filename).open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    return load_manifest(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare declared Chrome MV3 host grants offline.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("before", help="old manifest JSON or - for stdin")
    parser.add_argument("after", help="new manifest JSON or - for stdin")
    parser.add_argument("-o", "--output", help="create a new JSON report; never overwrite a file")
    args = parser.parse_args(argv)
    try:
        if args.before == args.after == "-":
            raise InputError("only one input may use stdin")
        result = compare(_read(args.before), _read(args.after))
        output = json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            with Path(args.output).open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(output)
        else:
            sys.stdout.write(output)
        return 1 if result["status"] == "host-expansion" else 0
    except InputError as exc:
        print(f"hostgrant-diff: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("hostgrant-diff: input/output operation failed", file=sys.stderr)
        return 2
