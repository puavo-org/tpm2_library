#!/usr/bin/env python3
import argparse
import subprocess
import json
import sys


def main():
    parser = argparse.ArgumentParser(
        description="rustc error picker"
    )
    parser.add_argument("crate", help="crate name")
    parser.add_argument("root", help="crate root")
    parser.add_argument("query", help="substring query")
    args = parser.parse_args()
    cmd = [
        "rustc",
        "--crate-type", "lib",
        "--crate-name", args.crate,
        args.root,
        "--edition=2021",
        "--emit=mir",
        "--error-format=json",
        "-o", "/dev/null",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    results = []
    for line in proc.stderr.splitlines():
        try:
            diag = json.loads(line)
        except json.JSONDecodeError:
            continue
        for span in diag.get("spans", []):
            if args.query in span.get("file_name", ""):
                results.append(diag)
                break
    if results:
        print(results[0].get("rendered", "").rstrip())


if __name__ == "__main__":
    main()
