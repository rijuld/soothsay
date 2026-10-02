#!/usr/bin/env python3
"""Run soothsay over popular real-world installers and compare verdicts.

The scripts are fetched fresh every run and never stored in the repo (they
belong to their authors). What is stored is tests/corpus/expected.json: each
installer's sha256 and the verdict soothsay gave it.

A verdict change is one of two things:

* regression: same bytes as last time, different verdict. soothsay changed,
  so that's on us. `--check` fails on these.
* upstream: the installer itself changed (new sha256) and so did its verdict.
  That's news about the installer, reported for the installer watch.

Usage:
    scripts/installer_corpus.py --check            # compare, exit 1 on regressions
    scripts/installer_corpus.py --update           # rewrite expected.json
    scripts/installer_corpus.py --json r.json --markdown r.md

Python 3 standard library only.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEVERITIES = ["none", "info", "notice", "warn", "danger"]


def load_list(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, url = line.split("\t")
            out.append((name, url))
    return out


def fetch(url, dest):
    """Download with curl; returns an error string or None."""
    r = subprocess.run(
        ["curl", "-fsSL", "--retry", "2", "--connect-timeout", "10",
         "--max-time", "60", "-o", dest, "--", url],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return (r.stderr.strip().splitlines() or [f"curl exited {r.returncode}"])[-1]
    return None


def analyze(binary, path):
    r = subprocess.run([binary, "--json", path], capture_output=True, text=True)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"soothsay exited {r.returncode}: {r.stderr.strip()}")
    return json.loads(r.stdout)


def summarize(name, url, report, data):
    live = [f for f in report["findings"] if f["reachable"]]
    counts = {s: sum(1 for f in live if f["severity"] == s) for s in ("danger", "warn", "notice")}
    serious = sorted({f["message"] for f in live if f["severity"] in ("warn", "danger")})
    ranked = sorted(live, key=lambda f: (-SEVERITIES.index(f["severity"]), f["line"]))
    standout, seen = [], set()
    for f in ranked:
        if f["severity"] in ("info",) or f["message"] in seen:
            continue
        seen.add(f["message"])
        standout.append(f"{f['severity']}: {f['message']}")
        if len(standout) == 2:
            break
    return {
        "name": name,
        "url": url,
        "sha256": hashlib.sha256(data).hexdigest(),
        "lines": report["lines"],
        "max_severity": report["max_severity"] or "none",
        "counts": counts,
        "serious": serious,
        "standout": standout,
    }


def compare(results, expected):
    """Annotate each result with its status against expected.json."""
    for r in results:
        exp = expected.get(r["name"])
        if r.get("error"):
            r["status"] = "fetch-failed"
        elif exp is None:
            r["status"] = "new"
        elif exp["max_severity"] == r["max_severity"]:
            r["status"] = "ok" if exp["sha256"] == r["sha256"] else "ok-upstream-changed"
        elif exp["sha256"] == r["sha256"]:
            r["status"] = "regression"
        else:
            r["status"] = "upstream"
        if exp:
            r["expected"] = exp["max_severity"]


def cell(s):
    return s.replace("|", "\\|").replace("\n", " ")


def markdown(results):
    marks = {
        "ok": "", "ok-upstream-changed": " (script changed)", "new": " (new)",
        "regression": " ⚠️ **regression**", "upstream": " 🔔 **installer changed**",
        "fetch-failed": " (fetch failed)",
    }
    lines = [
        "| Installer | Lines | Verdict | What stands out |",
        "| :-- | --: | :-- | :-- |",
    ]
    for r in results:
        if r.get("error"):
            lines.append(f"| [{r['name']}]({r['url']}) | | fetch failed | {cell(r['error'])} |")
            continue
        verdict = r["max_severity"]
        if r["status"] in ("regression", "upstream"):
            verdict = f"{r['expected']} → {verdict}"
        lines.append(
            f"| [{r['name']}]({r['url']}) | {r['lines']:,} | {verdict}{marks[r['status']]} | "
            f"{cell('; '.join(r['standout'])) or 'nothing notable'} |"
        )
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=os.path.join(ROOT, "target", "release", "soothsay"))
    ap.add_argument("--list", default=os.path.join(ROOT, "tests", "corpus", "installers.tsv"))
    ap.add_argument("--expected", default=os.path.join(ROOT, "tests", "corpus", "expected.json"))
    ap.add_argument("--json", help="write full results here")
    ap.add_argument("--markdown", help="write the report table here")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="exit 1 if soothsay's verdict changed on unchanged bytes")
    mode.add_argument("--update", action="store_true", help="rewrite expected.json from this run")
    args = ap.parse_args()

    if not os.access(args.bin, os.X_OK):
        sys.exit(f"no soothsay binary at {args.bin} (cargo build --release)")
    try:
        with open(args.expected) as f:
            expected = json.load(f)
    except FileNotFoundError:
        expected = {}

    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, url in load_list(args.list):
            dest = os.path.join(tmp, f"{name}.sh")
            err = fetch(url, dest)
            if err:
                results.append({"name": name, "url": url, "error": err})
                print(f"  {name:<10} fetch failed: {err}", file=sys.stderr)
                continue
            with open(dest, "rb") as f:
                data = f.read()
            results.append(summarize(name, url, analyze(args.bin, dest), data))
            r = results[-1]
            print(f"  {name:<10} {r['lines']:>5} lines  {r['max_severity']}", file=sys.stderr)

    compare(results, expected)
    report = markdown(results)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write(report)
    else:
        print(report)

    regressions = [r["name"] for r in results if r.get("status") == "regression"]
    upstream = [r["name"] for r in results if r.get("status") == "upstream"]
    failed = [r["name"] for r in results if r.get("status") == "fetch-failed"]

    # Let a GitHub Actions step branch on what happened.
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"regressions={' '.join(regressions)}\n")
            f.write(f"upstream={' '.join(upstream)}\n")
            f.write(f"fetch_failed={' '.join(failed)}\n")

    if failed:
        print(f"warning: couldn't fetch {', '.join(failed)}", file=sys.stderr)
    if upstream:
        print(f"installer changed upstream: {', '.join(upstream)}", file=sys.stderr)

    if args.update:
        new = dict(expected)
        for r in results:
            if not r.get("error"):
                new[r["name"]] = {"url": r["url"], "sha256": r["sha256"], "max_severity": r["max_severity"]}
        with open(args.expected, "w") as f:
            json.dump(new, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"updated {os.path.relpath(args.expected)}", file=sys.stderr)
    elif args.check and regressions:
        print(f"regression: soothsay's verdict changed on unchanged bytes: {', '.join(regressions)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
