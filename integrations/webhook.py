#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward JSON findings from stdin to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    try:
        raw = sys.stdin.read()
    except Exception as exc:
        print(f"webhook: could not read stdin: {exc}", file=sys.stderr)
        return 2

    if not raw.strip():
        print("webhook: no input received on stdin; nothing to post", file=sys.stderr)
        return 2

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(f"webhook: ignoring malformed header (missing ':'): {h!r}", file=sys.stderr)
            continue
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
