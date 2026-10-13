#!/usr/bin/env python3
"""Huntress CTF 2026 Game Master client.

A thin, dependency-free wrapper around the Game Master HTTP API used to drive
the Binary Reverse Engineering lane. It shells out to ``curl`` (already
configured for this environment's outbound proxy) and passes the bearer token
via ``curl --config -`` so the secret never appears in process arguments or
shell history.

Token resolution order:
  1. ``$HUNTRESS_GM_TOKEN``            (the raw bearer)
  2. file named by ``$HUNTRESS_GM_TOKEN_FILE``
  3. ``~/.huntress_token``

Usage examples:
  gm.py list --lane binary
  gm.py openapi
  gm.py status   <challenge-id>
  gm.py start    <challenge-id> [--run-for-time]
  gm.py retry    <challenge-id> [--run-for-time]
  gm.py artifact <challenge-id> -o out.zip [--delivery N]
  gm.py submit   <challenge-id> --answers answers.json
  gm.py submit   <challenge-id> --kv id1=val1 --kv id2=val2
"""
import argparse
import json
import os
import subprocess
import sys
from urllib.parse import urlencode

BASE = "https://2026.huntress.ctf.games/"


def _read_token() -> str:
    tok = os.environ.get("HUNTRESS_GM_TOKEN")
    if tok:
        return tok.strip()
    path = os.environ.get("HUNTRESS_GM_TOKEN_FILE") or os.path.expanduser("~/.huntress_token")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError as exc:
        sys.exit(f"gm.py: cannot read token (set HUNTRESS_GM_TOKEN or HUNTRESS_GM_TOKEN_FILE): {exc}")


def _curl(url, *, body=None, binary_out=None):
    """Run curl against *url*. The bearer is fed via --config - (stdin) so it is
    never visible in argv. Returns raw stdout bytes."""
    token = _read_token()
    config = f'header = "Authorization: Bearer {token}"\nsilent\nshow-error\n'
    cmd = ["curl", "--config", "-"]
    if binary_out:
        cmd += ["-o", binary_out]
    if body is not None:
        cmd += ["--data-binary", body, "-H", "Content-Type: application/json"]
    cmd += [url]
    proc = subprocess.run(cmd, input=config.encode(), capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode(errors="replace"))
    return proc.stdout


def _get(params):
    return _curl(BASE + "?" + urlencode(params))


def _post(payload):
    return _curl(BASE, body=json.dumps(payload))


def _pp(raw: bytes):
    try:
        print(json.dumps(json.loads(raw.decode()), indent=2, ensure_ascii=False))
    except Exception:
        sys.stdout.buffer.write(raw)
        if raw[-1:] != b"\n":
            print()


def main():
    ap = argparse.ArgumentParser(description="Huntress CTF Game Master client")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("openapi")

    p = sub.add_parser("list")
    p.add_argument("--day"); p.add_argument("--lane"); p.add_argument("--all", action="store_true")
    p.add_argument("--search")

    p = sub.add_parser("status"); p.add_argument("challenge")
    p = sub.add_parser("start"); p.add_argument("challenge"); p.add_argument("--run-for-time", action="store_true")
    p = sub.add_parser("retry"); p.add_argument("challenge"); p.add_argument("--run-for-time", action="store_true")
    p = sub.add_parser("practice"); p.add_argument("challenge")

    p = sub.add_parser("artifact"); p.add_argument("challenge"); p.add_argument("-o", "--out", required=True)
    p.add_argument("--delivery")

    p = sub.add_parser("submit"); p.add_argument("challenge")
    p.add_argument("--answers"); p.add_argument("--kv", action="append", default=[])

    p = sub.add_parser("pair"); p.add_argument("--reset", action="store_true")

    a = ap.parse_args()

    if a.cmd == "openapi":
        _pp(_get({"op": "openapi"}))
    elif a.cmd == "list":
        params = {"op": "list"}
        if a.day: params["day"] = a.day
        if a.lane: params["lane"] = a.lane
        if a.all: params["all"] = "true"
        if a.search: params["search"] = a.search
        _pp(_get(params))
    elif a.cmd == "status":
        _pp(_get({"op": "status", "challenge": a.challenge}))
    elif a.cmd == "artifact":
        params = {"op": "artifact", "challenge": a.challenge}
        if a.delivery:
            params["delivery"] = a.delivery
        _curl(BASE + "?" + urlencode(params), binary_out=a.out)
        print(f"saved -> {a.out}")
    elif a.cmd == "start":
        payload = {"challenge": a.challenge}
        if a.run_for_time:
            payload["run_for_time"] = True
        _pp(_post(payload))
    elif a.cmd == "retry":
        payload = {"op": "retry", "challenge": a.challenge}
        if a.run_for_time:
            payload["run_for_time"] = True
        _pp(_post(payload))
    elif a.cmd == "practice":
        _pp(_post({"op": "practice", "challenge": a.challenge}))
    elif a.cmd == "submit":
        answers = {}
        if a.answers:
            with open(a.answers) as fh:
                answers = json.load(fh)
        for kv in a.kv:
            k, _, v = kv.partition("=")
            answers[k] = v
        _pp(_post({"challenge": a.challenge, "answers": answers}))
    elif a.cmd == "pair":
        _pp(_post({"op": "pair", "reset": True}) if a.reset else _post({"op": "pair"}))


if __name__ == "__main__":
    main()
