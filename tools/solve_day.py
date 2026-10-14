#!/usr/bin/env python3
"""Per-day orchestrator for the Huntress Binary RE lane.

Runs the three modes of one day in the order that lets each inform the next:

  1. single_solve  — UNTIMED. Dry-run the solver over the day's artifact to
     confirm every field is covered (no None / no extraction error) before any
     clock is running. New, unseen field types surface here, safely.
  2. time_trial    — TIMED, scored. Solve for real. This is where scored
     feedback validates the answer formats. It gates mastery: if the time
     trial does not come back CORRECT, we stop rather than burn scarce mastery
     variants on a mis-calibrated solver.
  3. mastery       — TIMED, scored, MULTI-DELIVERY. Run last, at full scale,
     with every set's artifact downloaded and submitted in parallel.

Usage:
  HUNTRESS_GM_TOKEN_FILE=... python3 tools/solve_day.py 14
  python3 tools/solve_day.py 14 --lane binary --tt-attempts 3 --mastery-attempts 3
  python3 tools/solve_day.py 14 --from mastery      # skip earlier stages
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm
import autosolve

LANE = "binary-reverse-engineering"


def resolve_ids(day, lane=LANE):
    """Find the single_solve / time_trial / mastery challenge ids for a day."""
    data = json.loads(gm._get({"op": "list", "all": "true"}).decode())
    base = None
    for ch in data.get("challenges", []):
        if ch.get("lane") == lane and ch.get("day") == day and ch.get("mode") == "single_solve":
            base = ch["id"]
            break
    if not base:
        # fall back to a day-scoped listing (handles smart-default omissions)
        data = json.loads(gm._get({"op": "list", "day": str(day), "lane": lane}).decode())
        for ch in data.get("challenges", []):
            if ch.get("mode") == "single_solve" and ch.get("lane") == lane:
                base = ch["id"]
                break
    if not base:
        return None
    return {"single_solve": base, "time_trial": f"{base}/time_trial",
            "mastery": f"{base}/mastery"}


def attempts_remaining(challenge):
    try:
        st = json.loads(gm._get({"op": "status", "challenge": challenge}).decode())
        return st.get("unique_attempts_remaining")
    except Exception:
        return None


def stage(title):
    print(f"\n{'='*70}\n== {title}\n{'='*70}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("day", type=int)
    ap.add_argument("--lane", default=LANE)
    ap.add_argument("--from", dest="start_from", default="single_solve",
                    choices=["single_solve", "time_trial", "mastery"],
                    help="skip to a later stage")
    ap.add_argument("--tt-attempts", type=int, default=3)
    ap.add_argument("--mastery-attempts", type=int, default=3)
    ap.add_argument("--force-mastery", action="store_true",
                    help="run mastery even if the time trial did not pass")
    a = ap.parse_args()

    ids = resolve_ids(a.day, a.lane)
    if not ids:
        print(f"[x] could not find day {a.day} in lane {a.lane} — is it released yet?")
        print("    (check: python3 tools/gm.py list --all | ids for this day)")
        return 2
    print(f"[i] day {a.day}: {ids['single_solve']}")
    base_work = os.path.join("/tmp", f"day{a.day}_{int(time.time())}")
    order = ["single_solve", "time_trial", "mastery"]
    stages = order[order.index(a.start_from):]

    tt_ok = None
    tt_blocked = False  # a genuine wrong answer (not a mere timeout) blocks mastery
    # ---- 1. single_solve: untimed coverage check ------------------------------
    if "single_solve" in stages:
        stage(f"DAY {a.day} · single_solve (untimed coverage check)")
        s = autosolve.run_attempt(ids["single_solve"], retry=False, dry_run=True,
                                  work=os.path.join(base_work, "single"))
        miss = s.get("missing") or []
        if miss:
            print(f"[!] {len(miss)} field(s) have NO answer — likely a new field "
                  f"type for day {a.day}. Calibrate these on the time trial before "
                  f"mastery:\n    {miss[:30]}")
        else:
            print(f"[✓] coverage OK: all {s.get('nq')} fields produced an answer.")

    # ---- 2. time_trial: scored validation (gates mastery) ---------------------
    if "time_trial" in stages:
        stage(f"DAY {a.day} · time_trial (scored)")
        rem = attempts_remaining(ids["time_trial"])
        if rem == 0:
            print("[!] no fresh time-trial variants left; skipping scored validation.")
        else:
            s = autosolve.run_attempt(ids["time_trial"], retry=True,
                                      attempts=a.tt_attempts,
                                      work=os.path.join(base_work, "tt"))
            tt_ok = s.get("result") in ("CORRECT", "already_solved")
            tt_blocked = s.get("result") == "incorrect"   # a real wrong answer
            print(f"[=] time_trial => {s.get('result')}")
            if tt_blocked:
                print("[!] time trial returned INCORRECT — a genuine wrong answer, so "
                      "the solver needs a format fix for this day. Mastery is gated off "
                      "until this is resolved (use --force-mastery to override).")
            elif not tt_ok:
                print("[~] time trial not CORRECT but not a wrong answer (e.g. expired / "
                      "no scored variants). Treating as a timing artifact, not a "
                      "correctness failure — proceeding to mastery.")

    # ---- 3. mastery: full-scale, parallel deliveries --------------------------
    if "mastery" in stages:
        stage(f"DAY {a.day} · mastery (scored, parallel deliveries)")
        if tt_blocked and not a.force_mastery:
            print("[x] skipping mastery: the time trial returned a genuine wrong "
                  "answer (use --force-mastery to override).")
            return 1
        rem = attempts_remaining(ids["mastery"])
        if rem == 0:
            print("[!] no fresh mastery variants remaining.")
            return 1
        s = autosolve.run_attempt(ids["mastery"], retry=True,
                                  attempts=a.mastery_attempts,
                                  work=os.path.join(base_work, "mastery"))
        print(f"\n[=] DAY {a.day} mastery => {s.get('result')} "
              f"({s.get('sets')} sets, {s.get('elapsed', 0):.1f}s)")
        return 0 if s.get("result") in ("CORRECT", "already_solved") else 1
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
