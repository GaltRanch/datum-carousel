#!/usr/bin/env python3
"""
Independent verifier for the Carousel's deterministic rotation.

Rule (datum_blocktemplates.c):
    set      = supplier caches (template_live/<addr>.json) with previousblockhash == prevhash,
               a transactions[] array, stale != true and — unless the gateway runs with
               template_require_validated=false — validated.proposal == true (the ingest's stamp:
               passed getblocktemplate mode=proposal + the datacarrier gate); sorted bytewise;
               capped to CAROUSEL_MAX_SET AFTER sorting
    seed     = BLAKE2b-256(prevhash lowercase hex ASCII)
    start    = uint64_be(seed[0:8]) % n
    cycle    = work cycles since prevhash was first seen (0-based)
    pick     = set[(start + cycle) % n]   — never advanced past a failing template
               (failed=true / pick="" means the gateway mined its own tx-set that cycle, no supplier paid)
    set_hash = BLAKE2b-256("\n".join(set) + "\n")[0:8] hex

Usage:
    verify_carousel_rotation.py --api http://127.0.0.1:7156          # check the live cycle
    verify_carousel_rotation.py --log /path/to/gateway.log [--tail N] # re-verify every logged cycle
    verify_carousel_rotation.py --template-dir DIR --api URL          # also rebuild the set from the caches

Exit code 0 = every checked cycle matches the rule, 1 = mismatch, 2 = usage / no data.
"""
import argparse, hashlib, json, os, re, sys, urllib.request

MAX_SET = 4096


def blake2b256(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()


def start_for(prevhash: str, n: int) -> int:
    return int.from_bytes(blake2b256(prevhash.lower().encode())[:8], "big") % n


def set_hash_for(addrs) -> str:
    return blake2b256(("\n".join(addrs) + "\n").encode())[:8].hex()


def expected_pick(prevhash: str, addrs, cycle: int) -> str:
    n = len(addrs)
    return addrs[(start_for(prevhash, n) + cycle) % n]


def fresh_set_from_dir(template_dir: str, prevhash: str, require_validated: bool = True):
    out = []
    for fn in os.listdir(template_dir):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(template_dir, fn)) as f:
                t = json.load(f)
        except Exception:
            continue
        if t.get("previousblockhash") != prevhash or not isinstance(t.get("transactions"), list) or t.get("stale") is True:
            continue
        if require_validated:
            v = t.get("validated")
            if not (isinstance(v, dict) and v.get("proposal") is True):
                continue
        out.append(fn[:-5])
    return sorted(out)[:MAX_SET]


def check_api(url: str, template_dir: str | None) -> bool:
    with urllib.request.urlopen(url.rstrip("/") + "/carousel", timeout=5) as r:
        st = json.load(r)
    if not st.get("carousel"):
        print("gateway is not in carousel mode"); return True
    if st.get("active") is False:
        print(f"template mode not active yet (activate_height={st.get('activate_height')}, template height={st.get('height')})"); return True
    n, addrs = st["n"], st["set"]
    print(f"height={st['height']} prevhash={st['prevhash']} cycle={st['cycle']} n={n} start={st['start']} idx={st['idx']} pick={st['pick']} failed={st.get('failed')}")
    if n == 0:
        print("no fresh supplier this cycle (gateway mined its own tx-set)"); return True
    ok = True
    if addrs != sorted(addrs):
        print("FAIL set is not sorted bytewise"); ok = False
    if start_for(st["prevhash"], n) != st["start"]:
        print(f"FAIL start: expected {start_for(st['prevhash'], n)} got {st['start']}"); ok = False
    if set_hash_for(addrs) != st["set_hash"]:
        print(f"FAIL set_hash: expected {set_hash_for(addrs)} got {st['set_hash']}"); ok = False
    exp = expected_pick(st["prevhash"], addrs, st["cycle"])
    exp_idx = (st["start"] + st["cycle"]) % n
    if st["idx"] != exp_idx:
        print(f"FAIL idx: expected {exp_idx} got {st['idx']}"); ok = False
    if st.get("failed"):
        print(f"note: scheduled template {exp} failed to load/apply — no supplier this cycle (allowed, visible)")
    elif exp != st["pick"]:
        print(f"FAIL pick: expected {exp} got {st['pick']}"); ok = False
    if template_dir:
        mine = fresh_set_from_dir(template_dir, st["prevhash"], st.get("require_validated", True))
        extra, missing = sorted(set(addrs) - set(mine)), sorted(set(mine) - set(addrs))
        # the caches move between the gateway's read and ours; report, don't fail, on small drift
        print(f"set vs {template_dir}: gateway={n} local={len(mine)} only-gateway={extra} only-local={missing}")
    print("OK live cycle matches the rule" if ok else "MISMATCH")
    return ok


ROT = re.compile(r"carousel: rotation h=(\d+) cycle=(\d+) n=(\d+) start=(\d+) (?:skipped=\d+ )?idx=(-?\d+) pick=(\S+) (?:FAILED|set=([0-9a-f]{16}) prevhash=([0-9a-f]{64}))")
SET = re.compile(r"carousel: set ([0-9a-f]{16}) n=(\d+) \[(\d+)\.\.(\d+)\] (\S+)")


def check_log(path: str, tail: int) -> bool:
    sets: dict[str, dict] = {}   # set_hash -> {"n": n, "addrs": {idx: addr}}
    rows = []
    with open(path, errors="replace") as f:
        for line in f:
            m = SET.search(line)
            if m:
                h, n, a, b, lst = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), m.group(5).split(",")
                s = sets.setdefault(h, {"n": n, "addrs": {}})
                for i, addr in enumerate(lst):
                    s["addrs"][a + i] = addr
                continue
            m = ROT.search(line)
            if m and m.group(7):          # FAILED lines carry no set/prevhash → nothing to recompute
                rows.append(m.groups())
    if tail:
        rows = rows[-tail:]
    if not rows:
        print("no rotation lines found"); return False
    ok, checked, unknown = True, 0, 0
    for h, cycle, n, start, idx, pick, sh, prevhash in rows:
        n, cycle, start, idx = int(n), int(cycle), int(start), int(idx)
        s = sets.get(sh)
        if not s or len(s["addrs"]) != s["n"]:
            unknown += 1; continue          # set logged before the tail we read
        addrs = [s["addrs"][i] for i in range(s["n"])]
        exp_start, exp_pick, exp_hash = start_for(prevhash, n), expected_pick(prevhash, addrs, cycle), set_hash_for(addrs)
        checked += 1
        if exp_hash != sh or exp_start != start or idx != (start + cycle) % n or exp_pick != pick:
            ok = False
            print(f"FAIL h={h} cycle={cycle}: logged start={start} idx={idx} pick={pick} set={sh} — expected start={exp_start} pick={exp_pick} set={exp_hash}")
    print(f"{'OK' if ok else 'MISMATCH'}: {checked} cycles verified, {unknown} skipped (set not in the portion read)")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", help="gateway API base URL, e.g. http://127.0.0.1:7156")
    ap.add_argument("--log", help="gateway log file to re-verify")
    ap.add_argument("--tail", type=int, default=0, help="only the last N rotation lines of --log")
    ap.add_argument("--template-dir", help="rebuild the fresh set from the supplier caches and compare")
    a = ap.parse_args()
    if not a.api and not a.log:
        ap.print_help(); return 2
    ok = True
    if a.api:
        ok &= check_api(a.api, a.template_dir)
    if a.log:
        ok &= check_log(a.log, a.tail)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
