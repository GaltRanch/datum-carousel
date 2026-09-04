#!/usr/bin/env python3
"""
On-chain check of Carousel blocks: for every block whose coinbase scriptSig carries the
CAROUSEL tag, print the supplier name (from the scriptSig), the coinbase outputs with their share
of the reward (finder / supplier / pool) and the transaction count. Everything here comes from the
chain — nothing from the pool. Don't trust, verify.

    carousel_blocks_onchain.py --conf /path/to/rpc.conf [--back 3000] [--max 10]
    carousel_blocks_onchain.py --url http://127.0.0.1:8332 --user U --password P

rpc.conf is a bitcoin.conf-style file with rpcconnect / rpcport / rpcuser / rpcpassword.
"""
import argparse, base64, json, re, sys, time, urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--conf"); ap.add_argument("--url"); ap.add_argument("--user"); ap.add_argument("--password")
    ap.add_argument("--back", type=int, default=3000, help="how many blocks back from the tip to scan")
    ap.add_argument("--max", type=int, default=10, help="stop after this many Carousel blocks")
    ap.add_argument("--tag", default="CAROUSEL", help="coinbase tag to look for")
    a = ap.parse_args()
    if a.conf:
        c = dict(l.strip().split("=", 1) for l in open(a.conf) if "=" in l and not l.startswith("#"))
        url, user, pw = f"http://{c.get('rpcconnect', '127.0.0.1')}:{c['rpcport']}/", c["rpcuser"], c["rpcpassword"]
    elif a.url and a.user:
        url, user, pw = a.url, a.user, a.password or ""
    else:
        ap.print_help(); return 2
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()

    def rpc(m, *p):
        req = urllib.request.Request(url, json.dumps({"method": m, "params": list(p), "id": 1}).encode(),
                                     {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
        r = json.load(urllib.request.urlopen(req, timeout=60))
        if r.get("error"): raise SystemExit(f"rpc {m}: {r['error']}")
        return r["result"]

    tip = rpc("getblockcount"); print(f"tip {tip}")
    tag, n, h = a.tag.encode(), 0, tip
    while h > tip - a.back and n < a.max:
        bh = rpc("getblockhash", h); b = rpc("getblock", bh, 1)
        cb = rpc("getrawtransaction", b["tx"][0], True, bh)
        sig = bytes.fromhex(cb["vin"][0]["coinbase"])
        h -= 1
        if tag not in sig:
            continue
        n += 1
        outs = [(o["value"], o["scriptPubKey"].get("address") or o["scriptPubKey"].get("type")) for o in cb["vout"]]
        tot = sum(v for v, _ in outs)
        m = re.search(rb"CAROUSEL[^/]*/([\x20-\x7e]+)", sig)
        name = m.group(1).decode().rstrip() if m else "?"
        print(f"\n#{h + 1}  {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(b['time']))} UTC  txs={len(b['tx'])}  reward={tot:.8f}  supplier={name!r}")
        for v, addr in outs:
            print(f"  {v:.8f}  {v / tot * 100:6.2f}%  {addr}")
    if n == 0:
        print(f"no block with tag {a.tag!r} in the last {a.back} blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
