#!/usr/bin/env python3
"""
DATUM-TS · PoC #2 — el commitment viaja por Stratum v1 real (mining.notify) sin romper mineros vanilla.

Novedad sobre la PoC #1: en SV1 el minero varía extranonce2 → el merkle_root CAMBIA en cada share.
Así que el commitment NO puede atar el merkle_root final. Ata las partes INVARIANTES del job (las que
definen QUÉ template se mina): coinb1, coinb2 (contiene los outputs/split) y merkle_branch (las otras
txs). El minero verifica UNA vez por job y después itera extranonce libremente.

Transporte: el pool manda `mining.notify` estándar + una notificación vendor `pyblock.tcommit`. Un minero
SV1 vanilla ignora el método desconocido y mina igual (no se rompe). El gateway DATUM-TS lee ambos y verifica.

Cadena: Bitcoin-BLAKE2b (blake2b). Firma: secp256k1 (`ecdsa`).

    python3 poc_stratum.py
"""
import hashlib, struct, json
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

TAG = b"DATUM-TS/commit/v1"
def b2(*c):  # blake2b-256
    h = hashlib.blake2b(digest_size=32)
    for x in c: h.update(x)
    return h.digest()
def hx(b): return b.hex()

# ── coinbase / split ── el split vive en coinb2 (los outputs). Reconstruible y parseable.
def encode_outputs(outs):
    b = struct.pack("<H", len(outs))
    for addr, sats in outs:
        a = addr.encode(); b += struct.pack("<H", len(a)) + a + struct.pack("<Q", sats)
    return b
def parse_outputs(coinb2):
    (n,) = struct.unpack_from("<H", coinb2, 0); off = 2; outs = []
    for _ in range(n):
        (ln,) = struct.unpack_from("<H", coinb2, off); off += 2
        addr = coinb2[off:off+ln].decode(); off += ln
        (sats,) = struct.unpack_from("<Q", coinb2, off); off += 8
        outs.append((addr, sats))
    return outs

def merkle_root_from_job(coinb1, extranonce1, extranonce2, coinb2, branch):
    """Como lo hace un minero SV1: coinbase = coinb1+xn1+xn2+coinb2; hash; foldear con la branch.
       (blake2b en esta cadena). Cambia con cada extranonce2 → NO sirve para el commitment."""
    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
    h = b2(coinbase)
    for node in branch:
        h = b2(h, node)
    return h

# ── SUPPLIER: arma el job SV1 + firma el commitment de las partes INVARIANTES ──
class Supplier:
    def __init__(self, name):
        self.name = name
        self.sk = SigningKey.generate(curve=SECP256k1); self.vk = self.sk.get_verifying_key()
        self.addr = "bc1q" + b2(self.vk.to_string()).hex()[:20]

    def build(self, other_txids, coinbase_outputs, clean=True):
        coinb1 = b"\x01\x00\x00\x00" + b"COINB1-height+tag(PyBLOCK-CAROUSEL-BLAKE2b/" + self.name.encode() + b")"
        coinb2 = encode_outputs(coinbase_outputs)                 # el split va acá
        branch = [b2(b"tx", t.encode()) for t in other_txids]     # ruta merkle de las otras txs
        supplier_id = self.addr.encode()
        # commitment sobre lo INVARIANTE (no el merkle_root final, que varía con extranonce)
        C = b2(TAG, coinb1, coinb2, b"".join(branch), supplier_id, b"\x01" if clean else b"\x00")
        sig = self.sk.sign_deterministic(C, hashfunc=hashlib.sha256)
        job = {"job_id": "j1", "prevhash": hx(b2(b"tip")), "coinb1": hx(coinb1), "coinb2": hx(coinb2),
               "merkle_branch": [hx(x) for x in branch], "version": "20000000", "nbits": "1a008d4f",
               "ntime": "66d70000", "clean_jobs": True}
        tcommit = {"job_id": "j1", "supplier_id": supplier_id.decode(), "supplier_pub": hx(self.vk.to_string()),
                   "clean": clean, "commitment": hx(C), "sig": hx(sig)}
        return job, tcommit

# ── MINERO VANILLA SV1: ignora pyblock.tcommit, mina igual (prueba: no se rompe) ──
def vanilla_miner(messages):
    handled, mined = [], False
    for m in messages:
        if m["method"] == "mining.notify":
            mined = True; handled.append("mining.notify → arma coinbase y mina")
        else:
            handled.append(f"{m['method']} → método desconocido, IGNORADO (sigo minando)")
    return mined, handled

# ── GATEWAY DATUM-TS: verifica el commitment UNA vez por job, contra las partes invariantes ──
def datumts_verify(job, tcommit, policy):
    reasons = []
    coinb1 = bytes.fromhex(job["coinb1"]); coinb2 = bytes.fromhex(job["coinb2"])
    branch = [bytes.fromhex(x) for x in job["merkle_branch"]]
    supplier_id = tcommit["supplier_id"].encode()
    C_recomputed = b2(TAG, coinb1, coinb2, b"".join(branch), supplier_id, b"\x01" if tcommit["clean"] else b"\x00")
    if hx(C_recomputed) != tcommit["commitment"]:
        reasons.append("commitment no reproduce el job (coinb1/coinb2/branch adulterados)")
    try:
        VerifyingKey.from_string(bytes.fromhex(tcommit["supplier_pub"]), curve=SECP256k1).verify(
            bytes.fromhex(tcommit["sig"]), bytes.fromhex(tcommit["commitment"]), hashfunc=hashlib.sha256)
    except BadSignatureError:
        reasons.append("firma del supplier inválida")
    outs = parse_outputs(coinb2); total = sum(s for _, s in outs) or 1
    by = {a: s for a, s in outs}
    if not tcommit["clean"]: reasons.append("template no limpia")
    sup_pct = 100 * by.get(tcommit["supplier_id"], 0) / total
    if sup_pct < policy["min_supplier_pct"]:
        reasons.append(f"no se le paga la comisión al supplier ({sup_pct:.2f}%)")
    if policy["pool_addr"] not in by: reasons.append("falta fee del pool")
    return (not reasons), reasons

POLICY = {"min_supplier_pct": 0.9, "pool_addr": "1PyBLoCKfeeXXXXXXXXXXXXXXXXXXXXXXX"}

def deliver(job, tcommit, tamper=None):
    """El pool 'manda' los dos mensajes. tamper() puede adulterar el job antes de servirlo."""
    j = json.loads(json.dumps(job))
    if tamper: tamper(j)
    msgs = [{"method": "mining.notify", "params": j},
            {"method": "pyblock.tcommit", "params": tcommit}]
    return j, msgs

def run(title, job, tcommit, tamper=None):
    j, msgs = deliver(job, tcommit, tamper)
    v_ok, v_log = vanilla_miner(msgs)
    d_ok, d_reasons = datumts_verify(j, tcommit, POLICY)
    print(f"\n{title}")
    print(f"  minero VANILLA SV1 : {'✅ mina' if v_ok else '❌ no'} (ignoró pyblock.tcommit → no se rompe)")
    print(f"  gateway DATUM-TS   : {'✅ verifica y mina' if d_ok else '❌ RECHAZA'}")
    for r in d_reasons: print(f"       ↳ {r}")
    return v_ok, d_ok

def main():
    sup = Supplier("nomadshiba")
    miner = "bc1qMINERfinderaddrxxxxxxxxxxxxxxxx"
    outs = [(miner, 98_000), (sup.addr, 1_000), (POLICY["pool_addr"], 1_000)]
    job, tcommit = sup.build(["aaa", "bbb"], outs)

    print("DATUM-TS · PoC #2 — commitment sobre Stratum v1 real\n" + "="*56)
    print(f"supplier {sup.name} · {sup.addr}")

    v1, d1 = run("Escenario 1 — pool honesto:", job, tcommit)

    def skim(j):  # el pool le saca el 1% al supplier reescribiendo coinb2
        j["coinb2"] = encode_outputs([(miner, 99_000), (POLICY["pool_addr"], 1_000)]).hex()
    v2, d2 = run("Escenario 2 — pool SKIMEA el 1% del supplier (reescribe coinb2):", job, tcommit, skim)
    print("       ⚠ el vanilla mina el bloque skimeado a ciegas; SOLO DATUM-TS lo detecta.")

    def swap(j):  # el pool mete otra tx (cambia la branch)
        j["merkle_branch"] = [b2(b"tx", b"EVIL").hex()]
    v3, d3 = run("Escenario 3 — pool SWAPEA txs (cambia merkle_branch):", job, tcommit, swap)

    # invariancia de extranonce: verifico UNA vez, luego itero extranonce2 (el root cambia, el commitment no)
    print("\nEscenario 4 — invariancia de extranonce (por qué atamos coinb1/coinb2/branch, no el root):")
    coinb1 = bytes.fromhex(job["coinb1"]); coinb2 = bytes.fromhex(job["coinb2"])
    branch = [bytes.fromhex(x) for x in job["merkle_branch"]]
    roots = {merkle_root_from_job(coinb1, b"\x00\x00\x00\x00", struct.pack("<I", n), coinb2, branch).hex()[:16]
             for n in range(4)}
    print(f"  4 extranonce2 → {len(roots)} merkle roots distintos (varía por share)")
    print(f"  el commitment se verificó 1 vez sobre lo invariante → sigue válido para los {len(roots)} → ✅")

    ok = (v1 and d1) and (v2 and not d2) and (v3 and not d3) and len(roots) == 4
    print("\n" + "="*56)
    print("RESULTADO:", "✅ el commitment viaja por SV1 real, no rompe mineros vanilla, y el gateway\n"
          "           DATUM-TS detecta skim/swap que el vanilla mina a ciegas." if ok else "❌ revisar")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
