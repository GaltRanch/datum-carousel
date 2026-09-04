#!/usr/bin/env python3
"""
DATUM-TS · PoC #1 — Commitment de template verificable (la pieza que le gana a DATUM).

Prueba la propiedad de seguridad CENTRAL del fork: el pool es un RELAY, no una fuente de
confianza. Un supplier (node-runner) arma su template limpia, la firma, y el minero puede
VERIFICAR — antes de minar — que el trabajo que recibió es exactamente esa template, con el
split acordado (finder/supplier/pool). Si el pool swapea la template, censura, o le roba el 1%
al supplier, el minero lo DETECTA y rechaza el job.

Cadena: Bitcoin-BLAKE2b (hash = blake2b). Firma: secp256k1 (misma curva que las llaves Bitcoin
del supplier). Sin deps externas salvo `ecdsa`.

    python3 poc_commitment.py
"""
import hashlib, struct
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

TAG = b"DATUM-TS/commit/v1"          # domain separation
def b2(*chunks: bytes) -> bytes:     # hash de la cadena
    h = hashlib.blake2b(digest_size=32)
    for c in chunks: h.update(c)
    return h.digest()

# ── modelo mínimo de template (lo justo para probar la propiedad, no un bloque completo) ──
def ser_outputs(outs):
    """coinbase outputs [(addr:str, sats:int)] → bytes deterministas."""
    b = struct.pack("<H", len(outs))
    for addr, sats in outs:
        ab = addr.encode()
        b += struct.pack("<H", len(ab)) + ab + struct.pack("<Q", sats)
    return b

def coinbase_txid(outs):
    """El coinbase COMMITEA sus outputs → tocar el split cambia este txid."""
    return b2(b"cb", ser_outputs(outs))

def merkle_root(txids):
    """Merkle blake2b sobre los txids (tx[0] = coinbase). Tocar cualquier tx cambia la raíz."""
    layer = list(txids)
    if not layer: return b2(b"empty")
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [b2(layer[i], layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

def is_clean(txids_meta):
    """Template limpia = sin OP_RETURN de datos (datacarrier=0). El supplier lo attesta."""
    return all(not m.get("op_return_data") for m in txids_meta)

# ── SUPPLIER: arma su template, computa el commitment, lo FIRMA ──
class Supplier:
    def __init__(self, name):
        self.name = name
        self.sk = SigningKey.generate(curve=SECP256k1)
        self.vk = self.sk.get_verifying_key()
        self.addr = "bc1q" + b2(self.vk.to_string()).hex()[:20]     # id de pago (mock de address)

    def build_job(self, other_txs_meta, coinbase_outputs):
        # txids: coinbase (commitea el split) + resto de txs del template del supplier
        cb = coinbase_txid(coinbase_outputs)
        txids = [cb] + [b2(b"tx", t["id"].encode()) for t in other_txs_meta]
        mroot = merkle_root(txids)
        clean = is_clean(other_txs_meta)
        supplier_id = self.addr.encode()
        # commitment: ata merkle_root (que ya ata el split vía coinbase) + supplier + flag de limpieza
        C = b2(TAG, mroot, supplier_id, b"\x01" if clean else b"\x00")
        sig = self.sk.sign_deterministic(C, hashfunc=hashlib.sha256)
        return {
            "supplier_id": supplier_id, "supplier_pub": self.vk.to_string(),
            "txids": txids, "coinbase_outputs": coinbase_outputs, "clean": clean,
            "merkle_root": mroot, "commitment": C, "sig": sig,
        }

# ── MINER GATEWAY: VERIFICA el job antes de minar (no confía en el pool) ──
def verify_job(job, policy):
    reasons = []
    # 1) el split que me dieron debe reproducir el coinbase, y los txids la merkle root
    cb = coinbase_txid(job["coinbase_outputs"])
    if job["txids"][0] != cb:
        reasons.append("coinbase no coincide con los outputs servidos (split adulterado)")
    if merkle_root(job["txids"]) != job["merkle_root"]:
        reasons.append("merkle_root no coincide con los txids (template swapeada)")
    # 2) el commitment debe reproducirse de lo que REALMENTE voy a minar
    C2 = b2(TAG, job["merkle_root"], job["supplier_id"], b"\x01" if job["clean"] else b"\x00")
    if C2 != job["commitment"]:
        reasons.append("commitment no reproduce el trabajo servido")
    # 3) la firma del supplier sobre el commitment debe ser válida (el pool no puede forjarla)
    try:
        VerifyingKey.from_string(job["supplier_pub"], curve=SECP256k1).verify(
            job["sig"], job["commitment"], hashfunc=hashlib.sha256)
    except BadSignatureError:
        reasons.append("firma del supplier inválida (commitment no firmado por el supplier)")
    # 4) política: template limpia + el supplier cobra su % + fee del pool presente
    total = sum(s for _, s in job["coinbase_outputs"]) or 1
    by_addr = {a: s for a, s in job["coinbase_outputs"]}
    if not job["clean"]:
        reasons.append("template NO limpia (trae datos OP_RETURN)")
    sup_addr = job["supplier_id"].decode()
    sup_pct = 100 * by_addr.get(sup_addr, 0) / total
    if sup_pct < policy["min_supplier_pct"]:
        reasons.append(f"al supplier no se le paga su comisión (recibe {sup_pct:.2f}%)")
    if policy["pool_addr"] not in by_addr:
        reasons.append("falta el fee del pool en el coinbase")
    return (len(reasons) == 0), reasons

# ── DEMO ──
POLICY = {"min_supplier_pct": 0.9, "pool_addr": "1PyBLoCKfeeXXXXXXXXXXXXXXXXXXXXXXX"}

def scenario(title, job):
    ok, reasons = verify_job(job, POLICY)
    print(f"  {'✅ ACEPTA (mina)' if ok else '❌ RECHAZA'}  · {title}")
    for r in reasons: print(f"       ↳ {r}")
    return ok

def main():
    sup = Supplier("nomadshiba")
    miner_addr = "bc1qMINERfinderaddressxxxxxxxxxxxxxx"
    txs = [{"id": "aaa", "op_return_data": False}, {"id": "bbb", "op_return_data": False}]
    # split honesto 98/1/1
    honest_outs = [(miner_addr, 98_000), (sup.addr, 1_000), (POLICY["pool_addr"], 1_000)]
    job = sup.build_job(txs, honest_outs)

    print("DATUM-TS · PoC commitment de template (Bitcoin-BLAKE2b)\n" + "-"*58)
    print(f"supplier: {sup.name} · {sup.addr}\n")

    print("Escenario 1 — pool HONESTO relaya tal cual:")
    r1 = scenario("template del supplier + split 98/1/1 intactos", job)

    print("\nEscenario 2 — pool SWAPEA la template (mete otras txs):")
    j2 = dict(job); j2["txids"] = [job["txids"][0], b2(b"tx", b"EVIL")]; j2["merkle_root"] = merkle_root(j2["txids"])
    r2 = scenario("pool cambió el bloque, conserva C/firma viejos", j2)

    print("\nEscenario 3 — pool le ROBA el 1% al supplier (lo saca del coinbase):")
    j3 = dict(job); j3["coinbase_outputs"] = [(miner_addr, 99_000), (POLICY["pool_addr"], 1_000)]
    r3 = scenario("pool skimeó la comisión del supplier", j3)

    print("\nEscenario 4 — pool FORJA un commitment nuevo para su template swapeada:")
    evil_txids = [job["txids"][0], b2(b"tx", b"EVIL")]; evil_root = merkle_root(evil_txids)
    j4 = dict(job); j4["txids"] = evil_txids; j4["merkle_root"] = evil_root
    j4["commitment"] = b2(TAG, evil_root, job["supplier_id"], b"\x01")   # C válido para SU template…
    r4 = scenario("…pero no puede firmarlo (no tiene la llave del supplier)", j4)

    print("\n" + "-"*58)
    good = (r1 and not r2 and not r3 and not r4)
    print("RESULTADO:", "✅ propiedad probada — el pool es RELAY, no fuente de confianza."
          if good else "❌ revisar")
    print("El minero solo mina si recibe la template EXACTA del supplier, con su comisión intacta,\n"
          "firmada por el supplier. Swap / censura / skim → detectado y rechazado.")
    return 0 if good else 1

if __name__ == "__main__":
    raise SystemExit(main())
