#!/usr/bin/env python3
"""
DATUM-TS · PoC #3 — SUPPLY-MODE: el node-runner publica y FIRMA su template al ingest, SIN hashrate.

Qué prueba:
  1. Un supplier registrado publica su template con un commitment FIRMADO → el ingest verifica la firma
     contra la pubkey registrada → acepta y guarda (en la MISMA forma que template_live/*.json real, +
     commitment/sig/pubkey) para que el Carousel lo sirva y el minero lo verifique (PoC #2).
  2. Un IMPERSONADOR que publica bajo la identidad de otro supplier (sin su key) → RECHAZADO.
     (Resuelve el hueco real de hoy: el ingest no autentica X-PyBLOCK-User.)
  3. Template SUCIA (OP_RETURN con datos) → RECHAZADA (datacarrier=0 lado-pool, load-bearing).
  4. Republicar la MISMA template → DEDUPE (no farmea "papeletas" — la preocupación de Kilombino).
  5. CHAIN-AGNÓSTICO: el commitment solo depende de la función de hash → mismo flujo con sha256d.

    python3 poc_supply.py
"""
import hashlib, json, time
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

TAG = b"DATUM-TS/commit/v1"

# ── CHAIN-AGNÓSTICO: la función de hash es lo ÚNICO que cambia entre cadenas ──
def _blake2b(*c):
    h = hashlib.blake2b(digest_size=32)
    for x in c: h.update(x)
    return h.digest()
def _sha256d(*c):
    h = hashlib.sha256()
    for x in c: h.update(x)
    return hashlib.sha256(h.digest()).digest()
CHAINS = {"blake2b": _blake2b, "sha256d": _sha256d}

def txids_root(H, txids):
    layer = list(txids)
    if not layer: return H(b"empty")
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [H(layer[i], layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

def commitment(H, supplier_id: bytes, height: int, prevhash: str, root: bytes, clean: bool) -> bytes:
    return H(TAG, supplier_id, height.to_bytes(4, "little"), bytes.fromhex(prevhash), root, b"\x01" if clean else b"\x00")

# ── REGISTRO de suppliers: identidad = address de pago → pubkey (v0: key registrada separada) ──
class Registry:
    def __init__(self): self.pub = {}
    def register(self, supplier_id: str, pubkey: bytes): self.pub[supplier_id] = pubkey
    def pubkey_of(self, supplier_id: str): return self.pub.get(supplier_id)

# ── SUPPLIER (node-runner, sin hashrate): arma template, commitea, firma, publica ──
class Supplier:
    def __init__(self, name, chain="blake2b"):
        self.name = name; self.H = CHAINS[chain]; self.chain = chain
        self.sk = SigningKey.generate(curve=SECP256k1); self.vk = self.sk.get_verifying_key()
        self.addr = "bc1q" + _blake2b(self.vk.to_string()).hex()[:20]

    def template(self, height, prevhash, txs, coinbasevalue):
        """Misma forma que template_live/*.json real (user/name/ts/height/coinbasevalue/transactions…)."""
        return {"user": self.addr, "name": self.name, "ts": int(time.time()), "chain": self.chain,
                "height": height, "previousblockhash": prevhash, "coinbasevalue": coinbasevalue,
                "transactions": txs}   # cada tx: {txid, fee, weight, op_return_data:bool}

    def publish_payload(self, tpl, sign_with=None):
        """Commitment sobre lo que define la template + firma. sign_with permite simular un impostor."""
        sk = sign_with or self.sk
        clean = all(not t.get("op_return_data") for t in tpl["transactions"])
        root = txids_root(self.H, [bytes.fromhex(t["txid"]) for t in tpl["transactions"]])
        C = commitment(self.H, tpl["user"].encode(), tpl["height"], tpl["previousblockhash"], root, clean)
        return {"template": tpl, "clean": clean, "commitment": C.hex(),
                "sig": sk.sign_deterministic(C, hashfunc=hashlib.sha256).hex(),
                "pubkey": sk.get_verifying_key().to_string().hex()}

# ── INGEST (lado pool): verifica firma + limpieza + dedupe, y guarda en forma template_live ──
class Ingest:
    def __init__(self, registry, chain="blake2b"):
        self.reg = registry; self.H = CHAINS[chain]; self.store = {}   # supplier_id → json guardado
        self.seen = set()

    def publish(self, p):
        tpl = p["template"]; sid = tpl["user"]
        # 1) identidad: la pubkey que FIRMA debe ser la REGISTRADA para ese supplier_id
        reg_pub = self.reg.pubkey_of(sid)
        if reg_pub is None: return False, "supplier no registrado"
        if bytes.fromhex(p["pubkey"]) != reg_pub: return False, "IMPERSONACIÓN: la key no es la registrada para esa address"
        # 2) el commitment debe reproducirse de la template recibida (no adulterada en tránsito)
        clean = all(not t.get("op_return_data") for t in tpl["transactions"])
        root = txids_root(self.H, [bytes.fromhex(t["txid"]) for t in tpl["transactions"]])
        C = commitment(self.H, sid.encode(), tpl["height"], tpl["previousblockhash"], root, clean)
        if C.hex() != p["commitment"]: return False, "commitment no reproduce la template"
        # 3) firma válida bajo la pubkey registrada
        try: VerifyingKey.from_string(reg_pub, curve=SECP256k1).verify(bytes.fromhex(p["sig"]), C, hashfunc=hashlib.sha256)
        except BadSignatureError: return False, "firma inválida"
        # 4) limpieza lado-pool (datacarrier=0) — load-bearing: el minero no puede verificarla en SV1
        if not clean: return False, "template SUCIA (OP_RETURN con datos) → rechazada en el ingest"
        # 5) dedupe: misma template (mismo commitment) no suma otra "papeleta"
        if p["commitment"] in self.seen: return False, "DUPLICADA (dedupe, no farmea rotación)"
        self.seen.add(p["commitment"])
        # 6) guardar en la forma real + campos DATUM-TS (para que el Carousel sirva C+sig → PoC #2)
        self.store[sid] = {**tpl, "stale": False, "datum_ts": {"commitment": p["commitment"], "sig": p["sig"], "pubkey": p["pubkey"]}}
        return True, "aceptada y guardada"

# ── DEMO ──
def tx(i, dirty=False): return {"txid": _blake2b(b"tx", str(i).encode()).hex(), "fee": 300+i*7, "weight": 560+i*4, "op_return_data": dirty}

def run(title, ingest, payload):
    ok, why = ingest.publish(payload)
    print(f"  {'✅ ACEPTA' if ok else '❌ RECHAZA'} · {title}\n       ↳ {why}")
    return ok

def main():
    print("DATUM-TS · PoC #3 — supply-mode (publicación firmada al ingest, sin hashrate)\n" + "="*68)
    reg = Registry(); ing = Ingest(reg, "blake2b")
    sup = Supplier("nomadshiba"); reg.register(sup.addr, sup.vk.to_string())
    prev = _blake2b(b"tip").hex(); H_ = 966_951
    print(f"supplier registrado: {sup.name} · {sup.addr} · cadena blake2b\n")

    tpl = sup.template(H_, prev, [tx(i) for i in range(5)], 312_540_000)
    r1 = run("1 · supplier honesto publica template limpia firmada", ing, sup.publish_payload(tpl))
    st = ing.store[sup.addr]
    print(f"       guardado en forma template_live: keys={list(st)[:6]}… + datum_ts{{commitment,sig,pubkey}} ✓")

    imp = Supplier("impostor"); tpl_imp = sup.template(H_, prev, [tx(9)], 312_540_000)   # misma identidad (addr de sup)
    r2 = run("2 · IMPOSTOR publica bajo la address de nomadshiba con SU key", ing, imp.publish_payload(tpl_imp, sign_with=imp.sk))

    tpl_d = sup.template(H_, prev, [tx(1), tx(2, dirty=True)], 312_540_000)
    r3 = run("3 · supplier publica template SUCIA (OP_RETURN con datos)", ing, sup.publish_payload(tpl_d))

    r4 = run("4 · supplier REPUBLICA la misma template (farmear papeletas)", ing, sup.publish_payload(tpl))

    print("\nChain-agnóstico — mismo flujo con sha256d:")
    reg2 = Registry(); ing2 = Ingest(reg2, "sha256d"); s2 = Supplier("nodo-sha", "sha256d"); reg2.register(s2.addr, s2.vk.to_string())
    r5 = run("5 · publicación firmada en cadena sha256d", ing2, s2.publish_payload(s2.template(1, "00"*32, [tx(3)], 1)))

    ok = r1 and (not r2) and (not r3) and (not r4) and r5
    print("\n" + "="*68)
    print("RESULTADO:", "✅ supply-mode probado — publicación AUTENTICADA (impersonación imposible),\n"
          "           limpieza y dedupe lado-pool, guardado compatible con el Carousel, chain-agnóstico."
          if ok else "❌ revisar")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
