"""
datum_ts_verify.py — DATUM-TS: verificación de publicación FIRMADA en el ingest (PoC #3 → producción).

Regla de compatibilidad (no rompe a nadie):
  · address NO registrada  → flujo legacy sin firma (como hoy).            status="legacy"
  · address REGISTRADA     → la publicación DEBE venir firmada con SU key: status="verified" | "reject"
      - sin bloque `_datum_ts` en el body        → reject (registered supplier must sign)
      - pubkey ≠ la registrada                    → reject (IMPERSONACIÓN)
      - commitment no reproduce la template       → reject (adulterada en tránsito)
      - firma inválida                            → reject
Registro (solo LECTURA para el ingest; se administra fuera): /var/www/pyblock/data/datum_ts_registry.json
  {"<address>": "<pubkey_hex secp256k1 (64 bytes, sin prefijo)>", ...}
Commitment (chain-agnóstico — solo cambia la función de hash):
  C = H(TAG ‖ addr ‖ height(u32le) ‖ prevhash(32B) ‖ txids_root ‖ 0x01)
  H = blake2b-256 en la cadena bip110/blake2b · sha256d en legacy. Firma = ECDSA secp256k1 (`ecdsa`).
El supplier manda en el JSON del template: "_datum_ts": {"commitment": hex, "sig": hex, "pubkey": hex}
(misma convención que `_user` / `_name`).
"""
import hashlib, json, os

TAG = b"DATUM-TS/commit/v1"
REGISTRY = os.environ.get("DATUM_TS_REGISTRY", "/var/www/pyblock/data/datum_ts_registry.json")

def _blake2b(*c):
    h = hashlib.blake2b(digest_size=32)
    for x in c: h.update(x)
    return h.digest()
def _sha256d(*c):
    h = hashlib.sha256()
    for x in c: h.update(x)
    return hashlib.sha256(h.digest()).digest()
def hash_for(chain: str):
    return _blake2b if chain in ("bip110", "blake2b") else _sha256d

def txids_root(H, txids_hex):
    layer = []
    for t in txids_hex:
        try: layer.append(bytes.fromhex(t))
        except Exception: layer.append(H(str(t).encode()))
    if not layer: return H(b"empty")
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [H(layer[i], layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

def commitment(H, addr: str, height, prevhash: str, root: bytes) -> bytes:
    try: h = int(height or 0)
    except Exception: h = 0
    try: pv = bytes.fromhex(prevhash or "")
    except Exception: pv = b""
    return H(TAG, addr.encode(), h.to_bytes(4, "little", signed=False), pv, root, b"\x01")

def load_registry() -> dict:
    try:
        with open(REGISTRY) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def verify_publication(tmpl: dict, addr: str, chain: str):
    """→ (status, reason, datum_ts_block). status ∈ {"legacy","verified","reject"}."""
    reg = load_registry()
    reg_pub = reg.get(addr)
    if not reg_pub:
        return "legacy", None, None                       # no registrada → como hoy
    blk = tmpl.get("_datum_ts")
    if not isinstance(blk, dict):
        return "reject", "registered supplier must sign its template (_datum_ts missing)", None
    pub = str(blk.get("pubkey", "")).lower()
    if pub != str(reg_pub).lower():
        return "reject", "IMPERSONATION: signing key is not the one registered for this address", None
    H = hash_for(chain)
    root = txids_root(H, [t.get("txid", "") for t in tmpl.get("transactions", [])])
    C = commitment(H, addr, tmpl.get("height"), tmpl.get("previousblockhash") or "", root)
    if str(blk.get("commitment", "")).lower() != C.hex():
        return "reject", "commitment does not reproduce the submitted template", None
    try:
        from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
        VerifyingKey.from_string(bytes.fromhex(pub), curve=SECP256k1).verify(
            bytes.fromhex(str(blk.get("sig", ""))), C, hashfunc=hashlib.sha256)
    except Exception:
        return "reject", "invalid supplier signature over the commitment", None
    return "verified", None, {"commitment": C.hex(), "sig": str(blk.get("sig")), "pubkey": pub, "chain": chain}
