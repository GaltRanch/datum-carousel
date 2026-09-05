#!/usr/bin/env python3
# PyBLOCK — endpoint HTTP: recibe el getblocktemplate CRUDO por POST y corre los 2 gates.
# El cliente (nodo mínimo) solo necesita bitcoin-cli + curl:
#   bitcoin-cli -rpcport=9332 getblocktemplate '{"rules":["segwit"]}' \
#     | curl -sX POST --data-binary @- http://179.27.118.130:5800/
# Todo el parseo (sin jq) y la validación (testmempoolaccept + BIP-110) pasan acá, del lado server.
import os, json, time, base64, urllib.request, re, struct, hashlib, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = os.environ.get("PYBLOCK_DATA", "/var/www/pyblock/data/template_declarations.jsonl")
def record(rec):
    try:
        with open(DATA, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass

# Métrica por-push (para VER si gzip mejora el TTFT): enc, bytes en el cable, bytes descomprimidos, ms de subida.
METRICS = os.environ.get("PYBLOCK_METRICS", "/var/www/pyblock/data/ingest_metrics.jsonl")
def metric(rec):
    try:
        with open(METRICS, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass

RPC_URL  = os.environ.get("RPC_URL", "http://127.0.0.1:8332/")
RPC_AUTH = "Basic " + base64.b64encode(
    f"{os.environ.get('RPC_USER','')}:{os.environ.get('RPC_PASS','')}".encode()).decode()
# ── Dual-chain: Node B (BIP-110 fork). Un template que construye sobre el tip de la fork se detecta y
# valida contra ESTE nodo (política bip110), no contra Node A (majority). Ver [[project_dual_chain_nodes]].
RPC_URL_110  = os.environ.get("RPC_URL_110", "http://127.0.0.1:8342/")
RPC_AUTH_110 = "Basic " + base64.b64encode(
    f"{os.environ.get('RPC_USER_110','')}:{os.environ.get('RPC_PASS_110','')}".encode()).decode()
BIP110_BIT = 0x10
MAXTX = int(os.environ.get("PYBLOCK_MAXTX", "40"))   # #4: testmempoolaccept es sólo una MUESTRA de primera-línea
                                                     # (top-fee txs). El chequeo profundo de spam lo hace el parser
                                                     # barato sin RPC (first_spam_output, TODAS las txs) + FeroxSpear
                                                     # async. Antes 200 → hasta 200 RPC/push martillaban el nodo.
MAX_TXS = int(os.environ.get("PYBLOCK_MAX_TXS_PER_TMPL", "100000"))  # tope defensivo de #txs/template (anti-OOM en op_return/cache_live/dedup). Un bloque real llega a ~pocos miles; 100k jamás falso-rechaza.
KNOTS_ONLY = os.environ.get("PYBLOCK_KNOTS_ONLY", "1") == "1"  # solo aceptar nodos Bitcoin Knots (UA)
# BIP-110 ABANDONED 2026-08-09 (activation split the chain into a dead minority fork; PyBLOCK volvió a la
# cadena mayoritaria con Knots 29.1). El gate de bit-4 queda OFF por defecto → NO rechazar templates que no
# señalen BIP-110. Reversible vía PYBLOCK_REQUIRE_BIP110=1 (no usar salvo que se re-adopte).
REQUIRE_BIP110 = os.environ.get("PYBLOCK_REQUIRE_BIP110", "0") == "1"

def rpc(method, params, url=None, auth=None):
    url = url or RPC_URL; auth = auth or RPC_AUTH
    body = json.dumps({"jsonrpc": "1.0", "id": "pb", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body,
            headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read())["result"]

# ── Gate de validez de bloque completo (proposal check) ──────────────────────────────────────
# testmempoolaccept valida cada tx por separado, NO el SET como bloque (conflictos entre txs, peso,
# sigops). Armamos un bloque candidato (coinbase mínima OP_TRUE + todas las txs) y le preguntamos al
# nodo si es consenso-válido: getblocktemplate mode:proposal → null = válido. Cierra el hueco anti-grief.
def _dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def _varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd'+struct.pack('<H',n)
    if n <= 0xffffffff: return b'\xfe'+struct.pack('<I',n)
    return b'\xff'+struct.pack('<Q',n)
def _push(b): return bytes([len(b)])+b

def build_candidate_block(t):
    h=int(t["height"]); h_le=h.to_bytes((h.bit_length()+7)//8 or 1,'little')
    ssig=_push(h_le)+_push(b'/PyBLOCK/')+b'\x00\x00\x00\x00'
    outs=struct.pack('<Q',int(t["coinbasevalue"]))+_varint(1)+b'\x51'; nout=1; has_wit=False  # OP_TRUE payout
    wc_hex=t.get("default_witness_commitment")
    if wc_hex:
        wc=bytes.fromhex(wc_hex); outs+=struct.pack('<Q',0)+_varint(len(wc))+wc; nout=2; has_wit=True
    cb_base=(b'\x01\x00\x00\x00'+_varint(1)+bytes(32)+b'\xff\xff\xff\xff'
             +_varint(len(ssig))+ssig+b'\xff\xff\xff\xff'+_varint(nout)+outs+b'\x00\x00\x00\x00')
    cb_txid=_dsha(cb_base)
    cb_ser=(cb_base[:4]+b'\x00\x01'+cb_base[4:-4]+_varint(1)+_varint(32)+bytes(32)+cb_base[-4:]) if has_wit else cb_base
    row=[cb_txid]+[bytes.fromhex(x["txid"])[::-1] for x in t.get("transactions",[])]
    while len(row)>1:
        if len(row)%2: row.append(row[-1])
        row=[_dsha(row[i]+row[i+1]) for i in range(0,len(row),2)]
    ntx=len(t.get("transactions",[]))+1
    is_b2b = any('blake2b' in str(r) for r in t.get("rules", []))
    if is_b2b:
        # Header v2 BLAKE2b (Knots SERIALIZE_METHODS): version|0x80000000 + campos extendidos. Para el
        # PROPOSAL (fCheckPOW=false) los campos de minado van en cero; sólo importa la ESTRUCTURA
        # (version-bit, height, txcount, merkle, bits). Sin esto, Node B rechaza el bloque legacy de 80B.
        hdr=(struct.pack('<I', int(t["version"]) | 0x80000000)     # complete version (header-v2 flag)
             +bytes.fromhex(t["previousblockhash"])[::-1]           # hashPrevBlock
             +row[0]                                                # hashMerkleRoot
             +struct.pack('<I',int(t["curtime"]))                   # time_on_wire (flags=0 → = nTime)
             +bytes.fromhex(t["bits"])[::-1]                        # nBits
             +struct.pack('<I',0)                                   # nNonce
             +struct.pack('<I',0)                                   # m_nonce2
             +struct.pack('<I',0)                                   # m_nonce3
             +bytes(16)                                             # m_extranonce (uint128)
             +struct.pack('<I',0)                                   # m_time_offset
             +struct.pack('<H',ntx & 0xffff)                        # m_txcount (uint16)
             +b'\x00'                                               # m_flags
             +b'\x00'                                               # m_xor_key_mask_clear_bits
             +bytes(16)                                             # m_xor_key (null)
             +struct.pack('<i',int(t["height"]))                    # m_height (int32)
             +bytes(32))                                            # m_mm_rhs
    else:
        hdr=(struct.pack('<I',int(t["version"]))+bytes.fromhex(t["previousblockhash"])[::-1]
             +row[0]+struct.pack('<I',int(t["curtime"]))+bytes.fromhex(t["bits"])[::-1]+struct.pack('<I',0))
    return (hdr+_varint(ntx)+cb_ser+b''.join(bytes.fromhex(x["data"]) for x in t.get("transactions",[]))).hex()

def proposal_ok(tmpl, url=None, auth=None, rules=None):
    """True=consenso-válido · False=inválido (rechazar) · None=no concluyente (error nuestro → no penalizar).
    url/auth = nodo contra el que se valida (Node A majority por defecto, Node B para templates bip110).
    rules = reglas del proposal: ["segwit"] legacy, ["segwit","blake2b"] para la fork (Node B rechaza un
    bloque blake2b si el proposal no declara la regla 'blake2b')."""
    url = url or RPC_URL; auth = auth or RPC_AUTH; rules = rules or ["segwit"]
    try:
        blk=build_candidate_block(tmpl)
    except Exception as e:
        # el template rompió NUESTRO constructor (hex/campos malformados) = malformado/hostil → RECHAZAR.
        # (Antes devolvía None = no-concluyente = se aceptaba → un template crash-crafted bypasseaba el gate.)
        print(f"[proposal build-err] {e}", flush=True); return False
    try:
        body=json.dumps({"jsonrpc":"1.0","id":"pb","method":"getblocktemplate",
                         "params":[{"mode":"proposal","data":blk,"rules":rules}]}).encode()
        req=urllib.request.Request(url, data=body, headers={"Authorization":auth,"Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=40) as r:
            j=json.loads(r.read())
    except Exception as e:
        print(f"[proposal rpc-err] {e}", flush=True); return None
    if j.get("error"):
        print(f"[proposal node-err] {j['error']}", flush=True); return None   # error RPC → probablemente nuestra construcción
    return j.get("result") in (None, "")   # null = válido; string (reject-reason) = SET inválido

_last_ok = {}   # user → (previousblockhash, ntxs) ya validado por proposal (evita re-chequear cada post)

# ── Rate-limit por IP (anti-DoS del endpoint público) ────────────────────────────────────────
# Un supplier legítimo postea ~8/min (block-driven cada 8s + bloques). 30/60s = ~4x headroom.
# Exento 127.0.0.1 (Tor hidden-service + selfpublish local comparten esa IP).
_hits = {}
RL_WINDOW = 60; RL_MAX = int(os.environ.get("PYBLOCK_RL_MAX", "30"))
# #4: Tor hidden-service + selfpublish local LLEGAN TODOS como 127.0.0.1 (el HS reenvía a :5800 por loopback).
# Antes 127.0.0.1 estaba TOTALMENTE exento → un atacante por Tor bypasseaba el rate-limit y amplificaba RPC
# contra el nodo. Ahora el loopback tiene su PROPIO bucket con límite alto (compartido por TODOS los Tor+local):
# un supplier Tor legítimo (~7/min) ni lo roza; una inundación queda acotada. NO rompe el path onion.
RL_MAX_LOCAL = int(os.environ.get("PYBLOCK_RL_MAX_LOCAL", "240"))
def rate_limited(ip):
    if ip in ("127.0.0.1", "::1", "localhost"):
        key, limit = "__local__", RL_MAX_LOCAL   # bucket compartido Tor/local, límite alto (ya no exento)
    else:
        key, limit = ip, RL_MAX
    now = time.time(); cut = now - RL_WINDOW
    q = _hits.setdefault(key, [])
    while q and q[0] < cut: q.pop(0)
    if len(q) >= limit: return True
    q.append(now)
    if len(_hits) > 5000:   # prune defensivo de IPs viejas
        for k in [k for k, v in list(_hits.items()) if not v or v[-1] < cut]: _hits.pop(k, None)
    return False

# ── Template LIVE cache (v1 del feature per-usuario) ─────────────────────────────────────────
# Al pasar los 2 gates, cachea el template COMPLETO validado para que el stratum server
# username-routed lo sirva. Escritura ATÓMICA (tmp+replace → el server nunca lee a medias).
# Flag `stale` = el prevhash del proveedor NO es nuestro tip actual (proveedor atrasado → HOLD, §4).
LIVE_DIR = os.environ.get("PYBLOCK_LIVE", "/var/www/pyblock/data/template_live")
def safe_user(u):
    return u if re.fullmatch(r'(bc1[a-z0-9]{20,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})', u or "") else None
def cache_live(user, tmpl, name="", hold=False, url=None, auth=None, chain="legacy", datum_ts=None):
    su = safe_user(user)
    if not su:
        return   # sin address válida no hay handle que el minero pueda referenciar
    try: tip = rpc("getbestblockhash", [], url, auth)
    except Exception: tip = None
    prev = tmpl.get("previousblockhash", "")
    live = {"user": su, "name": (name or "")[:32], "ts": int(time.time()), "version": int(tmpl.get("version", 0)),
            "chain": chain,   # dual-chain: "legacy" (Node A) o "bip110" (Node B)
            "previousblockhash": prev, "bits": tmpl.get("bits"), "curtime": tmpl.get("curtime"),
            "height": tmpl.get("height"), "coinbasevalue": tmpl.get("coinbasevalue"),
            "default_witness_commitment": tmpl.get("default_witness_commitment"),
            "transactions": [{"data": t["data"], "txid": t["txid"], "fee": t.get("fee", 0), "weight": t.get("weight", 0)} for t in tmpl.get("transactions", [])],
            "datum_ts": datum_ts,   # DATUM-TS: {commitment,sig,pubkey,chain} si la publicación vino FIRMADA y verificada; None = legacy
            "stale": bool(hold) or (tip is None) or (prev != tip), "tip": tip}   # #1: hold/nodo-caído → no servir
    # Stamp de validación EXPLÍCITO para el gateway (review Kilombino 2026-09-05): solo se llega a cache_live sin
    # hold y sin stale tras pasar spam-gate + datacarrier-gate + getblocktemplate mode=proposal (o dedup de un
    # contenido idéntico ya validado). El gateway (template_require_validated) NO sirve templates sin este stamp.
    live["validated"] = ({"proposal": True, "datacarrier": True, "ts": live["ts"], "tip": tip}
                         if (not hold and tip is not None and prev == tip) else None)
    try:
        os.makedirs(LIVE_DIR, exist_ok=True)
        tmp = f"{LIVE_DIR}/.{su}.tmp"
        with open(tmp, "w") as f: json.dump(live, f)
        os.replace(tmp, f"{LIVE_DIR}/{su}.json")   # atómico
    except Exception:
        pass
    # Uptime continuo por supplier → gate de 7h para el market + purga de offline. Si hubo un gap
    # de posts > 10min, la racha se resetea (estuvo offline). {online_since, last}.
    try:
        REG = "/var/www/pyblock/data/tmpl_providers"; os.makedirs(REG, exist_ok=True)
        now = int(time.time()); upf = f"{REG}/{su}.uptime"; prev = {}
        try:
            with open(upf) as f: prev = json.load(f)
        except Exception: prev = {}
        since = int(prev.get("online_since", now)) if prev else now
        if (now - int(prev.get("last", 0))) > 600: since = now   # gap >10min → racha reseteada
        tmp2 = f"{REG}/.{su}.uptime.tmp"
        with open(tmp2, "w") as f: json.dump({"online_since": since, "last": now}, f)
        os.replace(tmp2, upf)
    except Exception:
        pass

# Razones de testmempoolaccept que NO son spam (son estado/policy, no contenido no-monetario):
# already/missing/spent/conflict/bip125 = ya en mempool o gastada · fee/insufficient/min relay =
# tx de fee baja que el nodo del provider aceptó (su minrelayfee < el nuestro) — consenso-válida igual.
BENIGN = ("missing", "already", "spent", "conflict", "bip125", "fee", "insufficient", "min relay", "mempool min", "dust",
          "same-nonwitness")   # txn-same-nonwitness-data-in-mempool = la tx ya está en nuestro mempool (dup non-witness) → benigno, NO spam

def first_spam(txs, url=None, auth=None):
    # testmempoolaccept individual: las txs del template ya están en el mempool → "already" (benigno).
    # Solo un rechazo por POLÍTICA real (scriptpubkey/datacarrier/bare-multisig) = spam.
    # url/auth = nodo del chain del template (política de mempool correcta por cadena).
    for i, tx in enumerate(txs):
        try:
            r = rpc("testmempoolaccept", [[tx]], url, auth)[0]
        except Exception as e:
            # Timeout / RPC error de NUESTRO nodo ≠ spam del provider. Es inconcluso → skip la tx
            # (no rechazar a un provider legítimo por un cuelgue nuestro). El proposal check (gate 4)
            # igual valida el bloque completo. (Antes esto devolvía spam → 116 falsos positivos.)
            print(f"[spam-gate rpc-err] tx[{i}] {e} — skip (inconclusive, NOT spam)", flush=True)
            continue
        if r.get("allowed"):
            continue
        reason = r.get("reject-reason", "")
        if any(k in reason for k in BENIGN) or not reason:
            continue  # benigno o sin razón concreta → no es spam
        return (i, reason)
    return None

# ── OP_RETURN / datacarrier gate ───────────────────────────────────────────────
# El spam-gate (testmempoolaccept) NO detecta OP_RETURN cuando las txs padre también
# están filtradas por nuestro nodo (devuelve "missing-inputs" = benigno). Así que
# parseamos los outputs de cada tx directo y rechazamos si hay OP_RETURN (scriptPubKey
# 0x6a) → template no spam-free. (La coinbase NO viene en las transactions del gbt, así
# que su OP_RETURN de witness-commitment no da falso positivo.)
def _rvarint(b, p):
    x = b[p]; p += 1
    if x < 0xfd: return x, p
    if x == 0xfd: return int.from_bytes(b[p:p+2], "little"), p + 2
    if x == 0xfe: return int.from_bytes(b[p:p+4], "little"), p + 4
    return int.from_bytes(b[p:p+8], "little"), p + 8

def tx_spam_output(txhex):
    """Razón del primer output NO-monetario, o None. Puro parseo (BARATO, sin RPC → corre sobre TODAS
    las txs). Detecta OP_RETURN (0x6a) y bare-multisig REAL (OP_M <pubkey-push> ... OP_N OP_CHECKMULTISIG).
    Excluye P2TR (51 20 <32B>) exigiendo push de pubkey (0x21/0x41) y OP_N antes del 0xae."""
    try:
        b = bytes.fromhex(txhex); p = 4                       # version
        if b[p] == 0x00 and b[p+1] == 0x01: p += 2            # segwit marker+flag
        nin, p = _rvarint(b, p)
        for _ in range(nin):
            p += 36                                           # prevout
            slen, p = _rvarint(b, p); p += slen               # scriptSig
            p += 4                                            # sequence
        nout, p = _rvarint(b, p)
        for _ in range(nout):
            p += 8                                            # value
            slen, p = _rvarint(b, p); spk = b[p:p+slen]; p += slen
            if slen >= 1 and spk[0] == 0x6a:
                return "op_return"                            # OP_RETURN datacarrier
            if (slen >= 25 and 0x51 <= spk[0] <= 0x60 and spk[-1] == 0xae
                    and 0x51 <= spk[-2] <= 0x60 and spk[1] in (0x21, 0x41)):
                return "bare_multisig"                        # bare-multisig datacarrier (NO P2TR)
        return None
    except Exception:
        return None

def first_spam_output(txs):
    for i, tx in enumerate(txs):
        r = tx_spam_output(tx)
        if r: return (i, r)
    return None

# ── FeroxSpear ban list: IPs / suppliers que el agente de defensa marcó como atacantes ──
# Se re-lee en cada post (archivo chico) → los bans que decide FeroxSpear toman efecto al instante.
FEROX_BANS = "/var/www/pyblock/data/ferox_bans.json"
def ferox_banned(ip, user):
    try:
        with open(FEROX_BANS) as f: b = json.load(f)
        return (ip in (b.get("ips") or []) or ip in (b.get("ips_soft") or [])
                or user in (b.get("suppliers") or []))
    except Exception:
        return False

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # silenciar el log default (ruido de scanners)
    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        self._send({"pyblock": "declare endpoint",
                    "uso": "POST el getblocktemplate crudo:  bitcoin-cli getblocktemplate '{\"rules\":[\"segwit\"]}' | curl -sX POST --data-binary @- <url>",
                    "gzip": "opcional pero recomendado para menor TTFT: comprimí el body y mandá 'Content-Encoding: gzip' (ej.  ... | gzip | curl -sX POST -H 'Content-Encoding: gzip' --data-binary @- <url>)"})
    def do_POST(self):
        ip = self.client_address[0]
        if rate_limited(ip):
            print(f"[rate-limit] {ip}", flush=True)
            return self._send({"ok": False, "reason": "rate limited — max 30 posts/min per IP"}, 429)
        print(f"[conn] {ip}", flush=True)
        t0 = time.time()
        enc = "gzip" if "gzip" in (self.headers.get("Content-Encoding") or "").lower() else "raw"
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n < 0 or n > 8_000_000:   # tope del body COMPRIMIDO (template real ~1.5MB crudo / ~300KB gzip)
                return self._send({"ok": False, "reason": "body too large"}, 413)
            raw = self.rfile.read(n)
            read_ms = round((time.time() - t0) * 1000, 1)   # ≈ tiempo de subida del body (lo que gzip achica)
            # gzip OPCIONAL (Content-Encoding: gzip) → reduce ~5x el upload (el cuello de botella real del TTFT
            # es subir el template sin comprimir). gzip NO ejecuta código: solo comprime; el body sigue siendo el
            # MISMO JSON de getblocktemplate. ANTI ZIP-BOMB: descompresión ACOTADA a 20MB (un template real es
            # ~1.5MB); si un cuerpo chico intenta expandirse más allá del tope, se rechaza (no agota RAM).
            if enc == "gzip":
                _d = zlib.decompressobj(zlib.MAX_WBITS | 16)   # 16 = wrapper gzip
                raw = _d.decompress(raw, 20_000_000)
                if _d.unconsumed_tail:
                    return self._send({"ok": False, "reason": "decompressed body exceeds 20MB limit"}, 413)
            dsize = len(raw)                                  # bytes descomprimidos (el JSON real)
            tmpl = json.loads(raw)
        except Exception:
            return self._send({"ok": False, "reason": "el body no es JSON de getblocktemplate (o gzip inválido)"}, 400)
        # ── validación defensiva del cuerpo (anti-crash #7/#8/#9/#15 + anti-OOM). TODO lo de abajo
        # asume estos tipos; sin esto, un JSON válido pero con tipos raros mataba el thread sin respuesta. ──
        if not isinstance(tmpl, dict):
            return self._send({"ok": False, "reason": "body must be a JSON object"}, 400)
        alltxs = tmpl.get("transactions", [])
        if not isinstance(alltxs, list):
            return self._send({"ok": False, "reason": "'transactions' must be an array"}, 400)
        if len(alltxs) > MAX_TXS:
            return self._send({"ok": False, "reason": f"too many transactions (>{MAX_TXS})"}, 413)
        for _t in alltxs:
            if not isinstance(_t, dict) or not isinstance(_t.get("data"), str) or not isinstance(_t.get("txid"), str):
                return self._send({"ok": False, "reason": "each transaction needs a string 'data' and 'txid'"}, 400)
        try:
            ver = int(tmpl.get("version") or 0)
        except (TypeError, ValueError):
            return self._send({"ok": False, "reason": "'version' must be an integer"}, 400)
        # identidad = ADDRESS del minero (header o campo _user). NUNCA la IP.
        # La IP se guarda solo server-side (/data protegido) para debug; jamás se muestra.
        addr = (tmpl.get("_user") or self.headers.get("X-PyBLOCK-User") or "").strip()
        user = addr if addr else "anonymous"
        name = (tmpl.get("_name") or self.headers.get("X-PyBLOCK-Name") or "").strip()[:40]
        ua   = (tmpl.get("_ua") or self.headers.get("X-PyBLOCK-UA") or "").strip()[:80]
        base = {"ts": int(time.time()), "ip": ip, "user": user, "name": name, "ua": ua,
                "nversion": f"0x{ver:08x}", "bip110": bool(ver & BIP110_BIT),
                "ntxs": len(alltxs), "height": tmpl.get("height"),
                "coinbasevalue": tmpl.get("coinbasevalue"),
                "prevhash": (tmpl.get("previousblockhash") or "")[:16]}

        def finish(verdict, gate=None, reason=None):
            record({**base, "verdict": verdict, "gate": gate, "reason": reason})
            metric({"ts": base["ts"], "enc": enc, "wire": n, "dsize": dsize, "read_ms": read_ms,
                    "total_ms": round((time.time() - t0) * 1000, 1), "user": user,
                    "verdict": verdict, "ntxs": len(alltxs)})
            body = {"ok": verdict == "accept", "gate": gate}
            if reason:
                body["reason"] = reason
            if verdict == "accept":
                body.update({"txs_validated": min(len(alltxs), MAXTX),
                             "nversion": base["nversion"], "job": "<merkle_root + target>"})
            self._send(body)

        if ferox_banned(ip, user):
            print(f"[reject ferox-ban] {ip} user={user}", flush=True)
            return finish("reject", "ferox-ban", "blocked by FeroxSpear — flagged as an attacker")
        if KNOTS_ONLY and "knots" not in ua.lower():
            print(f"[reject knots] {ip} user={user} ua={ua!r}", flush=True)
            return finish("reject", "knots", "banned: node is not Bitcoin Knots (UA has no 'Knots')")
        if REQUIRE_BIP110 and (ver & BIP110_BIT) == 0:
            print(f"[reject bip110] {ip} user={user} 0x{ver:08x}", flush=True)
            return finish("reject", "bip110", f"nVersion 0x{ver:08x} does not signal BIP-110 (bit 4)")
        # ── Dual-chain: detectar la cadena por el prevhash del template y elegir el nodo de validación ──
        # Un template que construye sobre el tip de la fork (Node B) se valida contra Node B (política bip110);
        # sobre el tip majority (Node A) contra Node A. Si el prevhash no es tip de ninguno (stale), se atribuye
        # por quién CONOCE el bloque (getblockheader). Así cada supplier se valida con la política de SU cadena.
        _prevf = tmpl.get("previousblockhash") or ""
        try: _tipA = rpc("getbestblockhash", [])
        except Exception: _tipA = None
        try: _tipB = rpc("getbestblockhash", [], RPC_URL_110, RPC_AUTH_110)
        except Exception: _tipB = None
        if _prevf and _tipB and _prevf == _tipB:
            node_url, node_auth, chain, node_tip = RPC_URL_110, RPC_AUTH_110, "bip110", _tipB
        elif _prevf and _tipA and _prevf == _tipA:
            node_url, node_auth, chain, node_tip = RPC_URL, RPC_AUTH, "legacy", _tipA
        else:
            chain, node_url, node_auth, node_tip = "legacy", RPC_URL, RPC_AUTH, _tipA   # default majority
            if _prevf:
                try: knB = bool(rpc("getblockheader", [_prevf], RPC_URL_110, RPC_AUTH_110))
                except Exception: knB = False
                try: knA = bool(rpc("getblockheader", [_prevf]))
                except Exception: knA = False
                if knB and not knA:   # conocido por la fork y NO por majority → template bip110
                    chain, node_url, node_auth, node_tip = "bip110", RPC_URL_110, RPC_AUTH_110, _tipB
        base["chain"] = chain
        # Un template clasificado bip110 DEBE tener bits de dificultad blake2b (exp del compact ≥ 0x19,
        # p.ej. 1a008d4f). Si trae bits SHA256 (exp 0x17, p.ej. 1702353d) el nodo NO está en la fork:
        # es un template SHA256 (a menudo stuck en 961639/shared-prev) posando de bip110 → RECHAZAR. Esto
        # cierra el hueco del stale-skip (impostores que pisaban el template blake2b de un supplier real).
        if chain == "bip110":
            try: _exp = int(str(tmpl.get("bits", ""))[:2], 16)
            except Exception: _exp = 0
            if 0 < _exp < 0x19:
                print(f"[reject not-blake2b] {ip} user={user} bits={tmpl.get('bits')}", flush=True)
                return finish("reject", "not-blake2b", f"bip110 template has SHA256-range bits ({tmpl.get('bits')}) — your node is not on the BLAKE2b fork")
        print(f"[chain] {ip} user={user} -> {chain} prev={_prevf[:12]}", flush=True)
        # ── DATUM-TS: publicación FIRMADA (ship-dark: env DATUM_TS_VERIFY=1 la activa). Address REGISTRADA
        # (datum_ts_registry.json) → DEBE firmar con su key (impersonación imposible); NO registrada → legacy
        # como hoy. Va ANTES del spam/proposal: un impostor no consume RPC. Fail-open del módulo (nunca tira
        # el ingest). Ver datum_ts_verify.py + ~/datum-ts-poc (PoC #3). 2026-09-03.
        _dts = None
        if os.environ.get("DATUM_TS_VERIFY", "0") == "1":
            try:
                import datum_ts_verify
                _st, _why, _dts = datum_ts_verify.verify_publication(tmpl, user, chain)
            except Exception as _e:
                _st, _why, _dts = "legacy", None, None
                print(f"[datum-ts error] {ip} user={user} {_e!r}", flush=True)
            if _st == "reject":
                print(f"[reject datum-ts] {ip} user={user} {_why}", flush=True)
                return finish("reject", "datum-ts", _why)
            if _st == "verified":
                print(f"[datum-ts verified] {ip} user={user}", flush=True)
        bad = first_spam([t["data"] for t in alltxs][:MAXTX], node_url, node_auth)
        if bad:
            print(f"[reject spam] {ip} user={user} tx[{bad[0]}] {bad[1]}", flush=True)
            return finish("reject", "spam", f"tx[{bad[0]}] non-monetary: {bad[1]}")
        # OP_RETURN / datacarrier gate — parseo directo de outputs (todas las txs; barato). Un template
        # soberano (node con datacarrier=0) no debería traer ninguna. Detecta lo que el spam-gate deja pasar.
        spm = first_spam_output([t["data"] for t in alltxs])
        if spm is not None:
            _i, _r = spm
            print(f"[reject {_r}] {ip} user={user} tx[{_i}]", flush=True)
            _hint = ("set your node's datacarrier=0" if _r == "op_return"
                     else "set permitbaremultisig=0")
            return finish("reject", _r, f"tx[{_i}] carries a {_r} datacarrier — {_hint} for a spam-free / sovereign template")
        # gate 4 — el template completo forma un bloque consenso-válido? (proposal → null).
        # SOLO chequeamos si el template está sobre NUESTRO tip actual. Si es stale (prevhash != tip,
        # típico en la transición de bloque) el proposal fallaría espuriamente → lo saltamos; el flag
        # `stale` + HOLD ya evita servirlo. Dedup por HASH del CONTENIDO REAL validado (prevhash + cbval +
        # witness-commitment + data de TODAS las txs), NO por (prevhash, ntxs): un atacante podía postear
        # un template válido y luego uno malicioso con el mismo prevhash y ntxs pero txs distintas → el
        # dedup saltaba el proposal → bloque inválido servido. El hash re-valida ante CUALQUIER cambio.
        _prev = _prevf
        is_stale = (node_tip is None) or (_prev != node_tip)   # tip del nodo de SU cadena; nodo caído → stale/HOLD (#1)
        # Dedup por HASH del CONTENIDO REAL (#2): version/bits/height/curtime/ntx + prevhash+cbval+witness+
        # data de TODAS las txs. Antes omitía version/bits/height/curtime/ntx → un template mutado (p.ej.
        # bits=min-diff o height falso, mismas txs) daba el MISMO hash → se saltaba el proposal → trabajo
        # inválido servido. Ahora cualquier mutación re-dispara el proposal.
        _cont = (str(_prev) + str(tmpl.get("coinbasevalue","")) + str(tmpl.get("default_witness_commitment","")) +
                 str(ver) + str(tmpl.get("bits","")) + str(tmpl.get("height","")) + str(tmpl.get("curtime","")) +
                 str(len(alltxs)) + "".join(t.get("data","") for t in alltxs))
        _ck = hashlib.sha256(_cont.encode()).hexdigest()
        if not is_stale and _last_ok.get(user) != _ck:
            pok = proposal_ok(tmpl, node_url, node_auth, ["segwit","blake2b"] if chain == "bip110" else ["segwit"])
            if pok is False:
                print(f"[reject proposal] {ip} user={user} chain={chain} height={tmpl.get('height')}", flush=True)
                return finish("reject", "invalid-block", f"template does not form a consensus-valid {chain} block (proposal check failed)")
            if pok is None:
                # FAIL-CLOSED (#1): no pudimos validar (nodo/RPC/deserialización) → NO servir. HOLD, no accept.
                print(f"[hold unverified] {ip} chain={chain} height={tmpl.get('height')}", flush=True)
                cache_live(user, tmpl, name, hold=True, url=node_url, auth=node_auth, chain=chain)
                return finish("reject", "unverified", "could not verify consensus-validity (node RPC error) — held, not served")
            _last_ok[user] = _ck   # pok True → validado POSITIVO (único camino que habilita servir)
        # Se llega acá sólo si: stale (cache_live lo marca stale→HOLD) o validado-True → servir.
        print(f"[accept] {ip} chain={chain} {len(alltxs)} txs 0x{ver:08x}", flush=True)
        cache_live(user, tmpl, name, url=node_url, auth=node_auth, chain=chain, datum_ts=_dts)   # v1: template completo + nombre + chain (+ datum_ts si firmada)
        finish("accept", "passed")

if __name__ == "__main__":
    print("PyBLOCK HTTP declare escuchando en http://0.0.0.0:5800/ (mainnet)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 5800), H).serve_forever()
