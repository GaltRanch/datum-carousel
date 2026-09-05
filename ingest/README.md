# Template ingest

`pyblock_http_server.py` is the HTTP endpoint (port 5800) where Template Suppliers POST their
`getblocktemplate` output (JSON, optionally gzip). It is the **only** writer of `template_dir`
(`template_live/<address>.json`), and the gateway only serves caches that carry its validation stamp.

Gates, in order (a template is cached only if it passes all of them):

1. **Shape / address** — payout address in the `user` field (P2PKH / bech32), sane sizes (anti zip-bomb).
2. **Spam gate** — a first-line sample of the transactions through `testmempoolaccept`; a rejection for a
   *policy* reason (scriptpubkey / datacarrier / bare-multisig) marks the template as spam.
3. **`datacarrier=0` gate** — every output of every transaction is parsed; any OP_RETURN or
   bare-multisig data carrier rejects the template (sovereign templates come from nodes with
   `datacarrier=0`).
4. **Node proposal check** — `getblocktemplate {"mode":"proposal","data":<block>}` on the pool's own
   node: the node decides whether the template forms a consensus-valid block (transactions, fees vs.
   declared `coinbasevalue`, witness commitment…). Fail-closed: if the node cannot be reached the
   template is held, not served.
5. **Stale / tip** — a template whose `previousblockhash` is not the node's tip is cached with
   `stale: true` (never served); it is re-checked when the supplier republishes at the new tip.
6. **DATUM-TS (optional, `DATUM_TS_VERIFY=1`)** — `datum_ts_verify.py`: the publication must be signed
   by the key registered for that address (commitment over addr, height, prevhash, txids root).

Only after 1–5 (and 6 when enabled) the cache is written atomically with
`validated: {proposal: true, datacarrier: true, ts, tip}`. Credentials come from the environment
(`RPC_URL`, `RPC_USER`, `RPC_PASS`; `RPC_URL_110`… for a second chain) — nothing is hard-coded.

Run: `RPC_URL=http://127.0.0.1:8332/ RPC_USER=… RPC_PASS=… PYBLOCK_LIVE=/path/to/template_live python3 pyblock_http_server.py`
