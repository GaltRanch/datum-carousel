# DATUM-TS — Proof of Concept

Fork blake2b-exclusivo de DATUM donde el **template supplier cobra** + el minero **verifica** la template.
Diseño completo: `~/pyblock-android-docs/DESIGN_datum_ts_fork.md`.

## PoC #1 — Commitment de template verificable ✅ (esta)
`python3 poc_commitment.py`

Prueba la propiedad CENTRAL (la que le gana a DATUM): **el pool es un relay, no una fuente de confianza.**
El supplier firma un commitment de su template; el minero verifica —antes de minar— que el trabajo es esa
template exacta, limpia, con el split (finder/supplier/pool) intacto. Ataques probados y rechazados:
swap de template · censura · robo de la comisión del supplier · commitment forjado.

Cripto: **blake2b** (hash de la cadena, nativo) + **secp256k1** (`ecdsa`, la misma curva de las llaves
Bitcoin del supplier). Sin infra: corre en 1 archivo.

### Qué está mockeado (y qué es real en producción)
| PoC | Producción |
|---|---|
| merkle/txids simplificados | header blake2b v2 real + merkle del template GBT |
| `addr = hash(pubkey)[:20]` | address Bitcoin real del supplier = su identidad de pago |
| firma sobre commitment con key random | el supplier firma con la key de SU address |
| verificación en función `verify_job()` | verificación en el gateway del minero (datum_gateway_tmpl) |
| split hardcodeado 98/1/1 | negociado + inyectado en el coinbase por el pool |

Lo que es REAL y transferible tal cual: el **esquema de commitment** `C = blake2b(TAG ‖ merkle_root ‖
supplier_id ‖ clean)` firmado por el supplier, y la **lógica de verificación** de 4 pasos.

## Roadmap de PoCs
- **#1 commitment** ✅ — la propiedad de seguridad (esto).
- **#2 stratum** ✅ (`poc_stratum.py`): `C`+firma viajan en `mining.notify` + notif vendor `pyblock.tcommit`;
  NO rompe mineros vanilla; el gateway DATUM-TS detecta skim/swap que el vanilla mina a ciegas. Ata lo
  INVARIANTE (coinb1/coinb2/branch), no el merkle_root (varía con extranonce2).
- **#3 supply-mode** ✅ (`poc_supply.py`): node-runner publica + FIRMA su template al ingest, sin hashrate.
  Publicación autenticada (impersonación → rechazada), limpieza + dedupe lado-pool, guardado compatible
  con template_live (+ `datum_ts{commitment,sig,pubkey}`). Chain-agnóstico (blake2b / sha256d).
- **#4 coinbase**: inyectar el output del supplier (1%) en la construcción del coinbase del gateway +
  confirmar el pago on-chain en un bloque de test.

Decisiones abiertas (ver diseño): split exacto · peso de rotación anti-sybil · cómo firma el supplier.
