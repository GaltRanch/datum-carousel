# DATUM-TS — fork de datum_gateway con comisiones para Template Suppliers

Diseño v0 · 2026-09-03 · para Curly + Kilombino. Objetivo: **protocolo de templates EXCLUSIVO para
Bitcoin-BLAKE2b donde el node-runner que APORTA la plantilla cobre una comisión en el coinbase — no solo
el minero.** Base conceptual = `datum_gateway` de OCEAN (github.com/OCEAN-xyz/datum_gateway, Jason Hughes),
llevado a blake2b sobre el tooling que ya corre (`datum_gateway_tmpl` + Carousel + ingest). Combina la
soberanía de DATUM (el bloque no lo dicta el pool) con la economía de Template Suppliers.

## Estado (2026-09-03) — hasta dónde llegamos
- **Decisión de cadena: EXCLUSIVO blake2b** (cerrada).
- **PoC #1 — commitment verificable ✅** (`~/datum-ts-poc/poc_commitment.py`): prueba la propiedad central
  (pool = relay, no fuente de confianza). Ataques probados y rechazados: swap · censura · robo del 1% ·
  commitment forjado. Cripto: blake2b + secp256k1.
- **PoC #2 — commitment sobre Stratum v1 ✅** (`poc_stratum.py`): viaja en `mining.notify` + notif vendor
  `pyblock.tcommit`, NO rompe mineros vanilla, el gateway DATUM-TS detecta el skim/swap que el vanilla mina
  a ciegas. Validó que el commitment ata lo INVARIANTE (coinb1/coinb2/branch), no el merkle_root (que varía
  con extranonce2).
- **PoC #3 — supply-mode ✅** (`poc_supply.py`): el node-runner publica y FIRMA su template al ingest
  SIN hashrate. Publicación AUTENTICADA (impersonación bajo la address de otro → rechazada: resuelve el
  hueco real de hoy, el ingest no autentica X-PyBLOCK-User), limpieza datacarrier=0 y dedupe lado-pool,
  guardado en la forma template_live + `datum_ts{commitment,sig,pubkey}` para que el Carousel lo sirva.
  Commitment **chain-agnóstico** probado (mismo flujo con sha256d).
- **Decisión CONFIRMADA por Curly (2026-09-03):** *fork blake2b + commitment chain-agnóstico*.
- **Split CERRADO (Curly 2026-09-03, tras review v0.2): 96 finder / 3 supplier / 1 pool — de BOOTSTRAP.**
  Objetivo con masa crítica: volver a 98/1/1. Es un knob (`template_supplier_bps` 100→300), número+restart.
- **✅ 96/3/1 YA VIVE EN PRODUCCIÓN (Carousel blake2b :30110, 23:34)** — config + restart + copy pública
  actualizada (carousel, suppliers, rentals, whitepapers, inspect config-driven; block.php y el bot derivan
  el split del coinbase real). Per-supplier :22xxx y LOTTO quedan como estaban (decisión pendiente).
- **#4 (inyección en el coinbase) — YA VIVE EN PRODUCCIÓN.** El Carousel de hoy inyecta supplier + pool:
  config `template_supplier_bps=100`, `template_pool_bps=100`, `pool_address=1PyBLoCK…`. Prueba on-chain,
  bloque **966542**: coinbase con 3 outputs = 98.00% finder · 1.00% supplier (bc1q8gzzy… libertad2140) ·
  1.00% pool. **No hay que construir la inyección: existe.**
- **Roadmap RE-ESCOPEADO — lo que queda es INTEGRACIÓN (toca componentes de producción):**
  (a) `datum_gateway_tmpl` (C): emitir `pyblock.tcommit` (C+firma) junto al `mining.notify` [PoC #2];
  (b) ✅ **DESPLEGADO ship-dark (2026-09-03)** — ingest `pyblock_http_server.py` + módulo
      `datum_ts_verify.py`: registro address→pubkey + verificación de firma en la publicación. Regla de
      compatibilidad: address REGISTRADA → debe firmar con su key (impersonación → reject); NO registrada →
      legacy sin firma (nadie se rompe). Hook antes del spam/proposal (impostores no consumen RPC),
      fail-open del módulo. Guarda `datum_ts{commitment,sig,pubkey,chain}` en template_live/*.json.
      **APAGADO por flag:** `DATUM_TS_VERIFY=0` en `/etc/pyblock/template-ingest.env` → `=1` + restart activa.
      **Registrar supplier:** `/var/www/pyblock/data/datum_ts_registry.json` = `{"<addr>": "<pubkey_hex>"}`.
      El supplier manda `"_datum_ts": {commitment, sig, pubkey}` en el JSON del template (como `_user`).
      Unit-test 5/5 OK · restart verificado (suppliers siguen [accept] en ambas cadenas).
  (c) end-to-end en un gateway de **STAGING** (puerto de test, NO el :30110 vivo): template firmada →
      servida con commitment → minada → coinbase on-chain == commitment.

## El gap que resolvemos
DATUM paga por *shares* (TIDES): el que provee la plantilla ganadora **no cobra nada extra por proveerla**.
("Encontramos 3 bloques SHA256 y no ganamos un carajo" — salió nuestra template, cero comisión.)
DATUM-TS mete un **output de comisión al supplier en el coinbase de ESE bloque**, on-chain, per-block.

## Lo que se MANTIENE de DATUM (no reinventar)
- La plantilla la arma un **nodo real** (GBT), con política limpia (`datacarrier=0`) — el pool NO dicta txs.
- **No-custodial**: el pago son outputs del coinbase, on-chain, en el bloque encontrado.
- Stratum v1 a los mineros; submit de soluciones al pool. SOLO fallback / `always_pay_self`.
- Compatibilidad con el protocolo DATUM donde se pueda (que un minero DATUM estándar pueda conectarse).

## Lo NUEVO (3 piezas)

### 1. Desacoplar los dos roles (DATUM asume minero == nodo)
- **Supplier mode**: el node-runner corre el gateway en modo "aporte" → **publica su template, sin hashrate**.
- **Miner mode**: apunta hashrate, recibe la template de un supplier (rotada), la mina.
- Un minero con su propio nodo = DATUM clásico (supplier+miner en uno) → sigue soportado.

### 2. Split del coinbase (lo construye el pool, va en el bloque)
- **Bootstrap:** Finder (minero): **96%** · Supplier (cuya template ganó): **3%** · Pool: **1%**.
  (Objetivo con masa crítica: 98 / 1 / 1. El pool mantiene su 1% en ambos.)
- Sub-dust → pool. Se escribe directo en el coinbase del bloque ganado (igual que Carousel hoy).

#### ★ La POOL también cobra — y está garantizado, no declarado (Curly 2026-09-03)
El 1% del pool está protegido por 3 capas, simétricas a las del supplier:
1. **El pool construye el coinbase** (coinb1/coinb2). El supplier aporta txs, NO arma el coinbase → no
   puede omitir el output del pool.
2. **El supplier firma el commitment sobre ese split** (con el 1% del pool adentro). Una template sin el
   cut del pool → **rechazada en el ingest** antes de servirse.
3. **El minero verifica que el output del pool esté** (política `pool_addr` presente — PoC #1/#2:
   "falta el fee del pool" → RECHAZA). Ni el minero puede minar un bloque que saltee al pool.
→ Nadie puede sacar el 1% del pool sin romper la verificación. En PoC #4 el gateway inyecta AMBOS outputs
  (supplier + pool) en el coinbase real.

### 3. ★ Commitment de la template — la pieza que le GANA a DATUM (trustless)
El agujero de "servir templates de terceros" es que el minero tiene que **confiar** en que el pool le
sirve la template limpia del supplier y no una inyectada/censurada. DATUM lo evita porque el minero
arma su propio bloque. Para igualarlo:
- Cada template del supplier lleva un **commitment**: `C = hash(merkle_root ‖ supplier_id ‖ coinbase_split)`,
  **firmado por el supplier** (clave asociada a su address de pago).
- El pool le sirve al minero el job **con `C` + la firma del supplier**.
- El **gateway del minero VERIFICA**: (a) el merkle_root que está minando == el commiteado; (b) el coinbase
  trae el split acordado (finder+supplier+pool). Si no coincide → rechaza el job.
- Resultado: el pool es un **relay/matchmaker**, NO una fuente de confianza. No puede swapear la template
  ni robarle el 1% al supplier sin que el minero lo detecte. **Eso es "DATUM sin confianza" + "el
  node-runner cobra" — lo que ni DATUM ni un pool normal dan solos.**

## Registro de suppliers + anti-spam (formalizar lo que ya tenés)
- Supplier se registra: address = identidad de pago + clave para firmar el commitment.
- **Rate-limit** de submissions por supplier; **dedupe** de templates idénticas (que uno no floodee para
  farmear "papeletas" — la preocupación de Kilombino).
- **Peso de rotación NO por cantidad de templates** (mata el incentivo a spamear). Opciones: uniforme, o
  ponderado por uptime/reputación del supplier (anti-sybil). El "sorteo" de Kilombino = draw ponderado de
  qué supplier ocupa el próximo slot. (Nota: el sorteo de HASHRATE entre participantes ya existe = CHIRP.)

## Modelo de confianza (honesto, para responder a los críticos)
- **Minero**: no confía en nadie más allá de verificar el commitment (§3). Pago no-custodial.
- **Supplier**: confía en que le paguen el 1% → **imposible de robar** porque va en el coinbase que el
  minero verifica.
- **Pool**: matchmaker + rotación + anti-spam. No censura/inyecta sin ser detectado; no skimea.

## Alcance del fork (qué tocar de verdad)
Lado **gateway (datum_gateway)**:
- Agregar `supply mode` (publica template, no mina).
- Verificación del commitment en el job de stratum (campo extra que el gateway del minero chequea).
Lado **pool**: ya lo tenés casi entero (Carousel + ingest + registro + anti-spam + split del coinbase).
Falta: firmar/servir el commitment, e inyectar el output del supplier en la negociación del coinbase DATUM.

## Alcance de cadena — DECIDIDO: **EXCLUSIVO BLAKE2b** (Curly, 2026-09-03)
NO sale a SHA256/Bitcoin. Es el protocolo NATIVO de la economía de templates de **Bitcoin-BLAKE2b**.
Implicancias:
- Se construye sobre el tooling blake2b que YA existe (`datum_gateway_tmpl` + Carousel + ingest), no sobre
  el datum_gateway SHA256 de OCEAN — el fork agrega supply-mode + verificación de commitment ahí.
- No compite con OCEAN en Bitcoin ni queda expuesto a "sos un fork de OCEAN" → historia limpia.
- **Flywheel de ecosistema**: node-runner cobra → más razón para correr nodo blake2b → más suppliers →
  más bloques limpios → más razón para minar blake2b (crece los ~666 nodos blake2b actuales).
- Trade honesto: NO gana mindshare en el DATUM de Bitcoin (los maxis SHA256 no lo adoptan). Es un
  constructor de ecosistema blake2b, no una jugada de protocolo Bitcoin. El pitch = "Bitcoin-BLAKE2b
  tiene una economía de templates que DATUM no da" (NO "mejoramos DATUM para Bitcoin").

## Decisiones abiertas (para vos + Kilombino)
1. ~~Split~~ → **RESUELTO: 96 / 3 / 1 de bootstrap** (Curly, tras review v0.2). El 3% al supplier arranca el
   flywheel (uniforme entre S → 3%/S); con masa crítica se baja a 98/1/1 (knob `template_supplier_bps`).
2. ~~Peso de rotación / sybil~~ → **RESUELTO (review v0.2):** uniforme + identidad anclada a **liveness de
   nodo** + **dedupe de slots por CONTENIDO de template** (1 nodo = 1 slot aunque use N addresses). Sin
   KYC/bond. Reputación/uptime como peso, en v1.
3. Cómo firma el supplier el commitment (clave separada vs derivada de la address).
4. ~~SHA256 vs blake2b~~ → **RESUELTO: blake2b exclusivo.**

## Feedback de Kilombino incorporado (2026-09-03)
- **Es varianza SOLO** (el finder cobra 98% de SU bloque) — NO suaviza pagos. Resuelve "quien arma el
  bloque cobra + trustless", no PPLNS. Para pagos suaves → combinar con **CHIRP** (lotería de hashrate,
  ya existe). Comunicarlo así, no sobre-vender.
- **Firma del commitment**: v0 = **clave registrada separada** (simple). v1 = derivada de la address
  (bech32 → **BIP322**, más curro).
- **Anti-sybil de la rotación** (problema genuinamente difícil sin KYC): v0 = **uniforme + anti-spam
  actual (rate-limit + dedup) + cap de slots por identidad**. Bond 1-de-2 multisig SOLO si aparece abuso
  real (agrega fricción → menos suppliers, contra el flywheel; no meterlo antes de tener el problema).
- **Validación de limpieza = lado-pool (load-bearing).** En SV1 el minero NO puede verificar limpieza
  (solo tiene `merkle_branch`, no las txs). La limpieza la garantiza el **ingest (datacarrier=0, ya
  validado)** + el supplier la firma en el commitment. Trustless total de limpieza = darle la template
  completa al minero (trade-off ancho de banda; evaluar en v1).
- **PoC #2 validó** un punto fino de SV1: el extranonce2 varía el merkle_root por-share → el commitment
  ata coinb1/coinb2/merkle_branch (lo INVARIANTE), no el root. Se verifica 1 vez por job.

## Upstream vs fork — RECONCILIAR con la decisión blake2b-exclusiva
Kilombino recomienda PR upstream a OCEAN primero. **PERO** OCEAN datum_gateway = SHA256/Bitcoin, y la
decisión es blake2b-exclusivo → **no se puede upstreamear una feature blake2b a un gateway de Bitcoin.**
Resolución: **fork blake2b (se mantiene la decisión de Curly)**, PERO diseñar el esquema de commitment
**chain-agnóstico** (lo único que cambia entre cadenas es la función de hash) → deja la OPCIÓN de proponerlo
upstream/SHA256 más adelante sin rehacer, sin atar el v0 a que OCEAN lo acepte.

## Review v0.2 de Kilombino (2026-09-03) — incorporado
Veredicto: "v0.2 es defendible; los PoCs quitan el riesgo técnico gordo". Tres puntos a apretar:

**1. Sybil NO cerrado, solo aplazado — y el flywheel EMPEORA el incentivo** (si el node-runner cobra,
hay dinero por identidad; "cap por identidad" es sybil-able: N addresses = N caps). Anclaje natural
gratis: ser supplier exige **un nodo real produciendo templates frescos y válidos (GBT)** → N nodos
sincronizados cuesta mucho más que N addresses. **Adoptado + refinado:**
- Identidad = **liveness de nodo** (templates frescos, válidos, continuos — el ingest YA lo mide: uptime
  por supplier + proposal check + prevhash==tip).
- **Hueco que la liveness sola no cierra:** un solo nodo puede publicar la MISMA template bajo N addresses.
  **Cierre: dedupear los slots de rotación por CONTENIDO de template (tx-set/merkle), no por address** —
  misma template = mismo nodo = un solo slot. Sybilar pasa a costar nodos independientes con templates
  distintas. Sin KYC ni bond. (Reemplaza el "cap de slots por identidad" de la v0.1.)

**2. Tamaño del incentivo al supplier.** Con rotación uniforme entre S suppliers, cada uno espera **1%/S**
del reward por bloque → migaja con muchos suppliers → pocos suppliers → no despega. Propuesta: **más al
supplier al principio (2–3%) para arrancar el flywheel, bajar con masa crítica.** Nota clave: es un **knob
de config** (`template_supplier_bps` del carousel, hoy 100 = 1%) → "arrancar alto, bajar después" es un
número + restart, sin código. **Decisión de Curly pendiente** (había cerrado 98/1/1 antes de este review).

**3. Precisión del trust ante críticos (adoptado como wording oficial):** el commitment garantiza
no-swap / no-skim (trustless de verdad contra el pool). Pero la **validez de consenso** (doble-gastos,
fees, txs válidas) y la **limpieza** dependen del ingest del pool en SV1. Wording: *"trustless contra el
pool; validez y limpieza garantizadas por el ingest hasta v1 (plantilla completa al minero)"*. Matiz a
favor: el ingest hace **proposal check fail-closed** antes de servir → una template inválida NO llega al
minero (se frena en el ingest); lo que sigue siendo confianza es que el ingest lo haga.

## Posicionamiento y público objetivo
Contribución de protocolo real (no truco de pool) **para Bitcoin-BLAKE2b**: "DATUM + comisión al proveedor
de template + verificabilidad de la template". Creditear a DATUM/Jason Hughes como base conceptual.
**Público objetivo (explícito, de Kilombino):** esto NO es para el minero que ya tiene nodo (ese solo-minea
al 100%). Es para **HASHRATE SIN NODO que quiere minar limpio, soberano y no-custodial sin montar infra —
a cambio de un 2%** (1% supplier + 1% pool). Eso hoy no lo da nadie. Ese es el mercado.
