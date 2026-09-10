# PULSAR — el reloj de la flota

`pyblock-node-broker`. Un solo interlocutor RPC entre Node B (BLAKE2b) y toda la flota de gateways DATUM de PyBLØCK.

Como un púlsar, emite un pulso regular hacia todos: consulta la punta del nodo cada 250 ms y, cuando cambia,
avisa (`/NOTIFY`) a cada gateway en el mismo milisegundo. Los gateways no cambian de código: hablan el mismo
JSON-RPC de bitcoind, solo apuntan su `rpcurl` a `127.0.0.1:8352`.

## Por qué existe
69 gateways preguntaban al nodo una vez por segundo si había cambiado la punta (4.140 llamadas/min, el 95 % de la
carga) y disparaban un `getblocktemplate` idéntico en ráfaga tras cada bloque. El coste por llamada era trivial;
lo que ahogaba al nodo era la contención de la cola RPC: 665-1.219 rechazos por hora.

Con PULSAR: la punta se sirve de memoria (0 llamadas al nodo), un solo template sirve a todos los gateways,
y el nodo ve ~60 llamadas/min en vez de ~4.350. Plano al crecer el número de suppliers.

## Reglas de seguridad (van antes que el rendimiento)
1. **Fail-open**: ante cualquier duda, la llamada va al nodo.
2. Jamás se sirve un template cuyo `previousblockhash` no sea la punta actual. Además TTL duro (3 s).
3. `submitblock`, `preciousblock` y cualquier otro método: passthrough literal. Nunca cacheado, nunca
   deduplicado, nunca un "éxito" inventado; el error del nodo viaja con cuerpo y status idénticos.
4. Solo se sirve de caché a quien presenta las credenciales correctas; si no, va al nodo.

## Operación
- Unidad: `pyblock-node-broker.service` · config `/etc/pyblock/node-broker.json` · estado `curl -s http://127.0.0.1:8352/stats`.
- Destinos de `/NOTIFY`: lista fija (`notify_urls`) ∪ descubiertos en `notify_ports_dir` (`*.port` + `notify_port_offset`).
- Reversión de un gateway: apuntar su `rpcurl` al nodo (`tmpl_providers/<addr>.rpcurl` = `127.0.0.1:8342` para los per-supplier) y reiniciar su unit.
- Build offline: `cargo build --offline --release`.

© PyBLØCK
