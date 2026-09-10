# PULSAR = pyblock-node-broker (nombre elegido por Curly 2026-09-09).
#!/bin/bash
# Una línea de estado para el despliegue del broker: cuántos gateways ya van por 8352 vs 8342,
# rechazos de la cola RPC del nodo en la hora en curso y en la anterior, y contadores del broker.
L=/home/curly/bip110-node/data/debug.log
H=$(date -u +%Y-%m-%dT%H); HP=$(date -u -d '-1 hour' +%Y-%m-%dT%H)
r_now=$(grep -a "^$H" "$L" 2>/dev/null | grep -c 'work queue depth exceeded')
r_prev=$(grep -a "^$HP" "$L" 2>/dev/null | grep -c 'work queue depth exceeded')
gw_broker=$(ss -tnp 2>/dev/null | grep -E 'datum_gateway_t|chirp_gateway' | grep -c ':8352')
gw_node=$(ss -tnp 2>/dev/null | grep -E 'datum_gateway_t|chirp_gateway' | grep -c ':8342')
b=$(curl -s -m 3 http://127.0.0.1:8352/stats | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin); s=d['served']; n=d['node']
    print('tip_cache=%s gbt_cache=%s gbt_fetch=%s pass=%s node_calls=%s err=%s tips=%s' % (s['tip_from_cache'],s['gbt_from_cache'],s['gbt_fetched'],s['passthrough'],n['calls'],n['errors'],n['tip_changes']))
except Exception as e: print('broker sin respuesta')" 2>/dev/null)
echo "$(date '+%H:%M') conexiones gateway→broker=$gw_broker gateway→nodo=$gw_node | rechazos nodo: hora_actual=$r_now hora_previa=$r_prev | broker: $b"
