//! PULSAR (pyblock-node-broker) — el reloj de la flota: un solo interlocutor del nodo para todos los gateways.
//! Como un púlsar, emite un pulso regular hacia todos: consulta la punta cada 250 ms y, al cambiar, avisa a cada gateway.
//!
//! Problema que resuelve: 69 gateways preguntan cada uno 1 vez por segundo si cambió la punta
//! (4.140 getbestblockhash/min = 95 % de la carga RPC del nodo) y disparan un getblocktemplate
//! idéntico cada 20 s y en ráfaga al llegar cada bloque. El coste por llamada es trivial; lo que
//! mata es la contención de la cola RPC.
//!
//! Qué hace: se pone delante del nodo hablando el MISMO JSON-RPC, así los gateways no cambian de
//! código (solo su `rpcurl`). Cachea las dos llamadas de LECTURA y deja pasar todo lo demás intacto.
//!
//! Reglas de seguridad (van antes que el rendimiento):
//!   1. Fail-open: ante cualquier duda, la llamada va al nodo.
//!   2. Jamás se sirve un template cuyo previousblockhash no sea la punta actual. Además TTL duro.
//!   3. submitblock / preciousblock / cualquier otro método: passthrough literal. Nunca cacheado,
//!      nunca deduplicado, nunca un "éxito" inventado. Si el nodo falla, el error viaja tal cual.
//!   4. Solo se sirve de caché a quien presenta las credenciales correctas; si no, va al nodo.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

#[derive(Clone)]
struct Cfg {
    listen: String,
    upstream: SocketAddr,
    auth: String,
    poll_ms: u64,
    gbt_ttl_ms: u64,
    tip_max_age_ms: u64,
    threads: usize,
    notify_urls: Vec<String>,
    /// Descubrimiento dinámico de destinos /NOTIFY: cada fichero `<dir>/*.port` es un supplier vivo
    /// (registro del reconciliador); su API escucha en puerto + `notify_port_offset`. Se relee en cada
    /// cambio de punta, así un supplier nuevo recibe el aviso sin tocar la config ni reiniciar el broker.
    notify_ports_dir: String,
    notify_port_offset: u32,
    timeout_ms: u64,
}

fn b64(input: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// POST JSON-RPC al nodo. Devuelve (status, cuerpo). Un fallo de transporte es Err — nunca se
/// convierte en un "ok" vacío (ese fue justo el bug de submitblock en DATUM).
fn node_post(cfg: &Cfg, auth: &str, body: &str) -> Result<(u16, String), String> {
    let to = Duration::from_millis(cfg.timeout_ms);
    let mut s = TcpStream::connect_timeout(&cfg.upstream, to).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(to)).ok();
    s.set_write_timeout(Some(to)).ok();
    s.set_nodelay(true).ok();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        cfg.upstream, auth, body.len(), body
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("respuesta sin cabeceras")?;
    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("status ilegible")?;
    Ok((code, String::from_utf8_lossy(&buf[pos + 4..]).to_string()))
}

struct Gbt {
    params_key: String,
    prevhash: String,
    result: String,
    at: Instant,
}

struct State {
    tip: Option<String>,
    tip_at: Instant,
    /// Epoch ms del momento en que se adoptó la punta actual: referencia con resolución real para
    /// medir "bloque nuevo → job nuevo" (el debug.log del nodo solo tiene segundos enteros).
    tip_adopted_ms: u64,
    gbt: Option<Gbt>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

struct Stats {
    tip_cache: AtomicU64,
    tip_miss: AtomicU64,
    gbt_cache: AtomicU64,
    gbt_fetch: AtomicU64,
    passthrough: AtomicU64,
    node_calls: AtomicU64,
    node_errors: AtomicU64,
    tip_changes: AtomicU64,
}

fn cfg_from(path: &str) -> Cfg {
    // Sin config no se arranca: arrancar con credenciales vacías "en silencio" sería un broker
    // que pasa todo al nodo y no cachea nada, es decir, el problema original disfrazado de solución.
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| { eprintln!("no puedo leer la config {path}: {e}"); std::process::exit(2) });
    let v: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| { eprintln!("config {path} no es JSON válido: {e}"); std::process::exit(2) });
    if v["rpcuser"].as_str().unwrap_or("").is_empty() || v["rpcpassword"].as_str().unwrap_or("").is_empty() {
        eprintln!("config {path}: faltan rpcuser/rpcpassword"); std::process::exit(2);
    }
    let up = v["upstream"].as_str().unwrap_or("127.0.0.1:8342").to_string();
    Cfg {
        listen: v["listen"].as_str().unwrap_or("127.0.0.1:8352").to_string(),
        upstream: up.parse().expect("upstream debe ser ip:puerto"),
        auth: format!(
            "Basic {}",
            b64(format!(
                "{}:{}",
                v["rpcuser"].as_str().unwrap_or(""),
                v["rpcpassword"].as_str().unwrap_or("")
            )
            .as_bytes())
        ),
        poll_ms: v["poll_ms"].as_u64().unwrap_or(1000),
        gbt_ttl_ms: v["gbt_ttl_ms"].as_u64().unwrap_or(3000),
        tip_max_age_ms: v["tip_max_age_ms"].as_u64().unwrap_or(5000),
        threads: v["threads"].as_u64().unwrap_or(24) as usize,
        notify_urls: v["notify_urls"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        notify_ports_dir: v["notify_ports_dir"].as_str().unwrap_or("").to_string(),
        notify_port_offset: v["notify_port_offset"].as_u64().unwrap_or(20000) as u32,
        timeout_ms: v["timeout_ms"].as_u64().unwrap_or(8000),
    }
}

/// Destinos de /NOTIFY = lista fija de la config ∪ descubiertos en `notify_ports_dir` (dedupe).
fn notify_targets(cfg: &Cfg) -> Vec<String> {
    let mut out: Vec<String> = cfg.notify_urls.clone();
    if !cfg.notify_ports_dir.is_empty() {
        if let Ok(rd) = std::fs::read_dir(&cfg.notify_ports_dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if !name.ends_with(".port") { continue; }
                if let Ok(txt) = std::fs::read_to_string(e.path()) {
                    if let Ok(p) = txt.trim().parse::<u32>() {
                        if p > 0 && p + cfg.notify_port_offset < 65536 {
                            out.push(format!("127.0.0.1:{}", p + cfg.notify_port_offset));
                        }
                    }
                }
            }
        }
    }
    out.sort(); out.dedup(); out
}

fn notify_all(urls: &[String]) {
    for u in urls {
        let u = u.clone();
        std::thread::spawn(move || {
            if let Ok(addr) = u.parse::<SocketAddr>() {
                if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
                    s.set_read_timeout(Some(Duration::from_millis(1500))).ok();
                    let _ = s.write_all(
                        format!("GET /NOTIFY HTTP/1.1\r\nHost: {u}\r\nConnection: close\r\n\r\n").as_bytes(),
                    );
                    let mut sink = Vec::new();
                    let _ = s.read_to_end(&mut sink);
                }
            }
        });
    }
}

/// Única puerta para adoptar una punta nueva, venga del poller o de un GBT recién traído.
/// Devuelve true si cambió. Al cambiar: se invalida el template cacheado (regla 2), se cuenta y se
/// avisa en abanico. Si la punta cambiara "en silencio" por una vía y no por otra, la fase 2
/// (/NOTIFY) tendría agujeros: por eso ambas vías pasan por aquí.
fn adopt_tip(state: &Mutex<State>, st: &Stats, cfg: &Cfg, h: &str) -> bool {
    let mut s = state.lock().unwrap();
    let changed = s.tip.as_deref() != Some(h);
    s.tip = Some(h.to_string());
    s.tip_at = Instant::now();
    if changed {
        s.gbt = None;
        s.tip_adopted_ms = now_ms();
        let t = s.tip_adopted_ms;
        drop(s);
        st.tip_changes.fetch_add(1, Ordering::Relaxed);
        let targets = notify_targets(cfg);
        eprintln!("tip {} adoptada en {} ms (notificando a {} gateways)", &h[..16], t, targets.len());
        notify_all(&targets);
    }
    changed
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/etc/pyblock/node-broker.json".into());
    let cfg = Arc::new(cfg_from(&path));
    let state = Arc::new(Mutex::new(State { tip: None, tip_at: Instant::now() - Duration::from_secs(3600), tip_adopted_ms: 0, gbt: None }));
    let fetch_lock = Arc::new(Mutex::new(()));
    let st = Arc::new(Stats {
        tip_cache: AtomicU64::new(0), tip_miss: AtomicU64::new(0),
        gbt_cache: AtomicU64::new(0), gbt_fetch: AtomicU64::new(0),
        passthrough: AtomicU64::new(0), node_calls: AtomicU64::new(0),
        node_errors: AtomicU64::new(0), tip_changes: AtomicU64::new(0),
    });

    // Poller único: UNA consulta de punta por segundo para toda la flota (antes: una por gateway).
    {
        let (cfg, state, st) = (cfg.clone(), state.clone(), st.clone());
        std::thread::spawn(move || loop {
            let body = r#"{"jsonrpc":"1.0","id":"broker","method":"getbestblockhash","params":[]}"#;
            st.node_calls.fetch_add(1, Ordering::Relaxed);
            match node_post(&cfg, &cfg.auth, body) {
                Ok((200, b)) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&b) {
                        if let Some(h) = v["result"].as_str() {
                            if h.len() == 64 { adopt_tip(&state, &st, &cfg, h); }
                        }
                    }
                }
                Ok(_) => { st.node_errors.fetch_add(1, Ordering::Relaxed); }
                Err(_) => { st.node_errors.fetch_add(1, Ordering::Relaxed); }
            }
            std::thread::sleep(Duration::from_millis(cfg.poll_ms));
        });
    }

    let server = Arc::new(tiny_http::Server::http(cfg.listen.as_str()).expect("no pude escuchar"));
    eprintln!("PULSAR (pyblock-node-broker) escuchando en {} → nodo {}", cfg.listen, cfg.upstream);

    let mut hs = Vec::new();
    for _ in 0..cfg.threads {
        let (server, cfg, state, fetch_lock, st) =
            (server.clone(), cfg.clone(), state.clone(), fetch_lock.clone(), st.clone());
        hs.push(std::thread::spawn(move || loop {
            let mut req = match server.recv() { Ok(r) => r, Err(_) => continue };
            let url = req.url().to_string();

            if url.starts_with("/stats") {
                let s = state.lock().unwrap();
                let out = json!({
                    "name": "PULSAR", "role": "broker RPC de Node B para la flota de gateways BLAKE2b",
                    "tip": s.tip, "tip_age_ms": s.tip_at.elapsed().as_millis() as u64,
                    "tip_adopted_ms": s.tip_adopted_ms, "notify_targets": notify_targets(&cfg).len(),
                    "gbt_cached": s.gbt.is_some(),
                    "gbt_age_ms": s.gbt.as_ref().map(|g| g.at.elapsed().as_millis() as u64),
                    "gbt_prevhash": s.gbt.as_ref().map(|g| g.prevhash.clone()),
                    "served": {
                        "tip_from_cache": st.tip_cache.load(Ordering::Relaxed),
                        "tip_passthrough": st.tip_miss.load(Ordering::Relaxed),
                        "gbt_from_cache": st.gbt_cache.load(Ordering::Relaxed),
                        "gbt_fetched": st.gbt_fetch.load(Ordering::Relaxed),
                        "passthrough": st.passthrough.load(Ordering::Relaxed),
                    },
                    "node": {
                        "calls": st.node_calls.load(Ordering::Relaxed),
                        "errors": st.node_errors.load(Ordering::Relaxed),
                        "tip_changes": st.tip_changes.load(Ordering::Relaxed),
                    }
                });
                drop(s);
                let _ = req.respond(json_resp(&out.to_string()));
                continue;
            }

            let auth = req.headers().iter()
                .find(|h| h.field.equiv("Authorization"))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();
            let mut body = String::new();
            if req.as_reader().read_to_string(&mut body).is_err() {
                let _ = req.respond(tiny_http::Response::from_string("bad body").with_status_code(400));
                continue;
            }

            let v: Value = match serde_json::from_str(&body) { Ok(v) => v, Err(_) => Value::Null };
            let method = v["method"].as_str().unwrap_or("");
            let id = v.get("id").cloned().unwrap_or(Value::Null);
            // Regla 4: solo se sirve de caché con las credenciales correctas.
            let authed = auth == cfg.auth;

            let (resp, code): (String, u16) = match (method, authed) {
                ("getbestblockhash", true) => {
                    let s = state.lock().unwrap();
                    let fresh = s.tip.clone().filter(|_| s.tip_at.elapsed() < Duration::from_millis(cfg.tip_max_age_ms));
                    drop(s);
                    match fresh {
                        Some(h) => {
                            st.tip_cache.fetch_add(1, Ordering::Relaxed);
                            (json!({"result": h, "error": Value::Null, "id": id}).to_string(), 200)
                        }
                        None => {
                            st.tip_miss.fetch_add(1, Ordering::Relaxed);
                            passthrough(&cfg, &st, &auth, &body)
                        }
                    }
                }
                ("getblocktemplate", true) => {
                    let pk = v["params"].to_string();
                    let hit = {
                        let s = state.lock().unwrap();
                        cache_hit(&s, &pk, cfg.gbt_ttl_ms)
                    };
                    match hit {
                        Some(r) => {
                            st.gbt_cache.fetch_add(1, Ordering::Relaxed);
                            (json!({"result": serde_json::from_str::<Value>(&r).unwrap_or(Value::Null),
                                   "error": Value::Null, "id": id}).to_string(), 200)
                        }
                        None => {
                            // Un solo hilo va al nodo; los demás esperan y releen la caché ya llena.
                            let _g = fetch_lock.lock().unwrap();
                            let hit2 = { let s = state.lock().unwrap(); cache_hit(&s, &pk, cfg.gbt_ttl_ms) };
                            if let Some(r) = hit2 {
                                st.gbt_cache.fetch_add(1, Ordering::Relaxed);
                                (json!({"result": serde_json::from_str::<Value>(&r).unwrap_or(Value::Null),
                                       "error": Value::Null, "id": id}).to_string(), 200)
                            } else {
                                st.gbt_fetch.fetch_add(1, Ordering::Relaxed);
                                st.node_calls.fetch_add(1, Ordering::Relaxed);
                                match node_post(&cfg, &auth, &body) {
                                    Ok((200, b)) => {
                                        if let Ok(rv) = serde_json::from_str::<Value>(&b) {
                                            if let Some(ph) = rv["result"]["previousblockhash"].as_str() {
                                                // El nodo es la autoridad sobre la punta: si el GBT trae una
                                                // punta nueva, se adopta por la misma puerta que el poller.
                                                adopt_tip(&state, &st, &cfg, ph);
                                                let mut s = state.lock().unwrap();
                                                s.gbt = Some(Gbt {
                                                    params_key: pk,
                                                    prevhash: ph.to_string(),
                                                    result: rv["result"].to_string(),
                                                    at: Instant::now(),
                                                });
                                            }
                                        }
                                        (b, 200)
                                    }
                                    Ok((c, b)) => { st.node_errors.fetch_add(1, Ordering::Relaxed); (b, c) }
                                    Err(e) => {
                                        st.node_errors.fetch_add(1, Ordering::Relaxed);
                                        (json!({"result": Value::Null,
                                               "error": {"code": -1, "message": format!("broker: {e}")},
                                               "id": id}).to_string(), 502)
                                    }
                                }
                            }
                        }
                    }
                }
                // Regla 3: submitblock, preciousblock y todo lo demás pasan literales.
                _ => passthrough(&cfg, &st, &auth, &body),
            };
            let _ = req.respond(json_resp(&resp).with_status_code(code));
        }));
    }
    for h in hs { let _ = h.join(); }
}

/// Caché válida solo si: mismos params, misma punta que la actual, y dentro del TTL (regla 2).
fn cache_hit(s: &State, pk: &str, ttl_ms: u64) -> Option<String> {
    let g = s.gbt.as_ref()?;
    let tip = s.tip.as_deref()?;
    if g.params_key == pk && g.prevhash == tip && g.at.elapsed() < Duration::from_millis(ttl_ms) {
        Some(g.result.clone())
    } else {
        None
    }
}

fn passthrough(cfg: &Cfg, st: &Stats, auth: &str, body: &str) -> (String, u16) {
    st.passthrough.fetch_add(1, Ordering::Relaxed);
    st.node_calls.fetch_add(1, Ordering::Relaxed);
    match node_post(cfg, auth, body) {
        Ok((c, b)) => { if c != 200 { st.node_errors.fetch_add(1, Ordering::Relaxed); } (b, c) }
        Err(e) => {
            st.node_errors.fetch_add(1, Ordering::Relaxed);
            // Nunca fabricar un éxito: el que llama tiene que ver el fallo (502 = el broker no llegó al nodo).
            (json!({"result": Value::Null, "error": {"code": -1, "message": format!("broker: {e}")}, "id": Value::Null}).to_string(), 502)
        }
    }
}

fn json_resp(s: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_string(s).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
    )
}
