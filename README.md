# datum-carousel

**A Bitcoin-BLAKE2b mining gateway where independent node-runners supply the block templates — and get paid for it.**

`datum-carousel` is a fork of [DATUM Gateway](https://github.com/OCEAN-xyz/datum_gateway) (OCEAN / Jason Hughes, MIT)
ported to **Bitcoin-BLAKE2b** and extended with:

- **Carousel** — one stratum endpoint that *rotates* across independent, spam-free block templates
  published by Template Suppliers. Miners point ordinary SV1 hardware (GPU/CPU/ASIC) at it with their
  own address as username; every cycle they mine a different sovereign block.
- **Template Suppliers** — anyone running a BLAKE2b full node can publish a clean (`datacarrier=0`)
  template into the rotation. No hashrate needed.
- **Deterministic rotation** — the Carousel serves suppliers in a round-robin whose order is fixed by
  the previous block hash: `pick = set[(start + cycle) % n]`, `start = BLAKE2b-256(prevhash) % n`,
  `set` = every fresh valid template, sorted. No weight, priority or allow-list in the selection path;
  every valid supplier is served exactly once per `n` cycles. Live on the API (`GET /carousel`), logged
  every cycle, and recomputable by anyone with `tools/verify_carousel_rotation.py`.
  See `docs/design/carousel-rotation.md`.
- **Non-custodial split, in the block's own coinbase** — the finder keeps **96%**, the supplier whose
  template won earns **3%**, the pool takes **1%** (bootstrap split; target 98/1/1 at critical mass).
  Nothing is ever held by the pool.
- **Per-supplier dedicated gateways** — a single-template mode (`template_file`) for suppliers who want
  their own stratum port.
- **DATUM-TS (in progress)** — a signed *template commitment* the miner verifies before mining, so the
  pool is a relay, not a trusted party. See `docs/design/` and `poc/`.

> Status: **public / pre-release.** Running in production on the PyBLØCK BLAKE2b pool. Not audited.

## How it works (one paragraph)

Suppliers POST their `getblocktemplate` output to the ingest, which validates it (consensus proposal
check, spam / `datacarrier` gate, dedupe) and caches it per address. The Carousel gateway picks a fresh
supplier template each cycle, injects its transaction set, builds the coinbase with the three outputs
(finder / supplier / pool), and serves the job over Stratum v1. When a block is found, the split is
already inside the coinbase — the block *is* the settlement.

## Build

Same toolchain as upstream DATUM Gateway (C, CMake). See `docs/UPSTREAM-README.md` for dependencies.

```
mkdir build && cd build
cmake ..
make datum_gateway
```

## Run

```
./build/datum_gateway -c configs/carousel.example.json      # Carousel (rotating templates)
./build/datum_gateway -c configs/supplier.example.json      # dedicated per-supplier gateway
```

Copy the example config, fill in your node RPC credentials and addresses, and **never commit a real
config** (`.gitignore` blocks `configs/*.json` except `*.example.json`).

Key `mining` settings:

| key | meaning |
|---|---|
| `blake2b_template` | template mode on (inject supplier tx-set) |
| `blake2b_template_carousel` | rotate across `template_dir` (Carousel) |
| `template_dir` / `template_file` | where supplier templates live (Carousel) / single template (dedicated) |
| `template_supplier_bps` | supplier share, basis points (300 = 3%) |
| `template_pool_bps` | pool share, basis points (100 = 1%) |
| `template_activate_height` | template/Carousel mode switches on when the block template reaches this height (0 = from start). Below it the gateway mines its own tx-set with a plain coinbase, so an announced switch is atomic on-chain and needs no restart |
| `template_activate_tag` | primary coinbase tag to switch to at that height (empty = keep `coinbase_tag_primary`) |
| `template_fast_recycle_ms` | right after a new block the fresh set is thin; while it is empty or below half of the previous block's set, the next cycle comes after this many ms instead of `work_update_seconds` (default 5000, 0 = off) |
| `pool_address` | pool fee address |

## Repository layout

```
src/        gateway sources (upstream + BLAKE2b + Carousel/Template mods)
configs/    *.example.json only — sanitized
docs/       whitepapers, design notes, UPSTREAM-README.md
poc/        DATUM-TS proofs of concept (commitment, stratum transport, signed supply)
```

## License

- Original DATUM Gateway code: **MIT**, © 2024–2025 Bitcoin Ocean, LLC, Jason Hughes and contributors —
  preserved verbatim in `LICENSE.MIT`.
- BLAKE2b port, Carousel, Template Suppliers, DATUM-TS and all other PyBLØCK additions:
  **Apache License 2.0** (`LICENSE`), © 2026 PyBLØCK. See `NOTICE`.
