# Carousel rotation — deterministic, prevhash-seeded round-robin

**Problem.** "What prevents the Carousel from selectively excluding, limiting or deprioritizing valid
supplier templates?" Auditing blocks shows *which* supplier was served — transparency — but not that
the pool couldn't have chosen otherwise. Selection neutrality has to be enforced by construction.

**Answer.** The Carousel no longer picks a template at random. Each work cycle it serves the next
supplier of a schedule that is a pure function of public data, so anyone can recompute who *should*
have been served and compare with what miners actually received.

## Rule

```
set      = supplier addresses whose cached template is fresh
           (template.previousblockhash == current tip), sorted bytewise ascending
seed     = BLAKE2b-256( prevhash as lowercase hex ASCII )
start    = uint64_be( seed[0:8] ) % n
cycle    = work cycles since this prevhash was first seen by the gateway (0-based,
           one cycle per work_update_seconds)
pick     = set[ (start + cycle + skipped) % n ]
set_hash = BLAKE2b-256( "\n".join(set) + "\n" )[0:8] hex
```

`skipped` counts scheduled templates that failed to load or apply in this cycle (corrupt file, no
`transactions[]`); they are tried in schedule order and the failure is logged.

**Right after a block.** Suppliers publish for the new tip within seconds, so cycle 0 often sees an
empty or thin set: the gateway then mines its own tx-set (no supplier output, plain coinbase) or the
one supplier already fresh. To keep that window short, while the set is empty or below half of the
previous block's set the next cycle comes after `template_fast_recycle_ms` (default 5 s) instead of a
full work cycle. Every cycle is still logged and follows the rule; `cycle` simply advances faster.

**Announced switch-over.** `template_activate_height` keeps the gateway in plain mode (own tx-set, plain
coinbase, `coinbase_tag_primary`) until the block template reaches that height, then turns template
mode on and swaps the primary tag to `template_activate_tag` in the same cycle — so a migration such as
"LOTTO becomes Carousel at block N" happens on-chain at exactly N, with no restart and no race.

## Properties

- **Exact fairness.** Every valid supplier is served exactly once per `n` cycles. Random selection
  only converged to that on average.
- **Unpredictable but verifiable order.** The starting offset is fixed by the previous block hash, which
  no party controls, and the order is the bytewise sort of the addresses.
- **No operator knob.** There is no weight, priority or allow-list in the selection path. The only
  filter is validity: `previousblockhash == tip` plus the ingest's consensus / `datacarrier=0` checks.
- **Recomputable by anyone.** Inputs are the tip, the set and the cycle index — all published.

## Where to see it

- **Log**, every cycle: `carousel: rotation h=<height> cycle=<k> n=<n> start=<s> skipped=<x> idx=<i> pick=<addr> set=<set_hash> prevhash=<hash>`
  and, whenever the fresh set changes, `carousel: set <set_hash> n=<n> [a..b] addr,addr,...` (16 addresses per line).
- **API**, live: `GET /carousel` → `{prevhash, height, cycle, n, start, skipped, idx, pick, set_hash, set[], rule}`.
- **Stratum.** The served job's coinbase carries `pick`'s payout output and its name in the scriptSig,
  so a supplier can measure its own serve-rate directly from the jobs it receives.
- **Verifier.** `tools/verify_carousel_rotation.py --api http://127.0.0.1:7156` checks the live cycle;
  `--log gateway.log` re-verifies every logged cycle; `--template-dir` rebuilds the set from the caches.

## What this does not cover

Refusing a valid template at the door (the ingest) is not preventable by any pool — it is detectable
(the supplier sees its publication rejected, the set never lists it). The remedy is exit: the gateway
is Apache-2.0, run your own. Template *integrity* (the miner verifying it mines what the supplier
signed) is the separate DATUM-TS commitment, see `docs/design/` and `poc/`.

## Implementation

`src/datum_blocktemplates.c` — `datum_template_apply_supplier()` (carousel branch), state in
`g_carousel_rot` (`src/datum_blocktemplates.h`); `src/datum_api.c` — `datum_api_carousel()`.
Freshness is pre-checked on the first 4 KB of each cache (the ingest writes `previousblockhash` in
the header) with a full parse as fallback, so a cycle costs one parse — the picked template — not `n`.
