/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <jansson.h>
#include <inttypes.h>
#include <curl/curl.h>
#include <stdatomic.h>
#include <signal.h>

#include "datum_gateway.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"
#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_pow.h"

volatile sig_atomic_t new_notify = 0;
atomic_int new_notify_threadsafe = 0;
atomic_int notify_othercause = 0;
static pthread_mutex_t new_notify_lock = PTHREAD_MUTEX_INITIALIZER;
volatile char new_notify_blockhash[256] = { 0 };
volatile int new_notify_height = 0;

void datum_blocktemplates_notifynew_sighandler() {
	new_notify = 1;
}

void datum_blocktemplates_notifynew(const char * const prevhash, const int height) {
	if (prevhash && *prevhash) pthread_mutex_lock(&new_notify_lock);
	new_notify_threadsafe = 1;
	if (prevhash) {
		if (prevhash[0]) {
			strncpy((char *)new_notify_blockhash, prevhash, 66);
			if (height > new_notify_height) {
				new_notify_height = height;
			}
			pthread_mutex_unlock(&new_notify_lock);
		}
	}
}

void datum_blocktemplates_notify_othercause() {
	notify_othercause = 1;
}

T_DATUM_TEMPLATE_DATA *template_data = NULL;

int next_template_index = 0;

const char *datum_blocktemplates_error = NULL;

int datum_template_init(void) {
	char *temp = NULL, *ptr = NULL;
	int i,j;
	
	template_data = (T_DATUM_TEMPLATE_DATA *)calloc(sizeof(T_DATUM_TEMPLATE_DATA),MAX_TEMPLATES_IN_MEMORY+1);
	if (!template_data) {
		DLOG_FATAL("Could not allocate RAM for in-memory template data. :( (1)");
		return -1;
	}
	
	// TODO: Be smarter about dependent RAM data and size
	// we're storing both binary and ascii hex versions of all txns for both processing and submitblock speedups
	j = (sizeof(T_DATUM_TEMPLATE_TXN)*16384) + (MAX_BLOCK_SIZE_BYTES*3) + 2000000;
	temp = calloc(j, MAX_TEMPLATES_IN_MEMORY);
	if (!temp) {
		DLOG_FATAL("ERROR: Could not allocate RAM for in-memory template data. :( (2)");
		return -2;
	}
	
	ptr = temp;
	for(i=0;i<MAX_TEMPLATES_IN_MEMORY;i++) {
		template_data[i].local_data = ptr;
		ptr+=j;
		template_data[i].local_data_size = j;
		template_data[i].local_index = i;
	}
	
	DLOG_DEBUG("Allocated %d MB of RAM for template memory", (j*MAX_TEMPLATES_IN_MEMORY)/(1024*1024));
	
	return 1;
}

static void datum_template_clear_header_fields(T_DATUM_TEMPLATE_DATA *p) {
	p->header_version = 0;
	p->header_transaction_count = 0;
	p->header_flags = 0;
	p->header_time_offset = 0;
	p->xor_key_mask_clear_bits = 0;
	memset(p->xor_key, 0, sizeof(p->xor_key));
	memset(p->merge_mining_rhs, 0, sizeof(p->merge_mining_rhs));
}

void datum_template_clear(T_DATUM_TEMPLATE_DATA* p) {
	p->coinbasevalue = 0;
	p->txn_count = 0;
	p->txn_total_size = 0;
	p->txn_data_offset = 0;
	p->txn_total_weight = 0;
	p->txn_total_sigops = 0;
	p->txns = p->local_data;
	datum_template_clear_header_fields(p);
}

static bool datum_gbt_try_hex_field(json_t *gbt, const char *key, unsigned char *out, size_t out_len) {
	json_t *v = json_object_get(gbt, key);
	if (!json_is_string(v)) return false;
	const char *s = json_string_value(v);
	if (!s || strlen(s) != out_len * 2) return false;
	return datum_pow_decode_hex_exact(s, out_len, out);
}

bool datum_gbt_parse_header_fields(json_t *gbt, T_DATUM_TEMPLATE_DATA *tdata) {
	json_t *jval;
	const char *s;
	bool have_blake2b = false;
	bool have_sha256d = false;
	json_int_t fv, xv;
	
	if (!gbt || !tdata || !json_is_object(gbt)) {
		if (tdata) datum_template_clear_header_fields(tdata);
		return false;
	}
	
	datum_template_clear_header_fields(tdata);
	
	jval = json_object_get(gbt, "powalgorithm");
	if (jval) {
		if (!json_is_string(jval)) {
			datum_template_clear_header_fields(tdata);
			return false;
		}
		s = json_string_value(jval);
		if (!s) {
			datum_template_clear_header_fields(tdata);
			return false;
		}
		if (!strcmp(s, "blake2b")) {
			have_blake2b = true;
			tdata->header_version = 2;
		} else if (!strcmp(s, "sha256d")) {
			have_sha256d = true;
		} else {
			datum_template_clear_header_fields(tdata);
			return false;
		}
	}
	
	jval = json_object_get(gbt, "header_version");
	if (jval) {
		if (!json_is_integer(jval) || json_integer_value(jval) == 0) {
			datum_template_clear_header_fields(tdata);
			return false;
		}
		tdata->header_version = (uint32_t)json_integer_value(jval);
	}
	
	if (have_sha256d && tdata->header_version >= 2) {
		datum_template_clear_header_fields(tdata);
		return false;
	}
	if (have_blake2b) {
		tdata->header_version = 2;
	}
	if (!tdata->header_version) {
		// BIP22 / SHA256d: success only when GBT named sha256d. Empty objects fail.
		return have_sha256d;
	}
	
	jval = json_object_get(gbt, "transaction_count");
	if (json_is_integer(jval) && json_integer_value(jval) >= 0) {
		tdata->header_transaction_count = (uint32_t)json_integer_value(jval);
	}
	
	jval = json_object_get(gbt, "h1_flags");
	if (!jval) jval = json_object_get(gbt, "header_flags");
	if (json_is_integer(jval)) {
		fv = json_integer_value(jval);
		if (fv >= 0 && fv <= 255) {
			if ((fv & 3) != 0) {
				DLOG_ERROR("BLAKE2b ASIC profile %d (header_flags&3) not supported; only profile 0", (int)(fv & 3));
				return false;
			}
			tdata->header_flags = (uint8_t)fv;
		}
	}
	
	jval = json_object_get(gbt, "time_offset");
	if (json_is_integer(jval) && json_integer_value(jval) >= 0 && json_integer_value(jval) <= UINT32_MAX) {
		tdata->header_time_offset = (uint32_t)json_integer_value(jval);
	}
	
	jval = json_object_get(gbt, "xor_key_mask_clear_bits");
	if (json_is_integer(jval)) {
		xv = json_integer_value(jval);
		if (xv >= 0 && xv <= 255) tdata->xor_key_mask_clear_bits = (uint8_t)xv;
	}
	
	datum_gbt_try_hex_field(gbt, "xor_key", tdata->xor_key, sizeof(tdata->xor_key));
	datum_gbt_try_hex_field(gbt, "merge_mining_rhs", tdata->merge_mining_rhs, sizeof(tdata->merge_mining_rhs));
	
	if (datum_config.mining_allow_hasher_time_rolling) {
		tdata->header_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	}
	
	return true;
}

T_DATUM_TEMPLATE_DATA *get_next_template_ptr(void) {
	T_DATUM_TEMPLATE_DATA *p;
	
	if (!template_data) return NULL;
	
	p = &template_data[next_template_index];
	
	datum_template_clear(p);
	
	next_template_index++;
	if (next_template_index >= MAX_TEMPLATES_IN_MEMORY) {
		next_template_index = 0;
	}
	
	return p;
}

T_DATUM_TEMPLATE_DATA *datum_gbt_parser(json_t *gbt) {
	T_DATUM_TEMPLATE_DATA *tdata;
	const char *s;
	int i,j;
	json_t *tx_array, *jval, *rule;
	size_t ri;
	bool want_blake2b;
	
	tdata = get_next_template_ptr();
	if (!tdata) {
		DLOG_ERROR("Could not get a template pointer.");
		return NULL;
	}
	
	tdata->height = json_integer_value(json_object_get(gbt, "height"));
	if (!tdata->height) {
		DLOG_ERROR("Missing data from GBT JSON (height)");
		return NULL;
	}
	
	tdata->coinbasevalue = json_integer_value(json_object_get(gbt, "coinbasevalue"));
	if (!tdata->coinbasevalue) {
		DLOG_ERROR("Missing data from GBT JSON (coinbasevalue)");
		return NULL;
	}
	
	tdata->mintime = json_integer_value(json_object_get(gbt, "mintime"));
	if (!tdata->mintime) {
		DLOG_ERROR("Missing data from GBT JSON (mintime)");
		return NULL;
	}
	
	tdata->sigoplimit = json_integer_value(json_object_get(gbt, "sigoplimit"));
	if (!tdata->sigoplimit) {
		DLOG_ERROR("Missing data from GBT JSON (sigoplimit)");
		return NULL;
	}
	
	tdata->curtime = json_integer_value(json_object_get(gbt, "curtime"));
	if (!tdata->curtime) {
		DLOG_ERROR("Missing data from GBT JSON (curtime)");
		return NULL;
	}
	
	tdata->sizelimit = json_integer_value(json_object_get(gbt, "sizelimit"));
	if (!tdata->sizelimit) {
		DLOG_ERROR("Missing data from GBT JSON (sizelimit)");
		return NULL;
	}
	
	tdata->weightlimit = json_integer_value(json_object_get(gbt, "weightlimit"));
	if (!tdata->weightlimit) {
		DLOG_ERROR("Missing data from GBT JSON (weightlimit)");
		return NULL;
	}
	
	tdata->version = json_integer_value(json_object_get(gbt, "version"));
	if (!tdata->version) {
		DLOG_ERROR("Missing data from GBT JSON (version)");
		return NULL;
	}

	if (json_object_get(gbt, "powalgorithm") || json_object_get(gbt, "header_version")) {
		if (!datum_gbt_parse_header_fields(gbt, tdata)) {
			DLOG_ERROR("Unsupported or invalid header/PoW fields from GBT JSON");
			return NULL;
		}
	} else {
		want_blake2b = false;
		jval = json_object_get(gbt, "rules");
		if (json_is_array(jval)) {
			json_array_foreach(jval, ri, rule) {
				s = json_string_value(rule);
				if (s && (!strcmp(s, "blake2b") || !strcmp(s, "!blake2b"))) {
					want_blake2b = true;
					break;
				}
			}
		}
		jval = json_object_get(gbt, "coinbaseaux");
		if (!want_blake2b && json_is_object(jval) && json_object_get(jval, "blake2b_headline")) {
			want_blake2b = true;
		}
		if (tdata->version & 0x80000000) {
			want_blake2b = true;
			tdata->version &= ~0x80000000;
		}
		if (!want_blake2b && !strcmp(datum_config.mining_pow_algorithm, "blake2b")) {
			want_blake2b = true;
		}
		if (want_blake2b && strcmp(datum_config.mining_pow_algorithm, "sha256d")) {
			tdata->header_version = 2;
			if (datum_config.mining_allow_hasher_time_rolling) {
				tdata->header_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
			}
		}
	}
	
	if (tdata->header_version >= 2) {
		tdata->blake2b_headline_len = 0;
		json_t *aux = json_object_get(gbt, "coinbaseaux");
		if (json_is_object(aux)) {
			json_t *hl = json_object_get(aux, "blake2b_headline");
			const char *hs = json_is_string(hl) ? json_string_value(hl) : NULL;
			size_t hlen = hs ? strlen(hs) : 0;
			if (hlen >= 2 && (hlen & 1) == 0 && (hlen >> 1) <= sizeof(tdata->blake2b_headline)) {
				for (size_t z = 0; z < (hlen >> 1); z++) tdata->blake2b_headline[z] = hex2bin_uchar(&hs[z << 1]);
				tdata->blake2b_headline_len = (uint8_t)(hlen >> 1);
			}
		}
	}
	
	jval = json_object_get(gbt, "bits");
	if (json_string_length(jval) != 8) {
		DLOG_ERROR("Wrong bits length from GBT JSON");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->bits, s);
	
	jval = json_object_get(gbt, "previousblockhash");
	if (json_string_length(jval) != 64) {
		DLOG_ERROR("Missing data from GBT JSON (previousblockhash)");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->previousblockhash, s);
	
	jval = json_object_get(gbt, "target");
	if (json_string_length(jval) != 64) {
		DLOG_ERROR("Missing data from GBT JSON (target)");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->block_target_hex, s);
	
	jval = json_object_get(gbt, "default_witness_commitment");
	if (json_string_length(jval) < 38 || json_string_length(jval) > 95) {
		DLOG_ERROR("Missing data from GBT JSON (default_witness_commitment)");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->default_witness_commitment, s);
	
	// "20000000", "192e17d5", "66256be5"
	// version, bits, time
	// 192e17d5 // gbt format matches stratum for bits
	
	// stash useful binary versions of prevblockhash and nbits
	for(i=0;i<64;i+=2) {
		tdata->previousblockhash_bin[31-(i>>1)] = hex2bin_uchar(&tdata->previousblockhash[i]);
	}
	for(i=0;i<4;i++) {
		tdata->bits_bin[3-i] = hex2bin_uchar(&tdata->bits[i<<1]);
	}
	tdata->bits_uint = upk_u32le(tdata->bits_bin, 0);
	nbits_to_target(tdata->bits_uint, tdata->block_target);
	
	// store binary default witness commitment
	j = strlen(tdata->default_witness_commitment);
	for(i=0;i<j;i+=2) {
		tdata->default_witness_commitment_bin[(i>>1)] = hex2bin_uchar(&tdata->default_witness_commitment[i]);
	}
	
	// Get the txns
	tx_array = json_object_get(gbt, "transactions");
	if (!json_is_array(tx_array)) {
		DLOG_ERROR("Missing data from GBT JSON (transactions)");
		return NULL;
	}
	
	tdata->txn_count = json_array_size(tx_array);
	tdata->txn_data_offset = sizeof(T_DATUM_TEMPLATE_TXN)*tdata->txn_count;
	if (tdata->txn_count > 0) {
		if (tdata->txn_count > 16383) {
			DLOG_WARN("DATUM Gateway does not support blocks with more than 16383 transactions! %d txns in template. Truncating template to 16383 transactions.", (int)tdata->txn_count);
			tdata->txn_count = 16383;
		}
		for(i=0;i<tdata->txn_count;i++) {
			json_t *tx = json_array_get(tx_array, i);
			if (!tx) {
				DLOG_ERROR("transaction %d not found!", i);
				return NULL;
			}
			if (!json_is_object(tx)) {
				DLOG_ERROR("transaction %d is not an object!", i);
				return NULL;
			}
			
			// index (1 based, like GBT depends)
			tdata->txns[i].index_raw = i+1;
			
			// txid
			jval = json_object_get(tx, "txid");
			if (json_string_length(jval) != 64) {
				DLOG_ERROR("Missing data from GBT JSON transactions[%d] (txid)",i);
				return NULL;
			}
			s = json_string_value(jval);
			strcpy(tdata->txns[i].txid_hex, s);
			hex_to_bin_le(tdata->txns[i].txid_hex, tdata->txns[i].txid_bin);
			
			// hash
			jval = json_object_get(tx, "hash");
			if (json_string_length(jval) != 64) {
				DLOG_ERROR("Missing data from GBT JSON transactions[%d] (hash)",i);
				return NULL;
			}
			s = json_string_value(jval);
			strcpy(tdata->txns[i].hash_hex, s);
			hex_to_bin_le(tdata->txns[i].hash_hex, tdata->txns[i].hash_bin);
			
			// fee
			tdata->txns[i].fee_sats = json_integer_value(json_object_get(tx, "fee"));
			
			// sigops
			tdata->txns[i].sigops = json_integer_value(json_object_get(tx, "sigops"));
			
			// weight
			tdata->txns[i].weight = json_integer_value(json_object_get(tx, "weight"));
			
			// data
			s = json_string_value(json_object_get(tx, "data"));
			if (!s) {
				DLOG_ERROR("Missing data from GBT JSON transactions[%d] (data)",i);
				return NULL;
			}
			
			// size
			tdata->txns[i].size = strlen(s)>>1;
			
			// raw txn data
			tdata->txns[i].txn_data_binary = &((uint8_t *)tdata->local_data)[tdata->txn_data_offset];
			tdata->txn_data_offset += tdata->txns[i].size+1;
			tdata->txns[i].txn_data_hex = &((char *)tdata->local_data)[tdata->txn_data_offset];
			tdata->txn_data_offset += (tdata->txns[i].size*2)+2;
			if (tdata->txn_data_offset >= tdata->local_data_size) {
				DLOG_ERROR("Exceeded template local size with txn data!");
				return NULL;
			}
			strcpy(tdata->txns[i].txn_data_hex, s);
			hex_to_bin(s, tdata->txns[i].txn_data_binary);
			
			// tallies
			tdata->txn_total_weight+=tdata->txns[i].weight;
			tdata->txn_total_size+=tdata->txns[i].size;
			tdata->txn_total_sigops+=tdata->txns[i].sigops;
		}
	}
	
	return tdata;
}

static uint64_t datum_json_u64(json_t *v) {
	if (json_is_integer(v)) return (uint64_t)json_integer_value(v);
	if (json_is_string(v)) return strtoull(json_string_value(v), NULL, 10);
	return 0;
}

extern char g_carousel_supplier[128];   // datum_coinbaser.c: supplier sorteado del ciclo
extern char g_carousel_supplier_name[40]; // datum_coinbaser.c: nombre del supplier ("name" del JSON) → scriptSig

// Copia el "name" del template JSON del supplier a g_carousel_supplier_name, sanitizado a ASCII imprimible
// (viene del header X-PyBLOCK-Name del join — no confiable). Vacío/ausente → queda "", el scriptSig no lo incluye.
static void datum_template_set_supplier_name(json_t *sup) {
	const char *nm = sup ? json_string_value(json_object_get(sup, "name")) : NULL;
	int w = 0;
	if (nm) {
		for (int z = 0; nm[z] && w < (int)sizeof(g_carousel_supplier_name) - 1; z++) {
			if (nm[z] >= 0x20 && nm[z] <= 0x7e) g_carousel_supplier_name[w++] = nm[z];
		}
	}
	g_carousel_supplier_name[w] = 0;
}

// Aplica el tx-set de un supplier YA CARGADO (sup) sobre res_val (GBT de nuestro nodo). our_ph = prevhash nuestro.
// Conserva el envelope consensus blake2b nuestro; solo si el supplier apunta al mismo tip. wtxid no consensus en solo.
// Devuelve true si aplicó (prevhash coincide + tiene transactions[]).
static bool datum_template_swap_from(json_t *res_val, json_t *sup, const char *our_ph, const char *sup_addr) {
	json_t *sup_txs, *our_txs, *new_txs, *tx;
	const char *sup_ph, *sup_wc, *txid, *data;
	uint64_t our_cbv, our_fees = 0, subsidy, sup_fees = 0, fee, wt;
	size_t k;

	sup_ph = json_string_value(json_object_get(sup, "previousblockhash"));
	if (!our_ph || !sup_ph || strcmp(our_ph, sup_ph)) return false;
	sup_txs = json_object_get(sup, "transactions");
	if (!json_is_array(sup_txs)) return false;

	our_cbv = datum_json_u64(json_object_get(res_val, "coinbasevalue"));
	our_txs = json_object_get(res_val, "transactions");
	if (json_is_array(our_txs)) {
		json_array_foreach(our_txs, k, tx) our_fees += datum_json_u64(json_object_get(tx, "fee"));
	}
	subsidy = (our_cbv >= our_fees) ? (our_cbv - our_fees) : our_cbv;

	new_txs = json_array();
	json_array_foreach(sup_txs, k, tx) {
		txid = json_string_value(json_object_get(tx, "txid"));
		data = json_string_value(json_object_get(tx, "data"));
		if (!txid || !data) continue;
		fee = datum_json_u64(json_object_get(tx, "fee"));
		wt  = datum_json_u64(json_object_get(tx, "weight"));
		sup_fees += fee;
		json_t *nt = json_object();
		json_object_set_new(nt, "data",   json_string(data));
		json_object_set_new(nt, "txid",   json_string(txid));
		json_object_set_new(nt, "hash",   json_string(txid));   // solo: wtxid no consensus
		json_object_set_new(nt, "fee",    json_integer((json_int_t)fee));
		json_object_set_new(nt, "weight", json_integer((json_int_t)wt));
		json_object_set_new(nt, "sigops", json_integer(0));
		json_array_append_new(new_txs, nt);
	}

	sup_wc = json_string_value(json_object_get(sup, "default_witness_commitment"));
	if (sup_wc) json_object_set_new(res_val, "default_witness_commitment", json_string(sup_wc));
	json_object_set_new(res_val, "coinbasevalue", json_integer((json_int_t)(subsidy + sup_fees)));
	json_object_set_new(res_val, "transactions", new_txs);

	DLOG_INFO("template: swap OK supplier=%s ntx=%zu subsidy=%"PRIu64" sup_fees=%"PRIu64" cbv=%"PRIu64,
		sup_addr, json_array_size(new_txs), subsidy, sup_fees, subsidy + sup_fees);
	return true;
}

// ---------------------------------------------------------------------------------------------
// Carousel — DETERMINISTIC rotation (replaces the old rand() shuffle). Selection neutrality is
// enforced by construction and recomputable by anyone from public data:
//   set     = supplier addresses whose cached template is fresh (previousblockhash == our tip),
//             sorted bytewise ascending (filename minus .json = payout address)
//   seed    = BLAKE2b-256(prevhash as lowercase hex ASCII)
//   start   = uint64_be(seed[0..8]) % n
//   cycle   = work cycles since this prevhash was first seen by this gateway (0-based, ~every
//             work_update_seconds)
//   pick    = set[(start + cycle + skipped) % n]   (skipped = scheduled templates that failed to
//             load/apply this cycle, tried in schedule order)
// Every valid supplier is served exactly once per n cycles (round-robin), in an order fixed by the
// previous block hash. Each cycle is logged ("carousel: rotation ...", the set whenever it changes)
// and exposed live on the API (/carousel). The served job carries pick's payout output + name in the
// coinbase, so a supplier can measure its own serve-rate straight from the stratum.
// ---------------------------------------------------------------------------------------------
T_CAROUSEL_ROTATION g_carousel_rot = { .lock = PTHREAD_MUTEX_INITIALIZER };

static int carousel_cmp(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }

// Membership test for the fresh set — FULL JSON parse, same rule the public verifier applies
// (tools/verify_carousel_rotation.py --template-dir): previousblockhash == our tip, a transactions[] array,
// not flagged stale by the ingest and — unless template_require_validated=false — carrying the ingest's
// validation stamp (validated.proposal == true: passed getblocktemplate mode=proposal + the datacarrier gate).
// No header prefilter: the set must be a pure function of the files' content.
static bool carousel_cache_fresh(const char *path, const char *our_ph) {
	json_error_t err;
	json_t *sup = json_load_file(path, 0, &err), *v;
	const char *ph;
	bool ok = false;
	if (!sup) return false;
	ph = json_string_value(json_object_get(sup, "previousblockhash"));
	ok = ph && !strcmp(ph, our_ph) && json_is_array(json_object_get(sup, "transactions"))
	     && !json_is_true(json_object_get(sup, "stale"));
	if (ok && datum_config.mining_template_require_validated) {
		v = json_object_get(sup, "validated");
		ok = json_is_object(v) && json_is_true(json_object_get(v, "proposal"));
	}
	json_decref(sup);
	return ok;
}

static void carousel_rot_publish(const char *our_ph, uint64_t height, uint32_t cycle, int n, int start, int idx, bool failed, const char *pick, const char *set_hash, char names[][128]) {
	int i;
	pthread_mutex_lock(&g_carousel_rot.lock);
	strncpy(g_carousel_rot.prevhash, our_ph, sizeof(g_carousel_rot.prevhash) - 1);
	g_carousel_rot.prevhash[sizeof(g_carousel_rot.prevhash) - 1] = 0;
	g_carousel_rot.height = height;
	g_carousel_rot.cycle = cycle;
	g_carousel_rot.n = n;
	g_carousel_rot.start = start;
	g_carousel_rot.idx = idx;
	g_carousel_rot.skipped = 0;
	g_carousel_rot.failed = failed;
	strncpy(g_carousel_rot.pick, pick ? pick : "", sizeof(g_carousel_rot.pick) - 1);
	g_carousel_rot.pick[sizeof(g_carousel_rot.pick) - 1] = 0;
	strncpy(g_carousel_rot.set_hash, set_hash ? set_hash : "", sizeof(g_carousel_rot.set_hash) - 1);
	g_carousel_rot.set_hash[sizeof(g_carousel_rot.set_hash) - 1] = 0;
	g_carousel_rot.set_n = n;
	for (i = 0; i < n; i++) { strncpy(g_carousel_rot.set[i], names[i], 127); g_carousel_rot.set[i][127] = 0; }
	g_carousel_rot.updated = (uint64_t)time(NULL);
	pthread_mutex_unlock(&g_carousel_rot.lock);
}

// Template mode (BLAKE2b): inyecta el tx-set del supplier. Single = template_file/config addr.
// Carousel = rotación DETERMINISTA (prevhash-seeded round-robin) sobre los suppliers frescos de template_dir;
// paga a ESE supplier (g_carousel_supplier). Ver el bloque de comentarios de arriba.
static void datum_template_apply_supplier(json_t *res_val) {
	json_error_t err;
	const char *our_ph;
	json_t *sup;

	if (!datum_config.mining_blake2b_template || !res_val) return;
	our_ph = json_string_value(json_object_get(res_val, "previousblockhash"));
	if (!our_ph) return;

	// Activación por altura de TEMPLATE (swap anunciado, p.ej. LOTTO→Carousel @970000): por debajo de la
	// altura el gateway no inyecta nada (tx-set propio, coinbase plano = LOTTO exacto). Al llegar, cambia el
	// tag primario del coinbase (una vez) y sigue en modo template. Sin restart, sin carrera con el bloque.
	if (datum_config.mining_template_activate_height > 0) {
		static uint64_t pre_logged_h = 0;
		static bool activated = false;
		uint64_t th = datum_json_u64(json_object_get(res_val, "height"));
		if (th < (uint64_t)datum_config.mining_template_activate_height) {
			if (pre_logged_h != th) {
				pre_logged_h = th;
				DLOG_INFO("template: PRE-ACTIVATION h=%"PRIu64" < %d — tx-set propio, coinbase plano (LOTTO)", th, datum_config.mining_template_activate_height);
			}
			g_carousel_supplier[0] = 0;
			g_carousel_supplier_name[0] = 0;
			pthread_mutex_lock(&g_carousel_rot.lock);
			g_carousel_rot.active = false;
			g_carousel_rot.activate_height = (uint64_t)datum_config.mining_template_activate_height;
			g_carousel_rot.height = th;
			g_carousel_rot.n = 0; g_carousel_rot.set_n = 0; g_carousel_rot.idx = -1; g_carousel_rot.pick[0] = 0;
			g_carousel_rot.updated = (uint64_t)time(NULL);
			pthread_mutex_unlock(&g_carousel_rot.lock);
			return;
		}
		if (!activated) {
			activated = true;
			if (datum_config.mining_template_activate_tag[0]) {
				char newtag[sizeof(datum_config.mining_coinbase_tag_primary)];
				strncpy(newtag, datum_config.mining_template_activate_tag, sizeof(newtag) - 1);
				newtag[sizeof(newtag) - 1] = 0;
				memcpy(datum_config.mining_coinbase_tag_primary, newtag, sizeof(newtag));
			}
			DLOG_INFO("template: *** ACTIVATED at template height %"PRIu64" (>= %d) — template/carousel mode ON, coinbase tag \"%s\" ***",
				th, datum_config.mining_template_activate_height, datum_config.mining_coinbase_tag_primary);
			pthread_mutex_lock(&g_carousel_rot.lock);
			g_carousel_rot.active = true;
			g_carousel_rot.activate_height = (uint64_t)datum_config.mining_template_activate_height;
			pthread_mutex_unlock(&g_carousel_rot.lock);
		}
	} else {
		pthread_mutex_lock(&g_carousel_rot.lock);
		g_carousel_rot.active = true;
		pthread_mutex_unlock(&g_carousel_rot.lock);
	}

	if (datum_config.mining_blake2b_template_carousel && datum_config.mining_template_dir[0]) {
		static char cr_prev[80] = "";
		static uint32_t cr_cycle = 0;
		static char cr_set_hash[17] = "";
		static char names[CAROUSEL_MAX_SET][128];
		static char setbuf[CAROUSEL_MAX_SET * 129];
		unsigned char h[32];
		char set_hash[17], path[640];
		uint64_t height = datum_json_u64(json_object_get(res_val, "height")), s = 0;
		size_t sl = 0;
		int n = 0, i, start, idx = -1;
		bool applied = false;
		struct dirent *de;
		DIR *d;

		// cycle counter: restarts at 0 on every new prevhash
		if (strcmp(cr_prev, our_ph)) {
			strncpy(cr_prev, our_ph, sizeof(cr_prev) - 1); cr_prev[sizeof(cr_prev) - 1] = 0;
			cr_cycle = 0;
			cr_set_hash[0] = 0;
			pthread_mutex_lock(&g_carousel_rot.lock);
			g_carousel_rot.n_prev_block = g_carousel_rot.n;   // baseline: how many suppliers the previous block ended with
			pthread_mutex_unlock(&g_carousel_rot.lock);
		} else {
			cr_cycle++;
		}

		d = opendir(datum_config.mining_template_dir);
		if (!d) { DLOG_WARN("carousel: no pude abrir %s", datum_config.mining_template_dir); g_carousel_supplier[0] = 0; g_carousel_supplier_name[0] = 0; return; }
		// Collect EVERY fresh cache (full parse), then sort; the cap applies after sorting (see CAROUSEL_MAX_SET).
		while ((de = readdir(d)) && n < CAROUSEL_MAX_SET) {
			size_t l = strlen(de->d_name), al;
			if (!(l > 5 && l <= 132 && !strcmp(de->d_name + l - 5, ".json"))) continue;
			snprintf(path, sizeof(path), "%s/%s", datum_config.mining_template_dir, de->d_name);
			if (!carousel_cache_fresh(path, our_ph)) continue;
			al = l - 5; if (al > 127) al = 127;
			memcpy(names[n], de->d_name, al); names[n][al] = 0;   // filename sin .json = supplier addr
			n++;
		}
		closedir(d);
		if (n == 0) {
			DLOG_WARN("carousel: ningún supplier fresco (prevhash %s) — uso tx-set propio", our_ph);
			g_carousel_supplier[0] = 0;   // sin supplier → build_user_coinbase no agrega output supplier
			g_carousel_supplier_name[0] = 0;
			carousel_rot_publish(our_ph, height, cr_cycle, 0, 0, -1, false, "", "", names);
			return;
		}
		qsort(names, n, sizeof(names[0]), carousel_cmp);

		// set hash = id of this cycle's fresh set; the full set is logged whenever it changes
		for (i = 0; i < n; i++) { size_t al = strlen(names[i]); memcpy(setbuf + sl, names[i], al); sl += al; setbuf[sl++] = '\n'; }
		datum_blake2b_256(h, (const unsigned char *)setbuf, sl);
		snprintf(set_hash, sizeof(set_hash), "%02x%02x%02x%02x%02x%02x%02x%02x", h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
		if (strcmp(set_hash, cr_set_hash)) {
			strcpy(cr_set_hash, set_hash);
			for (i = 0; i < n; i += 16) {   // logger caps a line at 1023 chars → 16 addresses per line
				char line[900];
				size_t ll = 0;
				int j, last = (i + 16 < n) ? i + 16 : n;
				for (j = i; j < last; j++) {
					int w = snprintf(line + ll, sizeof(line) - ll, "%s%s", j > i ? "," : "", names[j]);
					if (w < 0 || ll + (size_t)w >= sizeof(line)) break;
					ll += (size_t)w;
				}
				DLOG_INFO("carousel: set %s n=%d [%d..%d] %s", set_hash, n, i, last - 1, line);
			}
		}

		// seed = BLAKE2b-256(prevhash hex ascii); start = uint64_be(seed[0..8]) % n
		datum_blake2b_256(h, (const unsigned char *)our_ph, strlen(our_ph));
		for (i = 0; i < 8; i++) s = (s << 8) | h[i];
		start = (int)(s % (uint64_t)n);

		// The schedule is NEVER advanced past a failing template: pick = set[(start + cycle) % n], full stop.
		// If that template fails to load/apply, this cycle mines the gateway's own tx-set with NO supplier
		// output (visible on-chain and in the API as failed=true) — the operator has no knob to skip anyone.
		idx = (int)(((uint64_t)start + (uint64_t)cr_cycle) % (uint64_t)n);
		snprintf(path, sizeof(path), "%s/%s.json", datum_config.mining_template_dir, names[idx]);
		sup = json_load_file(path, 0, &err);
		if (sup && datum_template_swap_from(res_val, sup, our_ph, names[idx])) {
			pthread_mutex_lock(&g_carousel_rot.lock);
			strncpy(g_carousel_supplier, names[idx], sizeof(g_carousel_supplier) - 1);
			g_carousel_supplier[127] = 0;
			datum_template_set_supplier_name(sup);   // nombre → scriptSig del job
			pthread_mutex_unlock(&g_carousel_rot.lock);
			applied = true;
		}
		if (sup) json_decref(sup);
		if (!applied) {
			DLOG_WARN("carousel: rotation h=%"PRIu64" cycle=%u n=%d start=%d idx=%d pick=%s FAILED to load/apply — tx-set propio, sin supplier este ciclo",
				height, cr_cycle, n, start, idx, names[idx]);
			pthread_mutex_lock(&g_carousel_rot.lock);
			g_carousel_supplier[0] = 0;
			g_carousel_supplier_name[0] = 0;
			pthread_mutex_unlock(&g_carousel_rot.lock);
			carousel_rot_publish(our_ph, height, cr_cycle, n, start, idx, true, "", set_hash, names);
			return;
		}
		DLOG_INFO("carousel: rotation h=%"PRIu64" cycle=%u n=%d start=%d skipped=0 idx=%d pick=%s set=%s prevhash=%s",
			height, cr_cycle, n, start, idx, names[idx], set_hash, our_ph);
		carousel_rot_publish(our_ph, height, cr_cycle, n, start, idx, false, names[idx], set_hash, names);
		return;
	}

	// modo single
	if (!datum_config.mining_template_file[0]) return;
	sup = json_load_file(datum_config.mining_template_file, 0, &err);
	if (!sup) { DLOG_WARN("template: no pude leer %s (%s) — uso tx-set propio", datum_config.mining_template_file, err.text); g_carousel_supplier_name[0] = 0; return; }
	datum_template_set_supplier_name(sup);   // per-supplier stratum: su nombre también va al scriptSig
	if (!g_carousel_supplier_name[0] && datum_config.mining_template_supplier_address[0]) {
		// supplier sin "name" → prefijo del address (mismo largo que el viejo tag -PREFIX de gen_b2b_config.sh)
		snprintf(g_carousel_supplier_name, sizeof(g_carousel_supplier_name), "%.8s", datum_config.mining_template_supplier_address);
	}
	if (!datum_template_swap_from(res_val, sup, our_ph, datum_config.mining_template_supplier_address))
		DLOG_WARN("template: supplier stale/invalid — uso tx-set propio");
	json_decref(sup);
}

void *datum_gateway_fallback_notifier(void *args) {
	CURL *tcurl = NULL;
	char req[512];
	char p1[72];
	p1[0] = 0;
	json_t *gbbh, *res_val;
	const char *s;
	
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL");
		panic_from_thread(__LINE__);
	}
	DLOG_DEBUG("Fallback notifier thread ready.");
	
	while(1) {
		snprintf(req, sizeof(req), "{\"jsonrpc\":\"1.0\",\"id\":\"%"PRIu64"\",\"method\":\"getbestblockhash\",\"params\":[]}", current_time_millis());
		gbbh = bitcoind_json_rpc_call(tcurl, &datum_config, req);
		if (gbbh) {
			res_val = json_object_get(gbbh, "result");
			if (!res_val) {
				DLOG_ERROR("ERROR: Could not decode getbestblockhash result!");
			} else {
				s = json_string_value(res_val);
				if (s) {
					if (strlen(s) == 64) {
						if (p1[0] == 0) {
							strncpy(p1,s,70);
						} else {
							if (strcmp(s, p1) != 0) {
								// new block?!?!?!
								datum_blocktemplates_notifynew(s,0);
								strncpy(p1,s,70);
							}
						}
					}
				}
			}
			json_decref(gbbh);
			gbbh = NULL;
		}
		sleep(1);
	}
}

void *datum_gateway_template_thread(void *args) {
	CURL *tcurl = NULL;
	json_t *gbt = NULL, *res_val;
	uint64_t i = 0;
	char gbt_req[1024];
	int j;
	T_DATUM_TEMPLATE_DATA *t;
	bool was_notified = false;
	int wnc = 0;
	uint64_t last_block_change = 0;
	pthread_t pthread_datum_gateway_fallback_notifier;
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL");
		panic_from_thread(__LINE__);
	}
	
	if (datum_template_init() < 1) {
		DLOG_FATAL("Couldn't setup template processor.");
		panic_from_thread(__LINE__);
	}
	
	{
		unsigned char dummy[64];
		if (!addr_2_output_script(datum_config.mining_pool_address, &dummy[0], 64)) {
			if (datum_config.api_modify_conf) {
				DLOG_ERROR("Could not generate output script for pool addr! Perhaps invalid? Configure via API/dashboard.");
			} else {
				DLOG_FATAL("Could not generate output script for pool addr! Perhaps invalid? This is bad.");
				panic_from_thread(__LINE__);
			}
		}
		while (!addr_2_output_script(datum_config.mining_pool_address, &dummy[0], 64)) {
			usleep(50000);
		}
	}
	
	if (datum_config.bitcoind_notify_fallback) {
		// start getbestblockhash poller thread as a backup for notifications
		DLOG_DEBUG("Starting fallback block notifier");
		pthread_create(&pthread_datum_gateway_fallback_notifier, NULL, datum_gateway_fallback_notifier, NULL);
	}
	
	DLOG_DEBUG("Template fetcher thread ready.");
	
	char p1[72];
	p1[0] = 0;
	
	while(1) {
		i++;
		
		// fetch latest template
		if (!strcmp(datum_config.mining_pow_algorithm, "blake2b")) {
			snprintf(gbt_req, sizeof(gbt_req), "{\"method\":\"getblocktemplate\",\"params\":[{\"rules\":[\"segwit\",\"blake2b\"]}],\"id\":%"PRIu64"}",(uint64_t)((uint64_t)time(NULL)<<(uint64_t)8)|(uint64_t)(i&255));
		} else {
			snprintf(gbt_req, sizeof(gbt_req), "{\"method\":\"getblocktemplate\",\"params\":[{\"rules\":[\"segwit\"]}],\"id\":%"PRIu64"}",(uint64_t)((uint64_t)time(NULL)<<(uint64_t)8)|(uint64_t)(i&255));
		}
		gbt = bitcoind_json_rpc_call(tcurl, &datum_config, gbt_req);
		
		if (!gbt) {
			datum_blocktemplates_error = "Could not fetch new template!";
			DLOG_ERROR("Could not fetch new template from %s!", datum_config.bitcoind_rpcurl);
			sleep(1);
			continue;
		} else {
			res_val = json_object_get(gbt, "result");
			if (!res_val) {
				datum_blocktemplates_error = "Could not decode GBT result!";
				DLOG_ERROR("%s", datum_blocktemplates_error);
			} else {
				datum_template_apply_supplier(res_val);   // template mode: inyecta el tx-set del supplier
				DLOG_DEBUG("DEBUG: calling datum_gbt_parser (new=%d)", was_notified?1:0);
				t = datum_gbt_parser(res_val);
				
				if (t) {
					datum_blocktemplates_error = NULL;
					DLOG_DEBUG("height: %lu / value: %"PRIu64, (unsigned long)t->height, t->coinbasevalue);
					DLOG_DEBUG("--- prevhash: %s", t->previousblockhash);
					DLOG_DEBUG("--- txn_count: %u / sigops: %u / weight: %u / size: %u", t->txn_count, t->txn_total_sigops, t->txn_total_weight, t->txn_total_size);
					
					// If the previous block hash changed, or work is no longer valid, we should push clean work
					const bool new_block = strcmp(t->previousblockhash, p1);
					if (new_block || notify_othercause) {
						notify_othercause = 0;
						update_stratum_job(t,true,JOB_STATE_EMPTY_PLUS);
						if (new_block) {
							last_block_change = current_time_millis();
							strcpy(p1, t->previousblockhash);
							was_notified = false;
							DLOG_INFO("NEW NETWORK BLOCK: %s (%lu)", t->previousblockhash, (unsigned long)t->height);
						} else {
							DLOG_DEBUG("Urgent work update triggered");
						}
						
						// sleep for a milisecond
						// this will let other threads churn for a moment.  we wont get all the empty jobs blasted out in a milisecond anyway
						usleep(1000);
						
						// wait for the empties to complete
						DLOG_DEBUG("Waiting on empty work send completion...");
						for(j=0;j<4000;j++) {
							if (stratum_latest_empty_check_ready_for_full()) break;
							usleep(1001);
						}
						DLOG_DEBUG("Empty sends done!");
						
						// use this template to setup for a coinbaser wait job while the empty + full w/blank jobs are blasted
						// then this job will get blasted when its ready.
						i = datum_stratum_v1_global_subscriber_count();
						DLOG_INFO("Updating priority stratum job for block %lu: %.8f BTC, %lu txns, %lu bytes (Sent to %llu stratum client%s)", (unsigned long)t->height, (double)t->coinbasevalue / (double)100000000.0, (unsigned long)t->txn_count, (unsigned long)t->txn_total_size, (unsigned long long)i, (i!=1)?"s":"");
						update_stratum_job(t,false,JOB_STATE_FULL_PRIORITY_WAIT_COINBASER);
					} else {
						if (was_notified) {
							// we got a notification of a new block, but there doesn't seem to actually be a new block.
							// we should quickly check again instead of actually updating the stratum job
							
							pthread_mutex_lock(&new_notify_lock);
							if ((new_notify_blockhash[0] > 0) && (!strcmp(t->previousblockhash,(char *)new_notify_blockhash))) {
								// we got notified for work we already knew about
								if (new_notify_height <= 0) {
									was_notified = false;
									wnc = 0;
								} else {
									if (new_notify_height == t->height) {
										was_notified = false;
										wnc = 0;
									}
								}
							}
							if (!was_notified) {
								DLOG_DEBUG("Multi notified for block we knew details about. (%s)", new_notify_blockhash);
							} else {
								DLOG_DEBUG("Notified, however new = %s, t->previousblockhash = %s, t->height = %lu, new_notify_height = %d", new_notify_blockhash, t->previousblockhash, (unsigned long)t->height, new_notify_height);
								
								// Sometimes we call GBT before we get the signal from a blocknotify.  It's a bit of a race condition.
								// Instead of freaking out, we'll just ignore things when we get a signal that results in the same block if it was
								// within 2.5s of a previous block change.
								// absolute worst case scenario here is that there's a reverse race condition of some kind where we get our notify early and GBT is still
								// returning the old block data... then we'd be one work change delay behind things.
								// that shouldn't be possible, though, if the notify comes from the same bitcoind that we're getting our templates from
								if ((current_time_millis()-2500) < last_block_change) {
									DLOG_DEBUG("This is probably a duplicate signal, since we just changed blocks less than 2.5s ago");
									was_notified = false;
								}
								
								if (((t->height < 800000) || (t->height > 2980000)) && (new_notify_blockhash[0] == 'T')) { // some hardcoded guardrails that should last for quite some time for testnet3 and testnet4
									DLOG_DEBUG("DEBUG: TESTNET FAST FORWARD HACK!!!");
									
									// set diff 1
									strcpy(t->bits, "1d00ffff");
									for(j=0;j<4;j++) {
										t->bits_bin[3-j] = hex2bin_uchar(&t->bits[j<<1]);
									}
									t->bits_uint = upk_u32le(t->bits_bin, 0);
									nbits_to_target(t->bits_uint, t->block_target);
									// ff 20 min
									if (new_notify_height > t->curtime) {
										t->curtime = new_notify_height;
										new_notify_height = -1;
									} else {
										t->curtime += 1200;
									}
									
									DLOG_DEBUG("t->curtime = %llu", (unsigned long long)t->curtime);
									
									update_stratum_job(t,true,JOB_STATE_FULL_PRIORITY_WAIT_COINBASER);
									new_notify_blockhash[0] = 0;
									was_notified = false;
								}
							}
							pthread_mutex_unlock(&new_notify_lock);
						} else {
							i = datum_stratum_v1_global_subscriber_count();
							DLOG_INFO("Updating standard stratum job for block %lu: %.8f BTC, %lu txns, %lu bytes (Sent to %llu stratum client%s)", (unsigned long)t->height, (double)t->coinbasevalue / (double)100000000.0, (unsigned long)t->txn_count, (unsigned long)t->txn_total_size, (unsigned long long)i, (i!=1)?"s":"");
							update_stratum_job(t,false,JOB_STATE_FULL_NORMAL_WAIT_COINBASER);
						}
					}
				}
			}
			json_decref(gbt);
		}
		gbt = NULL;
		
		if ((!was_notified) || (new_notify || new_notify_threadsafe)) {
			uint64_t wait_us = (uint64_t)datum_config.bitcoind_work_update_seconds * (uint64_t)1000000;
			// Carousel fast re-cycle: right after a block the fresh set is thin (suppliers publish for the new tip
			// within seconds). While it is empty or below half of the previous block's set, cycle again sooner so
			// miners spend seconds, not a full work cycle, on the pool's own tx-set / the single fastest supplier.
			if (datum_config.mining_blake2b_template_carousel && datum_config.mining_template_fast_recycle_ms > 0
			    && (current_time_millis() - last_block_change) < 30000) {
				int n, nprev; bool act;
				pthread_mutex_lock(&g_carousel_rot.lock);
				n = g_carousel_rot.n; nprev = g_carousel_rot.n_prev_block; act = g_carousel_rot.active;
				pthread_mutex_unlock(&g_carousel_rot.lock);
				if (act && (n == 0 || (nprev >= 2 && n < nprev / 2))) {
					wait_us = (uint64_t)datum_config.mining_template_fast_recycle_ms * 1000ULL;
					DLOG_INFO("carousel: fresh set thin (n=%d, prev block n=%d) — fast re-cycle in %d ms", n, nprev, datum_config.mining_template_fast_recycle_ms);
				}
			}
			for(i=0;i<(wait_us/(uint64_t)2500);i++) {
				usleep(2500);
				if (new_notify || new_notify_threadsafe) {
					new_notify = 0;
					new_notify_threadsafe = 0;
					was_notified = 1;
					wnc = 0;
					DLOG_INFO("NEW NETWORK BLOCK NOTIFICATION RECEIVED");
					break;
				}
			}
		} else {
			usleep(250000);
			wnc++;
			if (wnc > 16) { // 4 seconds
				// something is weird.
				DLOG_WARN("We received a new block notification, however after 16 attempts we did not see a new block.");
				was_notified = false;
				wnc = 0;
			}
		}
	}
	// this thread is never intended to exit unless the application dies
	
	// TODO: Clean things up
}
