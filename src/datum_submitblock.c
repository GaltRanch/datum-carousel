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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <curl/curl.h>
#include <pthread.h>
#include <jansson.h>

#include "datum_utils.h"
#include "datum_conf.h"
#include "datum_jsonrpc.h"

pthread_mutex_t submitblock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t submitblock_cond = PTHREAD_COND_INITIALIZER;
int submit_block_triggered = 0;
const char *submitblock_ptr = NULL;
char submitblock_hash[256] = { 0 };

// Block submission must survive a momentarily overloaded node: bitcoind answers HTTP 503 ("Work queue depth
// exceeded") when its RPC queue is full, and a timeout/refused connection looks the same to us. With
// CURLOPT_FAILONERROR those came back as NULL, which the old code logged as "submitted successfully" -- a
// found block silently lost. Now: retry on transport failure with backoff (100 ms -> 2 s, ~1 minute total),
// never retry a real reply (accepted or rejected), and never claim success without one.
#ifndef DATUM_SUBMITBLOCK_MAX_ATTEMPTS
#define DATUM_SUBMITBLOCK_MAX_ATTEMPTS 40
#endif
#ifndef DATUM_SUBMITBLOCK_BACKOFF_MS
#define DATUM_SUBMITBLOCK_BACKOFF_MS 100
#endif
#define DATUM_SUBMITBLOCK_BACKOFF_MAX_MS 2000

void preciousblock(CURL *curl, char *blockhash) {
	json_t *json;
	char rpc_data[384];
	long http_code = 0;
	int attempt;
	snprintf(rpc_data, sizeof(rpc_data), "{\"method\":\"preciousblock\",\"params\":[\"%s\"],\"id\":1}", blockhash);
	for (attempt = 1; attempt <= 5; attempt++) {
		http_code = 0;
		json = bitcoind_json_rpc_call_http(curl, &datum_config, rpc_data, &http_code);
		if (json) { json_decref(json); return; }
		if (http_code == 200) return;   // real reply we could not use -- not a transport problem, retrying won't help
		DLOG_WARN("preciousblock %s attempt %d/5 got no reply (HTTP %ld), retrying", blockhash, attempt, http_code);
		usleep((useconds_t)DATUM_SUBMITBLOCK_BACKOFF_MS * 1000 * attempt);
	}
	return;
}

void datum_submitblock_doit(CURL *tcurl, char *url, const char *submitblock_req, const char *block_hash_hex) {
	json_t *r;
	char *s = NULL;
	long http_code = 0;
	int attempt;
	unsigned int backoff_ms = DATUM_SUBMITBLOCK_BACKOFF_MS;
	r = NULL;
	for (attempt = 1; attempt <= DATUM_SUBMITBLOCK_MAX_ATTEMPTS; attempt++) {
		http_code = 0;
		if (!url) {
			r = bitcoind_json_rpc_call_http(tcurl, &datum_config, submitblock_req, &http_code);
		} else {
			r = json_rpc_call_full(tcurl, url, NULL, submitblock_req, NULL, &http_code);
		}
		if (r) break;
		if (http_code == 200) break;   // the node answered, just not with a usable JSON-RPC reply: retrying won't change that
		DLOG_WARN("Block %s submit attempt %d/%d got no reply from the node (HTTP %ld) -- retrying in %u ms", block_hash_hex, attempt, DATUM_SUBMITBLOCK_MAX_ATTEMPTS, http_code, backoff_ms);
		usleep((useconds_t)backoff_ms * 1000);
		if (backoff_ms < DATUM_SUBMITBLOCK_BACKOFF_MAX_MS) backoff_ms *= 2;
	}
	
	if (!r) {
		// We never got a usable reply: we genuinely don't know whether the block was accepted. Never claim success.
		DLOG_ERROR("Did not get a valid response submitting block %s (last HTTP %ld)! It may or may not have been accepted -- CHECK YOUR NODE (the block JSON is in save_submitblocks_dir if configured)", block_hash_hex, http_code);
	} else {
		json_t * const res_val = json_object_get(r, "result");
		if (json_is_null(res_val)) {
			// a null result means success here
			DLOG_INFO("Block %s submitted to upstream node successfully!%s", block_hash_hex, attempt > 1 ? " (after retries)" : "");
		} else {
			s = json_dumps(res_val, JSON_ENCODE_ANY);
			if (!s) {
				DLOG_WARN("Upstream node rejected our block! (unknown)");
			} else {
				DLOG_WARN("Upstream node rejected our block! (%s)",s);
				free(s);
			}
		}
		json_decref(r);
	}
	
	// precious block!
	preciousblock(tcurl, submitblock_hash);
}

void *datum_submitblock_thread(void *ptr) {
	CURL *tcurl = NULL;
	int i;
	
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL for submitblock!!! This is REALLY REALLY BAD.  Like accidentally calling your wife your ex-girlfriend's name bad.");
		panic_from_thread(__LINE__);
	}
	
	DLOG_DEBUG("Submitblock thread active");
	
	while (1) {
		// Lock the mutex before waiting on the condition variable
		pthread_mutex_lock(&submitblock_mutex);
		
		// Wait for the event to be triggered
		while (!submit_block_triggered) {
			pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
		}
		
		if (submitblock_ptr != NULL) {
			DLOG_DEBUG("SUBMITTING BLOCK TO OUR NODE!");
			
			datum_submitblock_doit(tcurl,NULL,submitblock_ptr,submitblock_hash);
			
			if (datum_config.extra_block_submissions_count > 0) {
				for(i=0;i<datum_config.extra_block_submissions_count;i++) {
					DLOG_DEBUG("SUBMITTING BLOCK TO EXTRA NODE %d!",i+1);
					datum_submitblock_doit(tcurl,(char *)datum_config.extra_block_submissions_urls[i],submitblock_ptr,submitblock_hash);
				}
			}
			submitblock_ptr = NULL;
		}
		
		// Reset the event flag
		submit_block_triggered = 0;
		pthread_cond_broadcast(&submitblock_cond);
		
		// Unlock the mutex after processing
		pthread_mutex_unlock(&submitblock_mutex);
	}
	
	return NULL;
}

void datum_submitblock_waitfree(void) {
	pthread_mutex_lock(&submitblock_mutex);
	while (submit_block_triggered || submitblock_ptr != NULL) {
		pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
	}
	pthread_mutex_unlock(&submitblock_mutex);
}

void datum_submitblock_trigger(const char *ptr, const char *hash) {
	if (!ptr || !hash || strlen(hash) >= sizeof(submitblock_hash)) {
		DLOG_ERROR("Invalid block submission request");
		return;
	}
	
	pthread_mutex_lock(&submitblock_mutex);
	while (submit_block_triggered || submitblock_ptr != NULL) {
		pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
	}
	submitblock_ptr = ptr;
	strcpy(submitblock_hash, hash);
	submit_block_triggered = 1;
	pthread_cond_signal(&submitblock_cond);
	pthread_mutex_unlock(&submitblock_mutex);
}

typedef struct {
	const char *requests[2];
	char hashes[2][256];
	size_t consumed;
} T_DATUM_SUBMITBLOCK_TEST_STATE;

static void *datum_submitblock_test_consumer(void *ptr) {
	T_DATUM_SUBMITBLOCK_TEST_STATE *state = ptr;
	int i;
	
	usleep(10000);
	for(i=0;i<2;i++) {
		struct timespec deadline;
		pthread_mutex_lock(&submitblock_mutex);
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_sec++;
		while (!submit_block_triggered) {
			int wait_result = pthread_cond_timedwait(&submitblock_cond, &submitblock_mutex, &deadline);
			if (wait_result == ETIMEDOUT) {
				pthread_mutex_unlock(&submitblock_mutex);
				return NULL;
			}
			datum_test(wait_result == 0);
			if (wait_result != 0) {
				pthread_mutex_unlock(&submitblock_mutex);
				return NULL;
			}
		}
		
		state->requests[i] = submitblock_ptr;
		strcpy(state->hashes[i], submitblock_hash);
		state->consumed++;
		submitblock_ptr = NULL;
		submit_block_triggered = 0;
		pthread_cond_broadcast(&submitblock_cond);
		pthread_mutex_unlock(&submitblock_mutex);
	}
	return NULL;
}

void datum_submitblock_tests(void) {
	static const char first_request[] = "first block";
	static const char second_request[] = "second block";
	static const char first_hash[] = "00000001";
	static const char second_hash[] = "00000002";
	T_DATUM_SUBMITBLOCK_TEST_STATE state = {0};
	pthread_t consumer;
	int create_result;
	
	create_result = pthread_create(&consumer, NULL, datum_submitblock_test_consumer, &state);
	datum_test(create_result == 0);
	if (create_result != 0) return;
	datum_submitblock_trigger(first_request, first_hash);
	datum_submitblock_trigger(second_request, second_hash);
	datum_submitblock_waitfree();
	datum_test(pthread_join(consumer, NULL) == 0);
	datum_test(state.consumed == 2);
	datum_test(state.requests[0] == first_request);
	datum_test(state.requests[1] == second_request);
	datum_test(!strcmp(state.hashes[0], first_hash));
	datum_test(!strcmp(state.hashes[1], second_hash));
}

void datum_submitblock_init(void) {
	// TODO: Handle rare issues.
	pthread_t pthread_datum_submitblock_thread;
	pthread_create(&pthread_datum_submitblock_thread, NULL, datum_submitblock_thread, NULL);
	return;
}
