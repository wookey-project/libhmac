#include "libc/types.h"
#include "libc/regutils.h"
#include "libc/arpa/inet.h"
#include "libc/string.h"
#include "api/hmac.h"

int hmac_init(hmac_context *ctx, const uint8_t *hmackey, uint32_t hmackey_len, hash_alg_type hash_type){
        uint8_t ipad[MAX_BLOCK_SIZE];
        uint8_t opad[MAX_BLOCK_SIZE];
	uint8_t local_hmac_key[MAX_BLOCK_SIZE] = { 0 };
        unsigned int i, local_hmac_key_len;

	/* Set ipad and opad to appropriate values */
	memset(ipad, 0x36, sizeof(ipad));
	memset(opad, 0x5c, sizeof(opad));

        /* Get the hash mapping of the current asked hash function */
        ctx->hash = get_hash_by_type(hash_type);
        if(ctx->hash == NULL){
		goto err;
        }

        if(hmackey_len <= ctx->hash->block_size){
		/* The key size is less than the hash function block size */
		local_memcpy(local_hmac_key, hmackey, hmackey_len);
		local_hmac_key_len = hmackey_len;
        }
	else{
		/* The key size is greater than the hash function block size.
		 * We hash it to shorten it.
		 */
		hash_context tmp_ctx;
		/* Check our callback */
		if(hash_mapping_callbacks_sanity_check(ctx->hash)){
			goto err;
		}
		ctx->hash->hfunc_init(&tmp_ctx);
		/* Check our callback */
		if(hash_mapping_callbacks_sanity_check(ctx->hash)){
			goto err;
		}
		ctx->hash->hfunc_update(&tmp_ctx, hmackey, hmackey_len);
		/* Check our callback */
		if(hash_mapping_callbacks_sanity_check(ctx->hash)){
			goto err;
		}
		ctx->hash->hfunc_finalize(&tmp_ctx, local_hmac_key);
		local_hmac_key_len = ctx->hash->digest_size;
	}

        /* Initialize our input and output hash contexts */
	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		goto err;
	}
        ctx->hash->hfunc_init(&(ctx->in_ctx));
	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		goto err;
	}
        ctx->hash->hfunc_init(&(ctx->out_ctx));

        /* Update our input context with K^ipad */
        for(i = 0; i < local_hmac_key_len; i++){
                ipad[i] ^= local_hmac_key[i];
        }
	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		goto err;
	}
        ctx->hash->hfunc_update(&(ctx->in_ctx), ipad, ctx->hash->block_size);
        /* Update our output context with K^opad */
        for(i = 0; i < local_hmac_key_len; i++){
                opad[i] ^= local_hmac_key[i];
        }
	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		goto err;
	}
        ctx->hash->hfunc_update(&(ctx->out_ctx), opad, ctx->hash->block_size);

        return 0;

err:
        return -1;
}

void hmac_update(hmac_context *ctx, const uint8_t *input, uint32_t ilen){
	if(ctx == NULL){
		return;
	}
	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		return;
	}
	ctx->hash->hfunc_update(&(ctx->in_ctx), input, ilen);
	return;
}

int hmac_finalize(hmac_context *ctx, uint8_t *output, uint32_t *outlen){
	uint8_t in_hash[MAX_DIGEST_SIZE];

	if((ctx == NULL) || (ctx->hash == NULL)){
		goto err;
	}

	if((*outlen) < ctx->hash->digest_size){
		goto err;
	}

	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		goto err;
	}
	ctx->hash->hfunc_finalize(&(ctx->in_ctx), in_hash);
	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		goto err;
	}
	ctx->hash->hfunc_update(&(ctx->out_ctx), in_hash, ctx->hash->digest_size);
	/* Check our callback */
	if(hash_mapping_callbacks_sanity_check(ctx->hash)){
		goto err;
	}
	ctx->hash->hfunc_finalize(&(ctx->out_ctx), output);
	*outlen = ctx->hash->digest_size;

	return 0;
err:
	return -1;
}

int hmac_pbkdf2(hash_alg_type hash_type, const uint8_t *password, uint32_t password_len, const uint8_t *salt, uint32_t salt_len, uint32_t c, uint32_t dklen, uint8_t *output, uint32_t *outlen){
        uint8_t hmac[MAX_DIGEST_SIZE];
	uint8_t prev_hmac[MAX_DIGEST_SIZE];
	uint8_t pbkdf[MAX_DIGEST_SIZE];
	hmac_context hm_ctx, hm_ctx_init;
	const hash_mapping *hash;
	uint32_t i, j, k;
	unsigned int num_rounds;
	uint32_t hmac_len = MAX_DIGEST_SIZE;

        /* Get the hash mapping of the current asked hash function */
        hash = get_hash_by_type(hash_type);
        if(hash == NULL){
		goto err;
        }
	if((*outlen) < dklen){
		goto err;
	}
	if(hmac_init(&hm_ctx_init, password, password_len, hash_type)){
		goto err;
	}
	if(c == 0){
		goto err;
	}
	num_rounds = ((dklen % hash->digest_size) == 0) ? (dklen / hash->digest_size) : ((dklen / hash->digest_size) + 1);
	for(i = 0; i < num_rounds; i++){
		uint32_t big_i = htonl(i+1);
		local_memset(pbkdf, 0, sizeof(pbkdf));
		hm_ctx = hm_ctx_init;
		hmac_update(&hm_ctx, salt, salt_len);
		hmac_update(&hm_ctx, (uint8_t*)(&big_i), 4);
		if(hmac_finalize(&hm_ctx, hmac, &hmac_len)){
			goto err;
		}
		/* Xor previous hmac with current value */
		for(k = 0; k < hash->digest_size; k++){
			pbkdf[k] ^= hmac[k];
		}
		for(j = 0; j < (c-1); j++){
			local_memcpy(prev_hmac, hmac, hmac_len);
			hm_ctx = hm_ctx_init;
			hmac_update(&hm_ctx, prev_hmac, hmac_len);
			if(hmac_finalize(&hm_ctx, hmac, &hmac_len)){
				goto err;
			}
			/* Xor previous hmac with current value */
			for(k = 0; k < hash->digest_size; k++){
				pbkdf[k] ^= hmac[k];
			}
		}
		if((i == (num_rounds-1)) && ((dklen % hash->digest_size) != 0)){
			local_memcpy(output+(i * hash->digest_size), pbkdf, dklen % hash->digest_size);
		}
		else{
			local_memcpy(output+(i * hash->digest_size), pbkdf, hash->digest_size);
		}
	}

	*outlen = dklen;
	return 0;
err:
	return -1;
}
