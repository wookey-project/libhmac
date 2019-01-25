#include "autoconf.h"
#include "api/hmac.h"

#ifdef HMAC_TEST_VECTORS
/*** HMAC test vectors, stolen from RFC4231 (https://tools.ietf.org/html/rfc4231) *****/
typedef struct {
        /* Test case name */
        const char *name;
        /* Hash function */
        hash_alg_type hash_type;
        /* Message */
        const uint8_t *msg;
        uint32_t msg_len;
	/* Key */
	const uint8_t *key;
	uint32_t key_len;
        /* Expected hmac and associated length */
        const uint8_t *exp_hmac;
        uint8_t exp_hmac_len;
} hmac_test_case;

#ifdef CONFIG_ECC_HASHNAME_SHA224
static const hmac_test_case hmac_sha224_test_case_1 = {
	.name = "HMAC_SHA224_1",
	.hash_type = SHA224,
	.msg = (uint8_t*)"Hi There",
	.msg_len = 8,
	.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	.key_len = 20,
	.exp_hmac = (uint8_t*)"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22",
	.exp_hmac_len = SHA224_DIGEST_SIZE,
};
#endif

#ifdef CONFIG_ECC_HASHNAME_SHA256
static const hmac_test_case hmac_sha256_test_case_1 = {
	.name = "HMAC_SHA256_1",
	.hash_type = SHA256,
	.msg = (uint8_t*)"Hi There",
	.msg_len = 8,
	.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	.key_len = 20,
	.exp_hmac = (uint8_t*)"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",
	.exp_hmac_len = SHA256_DIGEST_SIZE,
};
#endif

#ifdef CONFIG_ECC_HASHNAME_SHA384
static const hmac_test_case hmac_sha384_test_case_1 = {
	.name = "HMAC_SHA384_1",
	.hash_type = SHA384,
	.msg = (uint8_t*)"Hi There",
	.msg_len = 8,
	.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	.key_len = 20,
	.exp_hmac = (uint8_t*)"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6",
	.exp_hmac_len = SHA384_DIGEST_SIZE,
};
#endif

#ifdef CONFIG_ECC_HASHNAME_SHA512
static const hmac_test_case hmac_sha512_test_case_1 = {
	.name = "HMAC_SHA512_1",
	.hash_type = SHA512,
	.msg = (uint8_t*)"Hi There",
	.msg_len = 8,
	.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	.key_len = 20,
	.exp_hmac = (uint8_t*)"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54",
	.exp_hmac_len = SHA512_DIGEST_SIZE,
};
#endif


#ifdef CONFIG_ECC_HASHNAME_SHA224
static const hmac_test_case hmac_sha224_test_case_2 = {
	.name = "HMAC_SHA224_2",
	.hash_type = SHA224,
	.msg = (uint8_t*)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	.msg_len = 152,
	.key = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	.key_len = 131,
	.exp_hmac = (uint8_t*)"\x3a\x85\x41\x66\xac\x5d\x9f\x02\x3f\x54\xd5\x17\xd0\xb3\x9d\xbd\x94\x67\x70\xdb\x9c\x2b\x95\xc9\xf6\xf5\x65\xd1",
	.exp_hmac_len = SHA224_DIGEST_SIZE,
};
#endif

#ifdef CONFIG_ECC_HASHNAME_SHA256
static const hmac_test_case hmac_sha256_test_case_2 = {
	.name = "HMAC_SHA256_2",
	.hash_type = SHA256,
	.msg = (uint8_t*)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	.msg_len = 152,
	.key = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	.key_len = 131,
	.exp_hmac = (uint8_t*)"\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2",
	.exp_hmac_len = SHA256_DIGEST_SIZE,
};
#endif

#ifdef CONFIG_ECC_HASHNAME_SHA384
static const hmac_test_case hmac_sha384_test_case_2 = {
	.name = "HMAC_SHA384_2",
	.hash_type = SHA384,
	.msg = (uint8_t*)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	.msg_len = 152,
	.key = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	.key_len = 131,
	.exp_hmac = (uint8_t*)"\x66\x17\x17\x8e\x94\x1f\x02\x0d\x35\x1e\x2f\x25\x4e\x8f\xd3\x2c\x60\x24\x20\xfe\xb0\xb8\xfb\x9a\xdc\xce\xbb\x82\x46\x1e\x99\xc5\xa6\x78\xcc\x31\xe7\x99\x17\x6d\x38\x60\xe6\x11\x0c\x46\x52\x3e",
	.exp_hmac_len = SHA384_DIGEST_SIZE,
};
#endif

#ifdef CONFIG_ECC_HASHNAME_SHA512
static const hmac_test_case hmac_sha512_test_case_2 = {
	.name = "HMAC_SHA512_2",
	.hash_type = SHA512,
	.msg = (uint8_t*)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	.msg_len = 152,
	.key = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
	.key_len = 131,
	.exp_hmac = (uint8_t*)"\xe3\x7b\x6a\x77\x5d\xc8\x7d\xba\xa4\xdf\xa9\xf9\x6e\x5e\x3f\xfd\xde\xbd\x71\xf8\x86\x72\x89\x86\x5d\xf5\xa3\x2d\x20\xcd\xc9\x44\xb6\x02\x2c\xac\x3c\x49\x82\xb1\x0d\x5e\xeb\x55\xc3\xe4\xde\x15\x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58",
	.exp_hmac_len = SHA512_DIGEST_SIZE,
};
#endif



const hmac_test_case *hmac_tests[] = {
#ifdef CONFIG_ECC_HASHNAME_SHA224
    &hmac_sha224_test_case_1,
    &hmac_sha224_test_case_2,
#endif
#ifdef CONFIG_ECC_HASHNAME_SHA256
    &hmac_sha256_test_case_1,
    &hmac_sha256_test_case_2,
#endif
#ifdef CONFIG_ECC_HASHNAME_SHA384
    &hmac_sha384_test_case_1,
    &hmac_sha384_test_case_2,
#endif
#ifdef CONFIG_ECC_HASHNAME_SHA512
    &hmac_sha512_test_case_1,
    &hmac_sha512_test_case_2
#endif
};

int do_hmac_test_vectors(void){
	unsigned int i;

	for(i = 0; i < sizeof(hmac_tests) / sizeof(hmac_test_case*); i++){
		hmac_context hmac_ctx;
	        uint8_t hmac_out[MAX_DIGEST_SIZE];
		uint32_t hmac_out_len = MAX_DIGEST_SIZE;

		if(hmac_init(&hmac_ctx, hmac_tests[i]->key,  hmac_tests[i]->key_len,  hmac_tests[i]->hash_type)){
			dbg_log("[HMAC self tests] %s failed :-(\n", hmac_tests[i]->name);
			dbg_flush();
		}
		hmac_update(&hmac_ctx, hmac_tests[i]->msg, hmac_tests[i]->msg_len);
		if(hmac_finalize(&hmac_ctx, hmac_out, &hmac_out_len)){
			dbg_log("[HMAC self tests] %s failed :-(\n", hmac_tests[i]->name);
			dbg_flush();
		}
		if(hmac_out_len != hmac_tests[i]->exp_hmac_len){
			dbg_log("[HMAC self tests] %s failed :-(\n", hmac_tests[i]->name);
			dbg_flush();
		}
		if(memcmp(hmac_out, hmac_tests[i]->exp_hmac, hmac_tests[i]->exp_hmac_len)){
			dbg_log("[HMAC self tests] %s failed :-(\n", hmac_tests[i]->name);
			dbg_flush();
		}
		else{
                        dbg_log("[HMAC self tests] %s OK!\n", hmac_tests[i]->name);
			dbg_flush();
		}
	}

	return 0;
}

#endif
