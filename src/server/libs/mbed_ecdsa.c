#include "mbed_ecdsa.h"

// int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
// {
//         mss_rtc_calendar_t calendar_count;
//         MSS_RTC_get_calendar_count(&calendar_count);
//
//         uint8_t puf_seed[32] = {0};
//         MSS_SYS_puf_get_random_seed(&puf_seed[0]);
//         uint8_t status;
//         if(status != MSS_SYS_SUCCESS)
//         {
//                 return 1; // error
//         }
//
//         memcpy(output, puf_seed, sizeof(uint8_t)*32);
//         *olen = sizeof(uint8_t)*32;
// }

uint8_t sign_data(uint8_t * private, uint8_t * data, size_t data_len, uint8_t * signature, size_t * signature_len)
{
	mbedtls_pk_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "mbedtls_pk_sign";
	uint8_t hash[HASH_SIZE];

	int ret = init_ctx(&ctx, &entropy, &ctr_drbg, pers, 0);

	if( ret != 0 )
		return 1;

	// Parse private key
	ret = mbedtls_pk_parse_key(&ctx, private, strlen((char *)private)+1, NULL, 0);
	if( ret != 0 )
	{
		free_ctx(&ctx, &entropy, &ctr_drbg);
		return 2;
	}

	// Compute SHA-256 hash
	mbedtls_sha256_ret(data, data_len, hash, 0);

	if( ( ret = mbedtls_pk_sign(&ctx, MBEDTLS_MD_SHA256, hash, HASH_SIZE, signature, signature_len, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
	{
		free_ctx(&ctx, &entropy, &ctr_drbg);
		return 3;
	}

	free_ctx(&ctx, &entropy, &ctr_drbg);
	return 0;
}

int verify_signature(uint8_t * public, uint8_t * data, size_t data_len, uint8_t * signature, size_t signature_len)
{
	mbedtls_pk_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "mbedtls_pk_sign";
	uint8_t hash[HASH_SIZE];

	int ret = init_ctx(&ctx, &entropy, &ctr_drbg, pers, 0);
	if(ret != 0)
		return 1;

	// Parse public key
	ret = mbedtls_pk_parse_public_key(&ctx, public, strlen((char *)public)+1);
	if( ret != 0 )
	{
		printf ("Error!\n");
		free_ctx(&ctx, &entropy, &ctr_drbg);
		return 2;
	}

	// Compute SHA-256 hash
	mbedtls_sha256_ret(data, data_len, hash, 0);

	//Verify signature
	ret = mbedtls_pk_verify(&ctx, MBEDTLS_MD_SHA256, hash, HASH_SIZE, signature, signature_len);
	if(ret != 0)
	{
		free_ctx(&ctx, &entropy, &ctr_drbg);
		return 3;
	}

	free_ctx(&ctx, &entropy, &ctr_drbg);
	printf ("Successfully verified signature!\n");
	return 0;
}

int init_ctx(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg, const char * pers, uint8_t loadGroup)
{
	mbedtls_pk_init(ctx);
	mbedtls_ctr_drbg_init(ctr_drbg);
	mbedtls_entropy_init(entropy);

	int ret = 0;
	// if( ( ret = mbedtls_entropy_add_source(entropy, mbedtls_hardware_poll, NULL, ENTROPY_MIN_BYTES_RELEASE, MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )
	//         return ret;

	if( ( ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
		return ret;

	if(loadGroup && (ret = mbedtls_pk_setup(ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
		return 0;

	return 0;
}

void free_ctx(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg)
{
	mbedtls_pk_free(ctx);
	mbedtls_ctr_drbg_free(ctr_drbg);
	mbedtls_entropy_free(entropy);
}
