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

// int sys_keys_to_pem(uint8_t * private_key, uint8_t * pub_dest, uint32_t pub_size, uint8_t * pri_dest, uint32_t pri_size)
// {
//         int ret = 0;
//         uint8_t status = 0u;
//
//         mbedtls_ecp_keypair issuerPair;
//         mbedtls_ecp_keypair_init(&issuerPair);
//
//         ret = mbedtls_ecp_group_load(&issuerPair.grp, MBEDTLS_ECP_DP_SECP384R1);
//         if(ret != 0)
//                 return ret;
//
//         // 384-bit values
//         uint8_t d[48] = {0x00u};
//         memcpy(&d[0], &private_key[0], 48u);
//         uint8_t p[96] = {0x00u}; // P (x,y) -> (48B,48B)
//         uint8_t q[96] = {0x00u}; // Q (x,y) -> (48B,48B)
//
//         // Load private key
//         if((ret = mbedtls_mpi_read_binary(&issuerPair.d, d, 48)) != 0)
//                 return ret;
//
//         // Get base point G for NIST elliptic curve P-384.
//         MSS_SYS_ecc_get_base_point(p);
//
//         // Compute public key
//         status = MSS_SYS_ecc_point_multiplication(&d[0], &p[0], &q[0]); // Q = d * P
//         if(status != MSS_SYS_SUCCESS)
//                 return status;
//         else{
//                 // X coordinate of Q
//                 if((ret = mbedtls_mpi_read_binary(&issuerPair.Q.X, q, 48)) != 0)
//                         return ret;
//
//                 // Y coordinate of Q
//                 if((ret = mbedtls_mpi_read_binary(&issuerPair.Q.Y, &q[48], 48)) != 0)
//                         return ret;
//
//                 // Z coordinate of R
//                 if((ret = mbedtls_mpi_lset(&issuerPair.Q.Z, 1)) != 0)
//                         return ret;
//         }
//
//         ret = mbedtls_ecp_check_privkey(&issuerPair.grp, &issuerPair.d);
//         if(ret != 0)
//                 return ret;
//
//         ret = mbedtls_ecp_check_pubkey(&issuerPair.grp, &issuerPair.Q);
//         if(ret != 0)
//                 return ret;
//
//         //// Now it's time to convert both into PEM format
//         mbedtls_pk_context * pk_ctx = (mbedtls_pk_context*)malloc(sizeof(mbedtls_pk_context));
//         mbedtls_pk_init(pk_ctx);
//         if((ret = mbedtls_pk_setup(pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
//                 return ret;
//
//         // Set the key pair of our context
//         mbedtls_ecp_keypair * oldctx = pk_ctx->pk_ctx;
//         pk_ctx->pk_ctx = (mbedtls_ecp_keypair *)&issuerPair;
//
//         // Write a PEM string for the public key
//         ret = mbedtls_pk_write_pubkey_pem(pk_ctx, pub_dest, ECC_PUBLIC_KEY_SIZE);
//         if(ret != 0)
//                 return ret;
//
//         // Write a PEM string for the private key
//         ret = mbedtls_pk_write_key_pem(pk_ctx, pri_dest, ECC_PRIVATE_KEY_SIZE);
//         if(ret != 0)
//                 return ret;
//
//         pk_ctx->pk_ctx = oldctx; // we should set it back so we can free it properly below
//         mbedtls_pk_free(pk_ctx);
//         mbedtls_ecp_keypair_free(&issuerPair);
//
//         return 0;
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
	// mbedtls_ecp_keypair *ec = (mbedtls_ecp_keypair *)ctx.pk_ctx;
	// char buffer[96];
	// mbedtls_mpi_write_binary (&ec->d,(uint8_t *) buffer, 96);
	// FILE *f = fopen("d2.mpi", "w");
	// fwrite(buffer, 96, 1, f);
	// fclose(f);

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
