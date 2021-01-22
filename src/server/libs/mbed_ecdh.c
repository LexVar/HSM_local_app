#include "mbed_ecdh.h"

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

// ECDH
uint8_t ecdh(uint8_t *privkey, uint8_t * public, uint8_t * secret, size_t * len)
{
	int ret = 0;

	const char pers[] = "ecdh";
	mbedtls_entropy_context ec_entropy;
	mbedtls_ctr_drbg_context ec_ctr_drbg;
	mbedtls_ctr_drbg_init(&ec_ctr_drbg);
	mbedtls_entropy_init(&ec_entropy);
	mbedtls_ecp_keypair * temp_pair;

	// Seed for drbg
	if( ( ret = mbedtls_ctr_drbg_seed(&ec_ctr_drbg, mbedtls_entropy_func, &ec_entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
	{
		mbedtls_entropy_free(&ec_entropy);
		return 1;
	}

	// ECDH context
	mbedtls_ecdh_context ctx_srv;
	mbedtls_ecdh_init(&ctx_srv);

	// Parse private and public and transform them into ec key pairs
	mbedtls_pk_context pk_ctx_pri;
	mbedtls_pk_init(&pk_ctx_pri);

	// Parse private key
	ret = mbedtls_pk_parse_key(&pk_ctx_pri, privkey, strlen((char *)privkey)+1, NULL, 0);
	if(ret != 0)
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ecdh_free(&ctx_srv);
		mbedtls_pk_free(&pk_ctx_pri);
		return 2;
	}

	// Parse other peer public key
	mbedtls_pk_context peer_ctx;
	mbedtls_pk_init(&peer_ctx);
	ret = mbedtls_pk_parse_public_key(&peer_ctx, public, strlen((char *)public)+1);
	if(ret != 0)
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ecdh_free(&ctx_srv);
		mbedtls_pk_free(&pk_ctx_pri);
		mbedtls_pk_free(&peer_ctx);
		return 3;
	}
	// Get ecp_key_pair structure - it contains ecc points
	mbedtls_ecp_keypair * peer_ecp = mbedtls_pk_ec(peer_ctx);

	// private key to ecc_key_pair
	temp_pair = mbedtls_pk_ec(pk_ctx_pri);
	// Set group from private key
	ctx_srv.grp = temp_pair->grp;
	// private
	mbedtls_mpi oldD = ctx_srv.d;
	ctx_srv.d = temp_pair->d;
	temp_pair = NULL;

	// Peer public key pair, write both X and Y points in buffer
	uint8_t cli_pub_x[48u],cli_pub_y[48u];
	ret = mbedtls_mpi_write_binary (&peer_ecp->Q.X, cli_pub_x, sizeof(cli_pub_x));
	ret = mbedtls_mpi_write_binary (&peer_ecp->Q.Y, cli_pub_y, sizeof(cli_pub_y));

	// char buffer[96];
	// mbedtls_mpi_write_binary (&ctx_srv.d, (uint8_t *)buffer, 96);
	// FILE *f = fopen("d.mpi", "w");
	// fwrite(buffer, 96, 1, f);
	// fclose(f);

	// store peer's public key X point from buffer into ecdh context
	ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.X, cli_pub_x, 48u);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);
		mbedtls_pk_free(&peer_ctx);
		return 4;
	}
	// store peer's public key Y point from buffer into ecdh context
	ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.Y, cli_pub_y, 48u);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);
		mbedtls_pk_free(&peer_ctx);
		return 5;
	}

	ret = mbedtls_mpi_lset(&ctx_srv.Qp.Z, 1);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);
		mbedtls_pk_free(&peer_ctx);
		return 6;
	}

	// compute shared secret
	ret = mbedtls_ecdh_calc_secret(&ctx_srv, len, secret, 128u, mbedtls_ctr_drbg_random, &ec_ctr_drbg);
	if(ret != 0)
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);
		mbedtls_pk_free(&peer_ctx);
		return 7;
	}
	mbedtls_ctr_drbg_free(&ec_ctr_drbg);
	mbedtls_entropy_free(&ec_entropy);
	mbedtls_pk_free(&pk_ctx_pri);
	ctx_srv.d = oldD;
	mbedtls_ecdh_free(&ctx_srv);
	return 0;
}

// KDF: SHA256 with salt
// PKCS#5 Key derivation
uint8_t kdf(uint8_t * salt, size_t saltlen, uint8_t * shared_secret, size_t len, uint8_t *key)
{
	int ret;
	const mbedtls_md_info_t *md_info;
	mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
	mbedtls_md_context_t md_ctx;
	mbedtls_md_init( &md_ctx );

	// Set hashing context first
	md_info = mbedtls_md_info_from_type( md_type );
	if( md_info == NULL )
	{
		mbedtls_md_free(&md_ctx);
		return 1;
	}

	if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
	{
		mbedtls_md_free(&md_ctx);
		return 2;
	}

	// Generate new key from shared secret
	// md_ctx - context
	// shared_secret - generated from ecdh
	// len - secret length
	// salt - to add more entropy
	// saltlen - salt length
	// 1 - algorithm iteration count
	// size of generated key
	// key buffer
	ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, shared_secret, len, salt, saltlen, 10000, KEY_SIZE*2, key);
	if(ret != 0)
	{
		mbedtls_md_free(&md_ctx);
		return 3;
	}
	mbedtls_md_free(&md_ctx);
	return 0;
}
