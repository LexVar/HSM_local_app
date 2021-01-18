/*
 * PKC.c
 *
 *  Created on: 10/02/2017
 *      Author: diogo
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pkc.h"

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

uint8_t PKC_signData(uint8_t * private, uint8_t * data, size_t data_len, uint8_t * signature, size_t * signature_len)
{
	mbedtls_pk_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "mbedtls_pk_sign";

	int ret = PKC_init(&ctx, &entropy, &ctr_drbg, pers, 0);

	if( ret != 0 )
		return 1;

	// Parse private key
	ret = mbedtls_pk_parse_key(&ctx, private, strlen((char *)private)+1, NULL, 0);
	if( ret != 0 )
	{
		PKC_free(&ctx, &entropy, &ctr_drbg);
		return 2;
	}

	if( ( ret = mbedtls_pk_sign(&ctx, MBEDTLS_MD_SHA256, data, 32, signature, signature_len, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
	{
		printf ("hello\n");
		PKC_free(&ctx, &entropy, &ctr_drbg);
		return 3;
	}

	PKC_free(&ctx, &entropy, &ctr_drbg);
	return 1;
}

int PKC_verifySignature(uint8_t * cert, uint8_t * data, size_t data_len, uint8_t * signature, size_t signature_len)
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt certificate;
	mbedtls_x509_crt_init(&certificate);
	size_t size;

	const char *pers = "mbedtls_pk_sign";

	int ret = PKC_init(NULL, &entropy, &ctr_drbg, pers, 0);

	if(ret != 0)
	{
		return 1;
	}

	size = strlen((char *)cert)+1;
	ret = mbedtls_x509_crt_parse(&certificate, cert, size);
	if(ret != 0)
	{
		PKC_free(NULL, &entropy, &ctr_drbg);
		return 1;
	}

	//Verify signature
	ret = mbedtls_pk_verify(&certificate.pk, MBEDTLS_MD_SHA256, data, 32, signature, signature_len);
	if(ret != 0)
	{
		PKC_free(NULL, &entropy, &ctr_drbg);
		mbedtls_x509_crt_free(&certificate);
		return 3;
	}

	mbedtls_x509_crt_free(&certificate);
	PKC_free(NULL, &entropy, &ctr_drbg);

	printf ("Successfully verified signature!\n");
	return 0;
}

int PKC_init(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg, const char * pers, uint8_t loadGroup)
{
	if (ctx != NULL)
		mbedtls_pk_init(ctx);
	mbedtls_ctr_drbg_init(ctr_drbg);
	mbedtls_entropy_init(entropy);

	int ret = 0;
	// if( ( ret = mbedtls_entropy_add_source(entropy, mbedtls_hardware_poll, NULL, ENTROPY_MIN_BYTES_RELEASE, MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )
	//         return ret;

	if( ( ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
		return ret;

	if (ctx != NULL && loadGroup)
		if((ret = mbedtls_pk_setup(ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
			return 0;

	return 0;
}

void PKC_free(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg)
{
	mbedtls_pk_free(ctx);
	mbedtls_ctr_drbg_free(ctr_drbg);
	mbedtls_entropy_free(entropy);
}

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
	ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, shared_secret, len, salt, saltlen, 1, KEY_SIZE*2, key);
	if(ret != 0)
	{
		mbedtls_md_free(&md_ctx);
		return 3;
	}
	mbedtls_md_free(&md_ctx);
	return 0;
}
