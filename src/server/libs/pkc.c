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

mbedtls_ecp_keypair * temp_pair;

////// Perform ECDH + KDF (PKCS#5)
/*
uint8_t SecComm(uint8_t * cli_pub_x, uint8_t * cli_pub_y)
{
	int ret = 0;

	const char pers[] = "ecdh";

	mbedtls_entropy_context SecComm_entropy;
	mbedtls_ctr_drbg_context SecComm_ctr_drbg;

	mbedtls_ctr_drbg_init(&SecComm_ctr_drbg);
	mbedtls_entropy_init(&SecComm_entropy);

	// seed seed for drbg
	if( ( ret = mbedtls_ctr_drbg_seed(&SecComm_ctr_drbg, mbedtls_entropy_func, &SecComm_entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
	{
		mbedtls_entropy_free(&SecComm_entropy);
		return 0;
	}

	mbedtls_ecdh_context ctx_srv;
	mbedtls_ecdh_init(&ctx_srv);

	////// Parse private and public and transform them into ec key pairs
	mbedtls_pk_context pk_ctx_pri;
	mbedtls_pk_init(&pk_ctx_pri);

	// Parse private key
	ret = mbedtls_pk_parse_key(&pk_ctx_pri, SESS_PRIVATE_KEY, strlen((char *)SESS_PRIVATE_KEY)+1, NULL, 0);
	if(ret != 0)
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_ecdh_free(&ctx_srv);
		mbedtls_pk_free(&pk_ctx_pri);

		return 0;
	}

	// pk -> ec pair
	temp_pair = mbedtls_pk_ec(pk_ctx_pri);

	// grp
	ctx_srv.grp = temp_pair->grp;

	// private
	mbedtls_mpi oldD = ctx_srv.d;
	ctx_srv.d = temp_pair->d;

	temp_pair = NULL;

	//// Compute shared secret
	// store client's public key X into ctx_srv public key
	ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.X, cli_pub_x, 48u);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);

		return 0;
	}

	// store client's public key Y into ctx_srv public key
	ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.Y, cli_pub_y, 48u);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);

		return 0;
	}

	ret = mbedtls_mpi_lset(&ctx_srv.Qp.Z, 1);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);

		return 0;
	}

	// compute shared secret
	int len = 0;
	uint8_t shared_secret[128] = {0};
	ret = mbedtls_ecdh_calc_secret(&ctx_srv, &len, shared_secret, 128u, mbedtls_ctr_drbg_random, &SecComm_ctr_drbg);
	if(ret != 0)
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);

		return 0;
	}

	///// PKCS#5 Key derivation to obtain sessionKey and HMAC Key

	const mbedtls_md_info_t *md_info;
	mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
	mbedtls_md_context_t md_ctx;
	mbedtls_md_init( &md_ctx );
	uint8_t expandedKey[64] = {0};

	md_info = mbedtls_md_info_from_type( md_type );
	if( md_info == NULL )
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);

		mbedtls_md_free(&md_ctx);

		return 0;
	}

	if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);

		mbedtls_md_free(&md_ctx);

		return 0;
	}

	ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, shared_secret, len, salt_IV, 16, 1, 64, expandedKey);
	if(ret != 0)
	{
		mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
		mbedtls_entropy_free(&SecComm_entropy);

		mbedtls_pk_free(&pk_ctx_pri);
		ctx_srv.d = oldD;
		mbedtls_ecdh_free(&ctx_srv);

		mbedtls_md_free(&md_ctx);

		return 0;
	}
	mbedtls_md_free(&md_ctx);

	uint8_t sessKey[32] = {0}, hmacKey[32] = {0};
	memcpy(&sessKey[0], expandedKey, 32);
	memcpy(&hmacKey[0], &expandedKey[32], 32);


	mbedtls_ctr_drbg_free(&SecComm_ctr_drbg);
	mbedtls_entropy_free(&SecComm_entropy);
	// The actual values (mbedtls_mpi) of Q and d contain pointers to mbedtls_mpi_uint so this is freed here only
	mbedtls_pk_free(&pk_ctx_pri);
	ctx_srv.d = oldD;
	mbedtls_ecdh_free(&ctx_srv);

	return 0;
}
*/
