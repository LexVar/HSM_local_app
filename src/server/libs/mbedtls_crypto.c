#include "mbedtls_crypto.h"

int mbed_sha256 (uint8_t * in, uint16_t len, uint8_t * hash)
{
	// Compute SHA-256 hash
	return mbedtls_sha256_ret(in, len, hash, 0);

}

// Returns 0 if successfull
// Calculates HMAC with SHA-256 of in buffer
int mbed_hmac (uint8_t * key, uint8_t * in, uint16_t len, uint8_t * out)
{
	 return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, KEY_SIZE*2*8, in, len, out);
}

// Returns 0 if successfull
// Works for both encryption and decryption
// Encryption: in -> plaintext, out -> ciphertext
// Decryption: in -> ciphertext, out -> plaintext
int mbed_aes_crypt(uint8_t * iv, uint8_t * in, uint8_t * out, uint16_t len, uint8_t * key)
{
	size_t nc_off = 0;
	int ret;
	uint8_t stream_block[16];

	memset (stream_block, 0 , 16);

	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);
	mbedtls_aes_setkey_enc(&aes_ctx, key, KEY_SIZE*8);
	ret = mbedtls_aes_crypt_ctr(&aes_ctx, len, &nc_off, iv, stream_block, in, out);
	mbedtls_aes_free(&aes_ctx);

	return ret;
}

int mbed_gen_pair_scalar(uint8_t * pri, uint8_t * pub)
{
	const unsigned char pers[] = "ecdh";
	int ret;
	mbedtls_pk_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, 4);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		mbedtls_pk_free(&ctx);
		return 1;
	}

	ret = mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 2;
	}

	// secp384r1
	ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP384R1, mbedtls_pk_ec(ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
	if( ret != 0 )
	{
		mbedtls_pk_free(&ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 3;
	}
	mbedtls_ecp_keypair * temp_pair = mbedtls_pk_ec(ctx);

	// Write public key to pub buffer
	ret = mbedtls_mpi_write_binary (&temp_pair->Q.X,(uint8_t *) pub, 48);
	ret = mbedtls_mpi_write_binary (&temp_pair->Q.Y,(uint8_t *) (pub+48), 48);
	if(ret != 0)
	{
		mbedtls_pk_free(&ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 4;
	}

	// Write private key scalar to priv buffer
	ret = mbedtls_mpi_write_binary (&temp_pair->d,(uint8_t *) pri, 48);
	if(ret != 0)
	{
		mbedtls_pk_free(&ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 5;
	}

	mbedtls_pk_free(&ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}

int mbed_gen_pair(uint8_t * pri, uint8_t * pub)
{
	const unsigned char pers[] = "ecdh";
	int ret;
	mbedtls_pk_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, 4);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		mbedtls_pk_free(&ctx);
		return 1;
	}

	ret = mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	printf ("hello: %d\n", ret);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 2;
	}

	// secp384r1
	ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP384R1, mbedtls_pk_ec(ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
	if( ret != 0 )
	{
		mbedtls_pk_free(&ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 3;
	}

	// Write public key to pub buffer
	ret = mbedtls_pk_write_pubkey_pem(&ctx, pub, 1000);
	if(ret != 0)
	{
		mbedtls_pk_free(&ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 4;
	}

	// Write private key to priv buffer
	ret = mbedtls_pk_write_key_pem(&ctx, pri, 1000);
	if(ret != 0)
	{
		mbedtls_pk_free(&ctx);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
		return 5;
	}

	mbedtls_pk_free(&ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}

uint8_t mbed_ecdh(uint8_t *privkey, uint8_t * public, uint8_t * secret, size_t * len)
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

uint8_t mbed_ecdh_scalar(uint8_t *privkey, uint8_t * public, uint8_t * secret, size_t * len)
{
	int ret = 0;
	const char pers[] = "ecdh";
	mbedtls_entropy_context ec_entropy;
	mbedtls_ctr_drbg_context ec_ctr_drbg;

	mbedtls_ctr_drbg_init(&ec_ctr_drbg);
	mbedtls_entropy_init(&ec_entropy);

	// Seed for drbg
	if( ( ret = mbedtls_ctr_drbg_seed(&ec_ctr_drbg, mbedtls_entropy_func, &ec_entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
	{
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		return 1;
	}

	// ECDH context
	mbedtls_ecdh_context ctx_srv;
	mbedtls_ecdh_init(&ctx_srv);

	ret = mbedtls_mpi_read_binary(&ctx_srv.d, privkey, 48u);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ecdh_free(&ctx_srv);
		return 2;
	}

	// store peer's public key X point from buffer into ecdh context
	ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.X, public, 48u);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ecdh_free(&ctx_srv);
		return 3;
	}
	// store peer's public key Y point from buffer into ecdh context
	ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.Y, public+48u, 48u);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ecdh_free(&ctx_srv);
		return 4;
	}

	ret = mbedtls_mpi_lset(&ctx_srv.Qp.Z, 1);
	if( ret != 0 )
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ecdh_free(&ctx_srv);
		return 5;
	}

	// compute shared secret
	ret = mbedtls_ecdh_calc_secret(&ctx_srv, len, secret, 128u, mbedtls_ctr_drbg_random, &ec_ctr_drbg);
	if(ret != 0)
	{
		mbedtls_ctr_drbg_free(&ec_ctr_drbg);
		mbedtls_entropy_free(&ec_entropy);
		mbedtls_ecdh_free(&ctx_srv);
		return 6;
	}

	mbedtls_ctr_drbg_free(&ec_ctr_drbg);
	mbedtls_entropy_free(&ec_entropy);
	mbedtls_ecdh_free(&ctx_srv);
	return 0;
}
