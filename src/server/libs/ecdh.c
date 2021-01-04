#include "openssl/evp.h"
#include "openssl/ec.h"

// Import public key from local certificate file
EVP_PKEY * import_public_key (uint8_t *certpath)
{
	FILE *certfp;
	X509 *cert;
	EVP_PKEY *key = NULL;

	if (!(certfp = fopen((char *)certpath, "r"))) {
		perror("fopen");
		return NULL;
	}

	if (!(cert = PEM_read_X509(certfp, NULL, NULL, NULL))) {
		fprintf(stderr, "[CRYPTO] Could not read x509 cert\n");
		fclose(certfp);
		return NULL;
	}
	fclose(certfp);

	if (!(key = X509_get_pubkey(cert))) {
		fprintf(stderr, "[CRYPTO] X509_get_pubkey failed!\n");
		X509_free(cert);
		return NULL;
	}
	X509_free(cert);
	return key;
}

// Import private key from local file
EVP_PKEY * import_private_key(uint8_t *keypath)
{
	FILE *keyfp;
	EVP_PKEY *key;

	if (!(keyfp = fopen((char *)keypath, "r"))) {
		perror("fopen");
		return NULL;
	}

	if (!(key = PEM_read_PrivateKey(keyfp, NULL, NULL, NULL))) {
		fprintf(stderr, "[CRYPTO] PEM_read_PrivateKey failed!\n");
		fclose(keyfp);
		return NULL;
	}
	fclose(keyfp);
	return key;
}

// Generate new ECC key
// Unused currently
uint8_t generate_ecc_key (EVP_PKEY *params, EVP_PKEY **key)
{
	EVP_PKEY_CTX *kctx;

	printf("hello\n");
	/* Create the context for the key generation */
	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
	{
		fprintf(stderr, "EVP_PKEY_CTX_new(params, NULL)) failed\n");
		return 0;
	}

	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(kctx))
	{
		fprintf(stderr, "EVP_PKEY_keygen_init(kctx) failed\n");
		EVP_PKEY_CTX_free(kctx);
		return 0;
	}
	if (1 != EVP_PKEY_keygen(kctx, key))
	{
		fprintf(stderr, "EVP_PKEY_keygen(kctx, &pkey) failed\n");
		EVP_PKEY_CTX_free(kctx);
		return 0;
	}
	EVP_PKEY_CTX_free(kctx);
	return 1;
}

// Implementation of ECDH protocol to compute shared secret
// Personal private key
// Other entities public key
// Returns shared secret
// Other entity computes the same secret from their private key and your public key
uint8_t *ecdh(uint8_t *privkeypath, uint8_t *peerkeypath, size_t *secret_len)
{
	EVP_PKEY_CTX *pctx;
	EVP_PKEY_CTX *ctx;
	uint8_t *secret;
	EVP_PKEY *pkey = NULL, *peerkey = NULL, *params = NULL;
	/* NB: assumes pkey, peerkey have been already set up */

	/* Create the context for parameter generation */
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
	{
		fprintf(stderr, "EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) failed\n");
		return NULL;
	}

	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(pctx))
	{
		fprintf(stderr, "EVP_PKEY_paramgen_init(pctx) failed\n");
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1))
	{
		fprintf(stderr, " EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) failed\n");
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(pctx, &params)) 
	{
		fprintf(stderr, "EVP_PKEY_paramgen(pctx, &params) failed\n");
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	// Import public and private keys
	peerkey = import_public_key(peerkeypath);
	if (peerkey == NULL)
	{
		fprintf(stderr, "Error opening file %s\n", privkeypath);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	pkey = import_private_key(privkeypath);
	if (pkey == NULL)
	{
		fprintf(stderr, "Error opening file %s\n", privkeypath);
		EVP_PKEY_free(peerkey);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}
	// ---------------------------

	// Begin computing secret
	/* Create the context for the shared secret derivation */
	if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
	{
		fprintf(stderr, "EVP_PKEY_CTX_new(pkey, NULL)) failed\n");
		EVP_PKEY_free(peerkey);
		EVP_PKEY_free(pkey);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	/* Initialise */
	if(1 != EVP_PKEY_derive_init(ctx))
	{
		fprintf(stderr, "EVP_PKEY_derive_init(ctx) failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peerkey);
		EVP_PKEY_free(pkey);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	/* Provide the peer public key */
	if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey))
	{
		fprintf(stderr, " EVP_PKEY_derive_set_peer(ctx, peerkey)failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peerkey);
		EVP_PKEY_free(pkey);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	/* Determine buffer length for shared secret */
	if(1 != EVP_PKEY_derive(ctx, NULL, secret_len))
	{
		fprintf(stderr, "EVP_PKEY_derive(ctx, NULL, secret_len) failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peerkey);
		EVP_PKEY_free(pkey);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	/* Create the buffer */
	if(NULL == (secret = OPENSSL_malloc(*secret_len)))
	{
		fprintf(stderr, "OPENSSL_malloc(*secret_len) failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peerkey);
		EVP_PKEY_free(pkey);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return NULL;
	}

	/* Derive the shared secret */
	if(1 != (EVP_PKEY_derive(ctx, secret, secret_len)))
	{
		fprintf(stderr, "EVP_PKEY_derive(ctx, secret, secret_len) failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peerkey);
		EVP_PKEY_free(pkey);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		free(secret);
		return NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);

	/* Never use a derived secret directly. Typically it is passed
	 * through some hash function to produce a key */
	return secret;
}
