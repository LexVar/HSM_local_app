#include <openssl/ssl.h>

/* NB: assumes eng, key, in, inlen are already set up,
 * and that key is an RSA public key
 */
int pub_encrypt (char * certpath, unsigned char * in, size_t inlen, unsigned char * out, size_t * outlen)
{
	EVP_PKEY_CTX *ctx;
	FILE *certfp;
	X509 *cert;
	EVP_PKEY *key;
	int ret;

	if (!(certfp = fopen(certpath, "r"))) {
		perror("fopen");
		return -1;
	}

	if (!(cert = PEM_read_X509(certfp, NULL, NULL, NULL))) {
		fprintf(stderr, "[CRYPTO] Could not read x509 cert\n");
		return -1;
	}
	fclose(certfp);

	if (!(key = X509_get_pubkey(cert))) {
		fprintf(stderr, "[CRYPTO] X509_get_pubkey failed!\n");
		X509_free(cert);
		return -1;
	}
	ctx = EVP_PKEY_CTX_new(key, NULL);
	if (!ctx)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_CTX_new failed\n");
		X509_free(cert);
		EVP_PKEY_free(key);
		return -1;
	}
	if (EVP_PKEY_encrypt_init(ctx) <= 0)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_encrypt_init failed\n");
		EVP_PKEY_CTX_free(ctx);
		X509_free(cert);
		EVP_PKEY_free(key);
		return -1;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_CTX_set_rsa_padding failed\n");
		EVP_PKEY_CTX_free(ctx);
		X509_free(cert);
		EVP_PKEY_free(key);
		return -1;
	}
	if (EVP_PKEY_encrypt(ctx, NULL, outlen, in, inlen) <= 0)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_encrypt failed\n");
		EVP_PKEY_CTX_free(ctx);
		X509_free(cert);
		EVP_PKEY_free(key);
		return -1;
	}

	/* Encrypted data is outlen bytes written to buffer out */
	ret = EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);

	EVP_PKEY_CTX_free(ctx);
	X509_free(cert);
	EVP_PKEY_free(key);

	return ret;
}

/* NB: assumes key in, inlen are already set up
* and that key is an RSA private key
*/
int private_decrypt (char * keypath, unsigned char * in, size_t inlen, unsigned char * out, size_t * outlen)
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key;
	int ret;
	FILE *keyfp;

	if (!(keyfp = fopen(keypath, "r"))) {
		perror("fopen");
		return -1;
	}

	if (!(key = PEM_read_PrivateKey(keyfp, NULL, NULL, NULL))) {
		fprintf(stderr, "[CRYPTO] PEM_read_PrivateKey failed!\n");
		fclose(keyfp);
		return -1;
	}
	fclose(keyfp);

	ctx = EVP_PKEY_CTX_new(key, NULL);
	if (!ctx)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_CTX_new failed\n");
		EVP_PKEY_free(key);
		return -1;
	}
	if (EVP_PKEY_decrypt_init(ctx) <= 0)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_decrypt_init failed\n");
		EVP_PKEY_free(key);
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_CTX_set_rsa_padding failed\n");
		EVP_PKEY_free(key);
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}
	if (EVP_PKEY_decrypt(ctx, NULL, outlen, in, inlen) <= 0)
	{
		fprintf(stderr, "[CRYPTO] EVP_PKEY_encrypt failed\n");
		EVP_PKEY_free(key);
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	/* Decrypted data is outlen bytes written to buffer out */
	ret = EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key);
	return ret;
}
// int main (void)
// {
//         unsigned char msg [] = "Hello, this is a message";
//         unsigned char in[128], out[128];
//         size_t outlen, inlen;
//
//         inlen=strlen(msg);
//
//         pub_encrypt ("test.cert", msg, inlen, out, &outlen);
//         printf ("pub encrypt: %s\n", out);
//         printf ("size: %d\n", outlen);
//         private_decrypt ("test.key", out, outlen, in, &inlen);
//         printf ("private decrypt: %s\n", in);
//         printf ("size: %d\n", inlen);
//         return 0;
// }
