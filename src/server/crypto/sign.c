#include "sign.h"

// Source: (FOR TESTING ONLY)
// https://gist.github.com/lattera/5246337

uint8_t *simple_digest(uint8_t *buf, uint32_t len, uint32_t *olen)
{
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    uint8_t *ret;
    const EVP_MD *sha256;

    sha256 = EVP_sha256();

    if (!(ret = (uint8_t *)malloc(EVP_MAX_MD_SIZE)))
    {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_DigestInit(ctx, sha256);
    EVP_DigestUpdate(ctx, buf, len);
    EVP_DigestFinal(ctx, ret, olen);

    EVP_MD_CTX_free(ctx);
    return ret;
}

uint8_t *simple_sign(uint8_t *keypath, uint8_t *data, uint32_t len, uint32_t *olen)
{
    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;
    const EVP_MD *sha256;
    uint8_t *sig;
    FILE *keyfp;

    if (!(keyfp = fopen((char *)keypath, "r"))) {
        perror("fopen");
        return NULL;
    }

    sha256 = EVP_sha256();

    if (!(pkey = PEM_read_PrivateKey(keyfp, NULL, NULL, NULL))) {
        fprintf(stderr, "PEM_read_PrivateKey failed!\n");
        fclose(keyfp);
        return NULL;
    }

    if (!(sig = calloc(1, EVP_PKEY_size(pkey)))) {
        perror("calloc");
        fclose(keyfp);
	EVP_PKEY_free(pkey);
        return NULL;
    }

    if (!(ctx = EVP_MD_CTX_create())) {
        fprintf(stderr, "EVP_MD_CTX_create failed!\n");
        free(sig);
	EVP_PKEY_free(pkey);
        fclose(keyfp);
        return NULL;
    }

    EVP_SignInit(ctx, sha256);
    EVP_SignUpdate(ctx, data, len);
    EVP_SignFinal(ctx, sig, olen, pkey);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    fclose(keyfp);

    return sig;
}

void *map_file(FILE *fp, size_t len)
{
    void *buf;

    buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fileno(fp), 0);
    if (buf == (void *)MAP_FAILED)
        return NULL;

    return buf;
}

uint32_t sign_data(uint8_t * data, uint32_t data_size, uint8_t * privkey, uint8_t * signature)
{
    uint8_t *hash, *sig;
    uint32_t hashlen;
    uint32_t siglen;

    if (!SSL_library_init())
        return -1;

    if (!(hash = simple_digest(data, data_size, &hashlen))) {
        fprintf(stderr, "Could not generate hash!\n");
        return -1;
    }

    if (!(sig = simple_sign(privkey, hash, hashlen, &siglen))) {
        fprintf(stderr, "Could not generate signature!\n");
        return -1;
    }

    memcpy(signature, sig, siglen);
    free(sig);
    free(hash);

    return 0;
}

uint32_t simple_verify(uint8_t *certpath, uint8_t *sig, uint32_t sigsz, uint8_t *buf, uint32_t len)
{
    FILE *certfp;
    X509 *cert;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    const EVP_MD *sha256;
    uint32_t ret;
    uint32_t olen;
    uint8_t *digest;

    digest = simple_digest(buf, len, &olen);

    if (!(ctx = EVP_MD_CTX_create())) {
        fprintf(stderr, "[-] EVP_MD_CTX_create failed!\n");
        return 0;
    }

    sha256 = EVP_sha256();

    if (!EVP_VerifyInit(ctx, sha256)) {
        fprintf(stderr, "[-] EVP_VerifyInit failed!\n");
	EVP_MD_CTX_free(ctx);
	free(digest);
        return 0;
    }

    if (!EVP_VerifyUpdate(ctx, digest, olen)) {
        fprintf(stderr, "[-] EVP_VerifyUpdate failed!\n");
	EVP_MD_CTX_free(ctx);
	free(digest);
        return 0;
    }

    if (!(certfp = fopen((char *)certpath, "r"))) {
        perror("fopen");
	EVP_MD_CTX_free(ctx);
	free(digest);
        return 0;
    }

    if (!(cert = PEM_read_X509(certfp, NULL, NULL, NULL))) {
        fprintf(stderr, "[-] Could not read x509 cert\n");
        fclose(certfp);
	EVP_MD_CTX_free(ctx);
	free(digest);
        return 0;
    }

    if (!(pkey = X509_get_pubkey(cert))) {
        fprintf(stderr, "X509_get_pubkey failed!\n");
        fclose(certfp);
	X509_free(cert);
	EVP_MD_CTX_free(ctx);
	free(digest);
        return 0;
    }

    ret = EVP_VerifyFinal(ctx, sig, sigsz, pkey);
    if (ret == 0) {
        fprintf(stderr, "EVP_VerifyFinal failed!\n");
    }

    EVP_MD_CTX_free(ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    fclose(certfp);
    free(digest);

    return ret;
}

uint32_t verify_data(uint8_t * data, uint32_t data_size, uint8_t * certfile, uint8_t * signature, uint32_t siglen)
{
    uint32_t res;

    if (!SSL_library_init())
        return -1;

    if ((res = simple_verify(certfile, signature, siglen, data, data_size))) {
        printf("[+] Verification succeeded!\n");
    } else {
        ERR_print_errors_fp(stderr);
        printf("[-] Verification failed!\n");
    }

    return res;
}
