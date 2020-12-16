#include "sign.h"

// Source: (FOR TESTING ONLY)
// https://gist.github.com/lattera/5246337

unsigned char *simple_digest(unsigned char *buf, unsigned int len, unsigned int *olen)
{
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    unsigned char *ret;
    const EVP_MD *sha256;

    sha256 = EVP_sha256();

    if (!(ret = (unsigned char *)malloc(EVP_MAX_MD_SIZE)))
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

unsigned char *simple_sign(char *keypath, unsigned char *data, unsigned int len, unsigned int *olen)
{
    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;
    const EVP_MD *sha256;
    unsigned char *sig;
    FILE *keyfp;

    if (!(keyfp = fopen(keypath, "r"))) {
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
        return NULL;
    }

    if (!(ctx = EVP_MD_CTX_create())) {
        fprintf(stderr, "EVP_MD_CTX_create failed!\n");
        free(sig);
        fclose(keyfp);
        return NULL;
    }

    EVP_SignInit(ctx, sha256);
    EVP_SignUpdate(ctx, data, len);
    EVP_SignFinal(ctx, sig, olen, pkey);

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

int sign_data(unsigned char * data, int data_size, char * privkey, unsigned char * signature)
{
    unsigned char *hash, *sig;
    unsigned int hashlen;
    unsigned int siglen;

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

    strncpy((char *)signature, (char *)sig, siglen);

    return 0;
}

int simple_verify(char *certpath, unsigned char *sig, unsigned int sigsz, unsigned char *buf, unsigned int len)
{
    FILE *certfp;
    X509 *cert;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    const EVP_MD *sha256;
    int ret;
    unsigned int olen;
    unsigned char *digest;

    digest = simple_digest(buf, len, &olen);

    if (!(ctx = EVP_MD_CTX_create())) {
        fprintf(stderr, "[-] EVP_MD_CTX_create failed!\n");
        return 0;
    }

    sha256 = EVP_sha256();

    if (!EVP_VerifyInit(ctx, sha256)) {
        fprintf(stderr, "[-] EVP_VerifyInit failed!\n");
        return 0;
    }

    if (!EVP_VerifyUpdate(ctx, digest, olen)) {
        fprintf(stderr, "[-] EVP_VerifyUpdate failed!\n");
        return 0;
    }

    if (!(certfp = fopen(certpath, "r"))) {
        perror("fopen");
        return 0;
    }

    if (!(cert = PEM_read_X509(certfp, NULL, NULL, NULL))) {
        fprintf(stderr, "[-] Could not read x509 cert\n");
        fclose(certfp);
        return 0;
    }

    if (!(pkey = X509_get_pubkey(cert))) {
        fprintf(stderr, "X509_get_pubkey failed!\n");
        fclose(certfp);
        return 0;
    }

    ret = EVP_VerifyFinal(ctx, sig, sigsz, pkey);
    if (ret == 0) {
        fprintf(stderr, "EVP_VerifyFinal failed!\n");
    }

    fclose(certfp);

    return ret;
}

int verify_data(unsigned char * data, int data_size, char * certfile, unsigned char * signature, int siglen)
{
    int res;

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
