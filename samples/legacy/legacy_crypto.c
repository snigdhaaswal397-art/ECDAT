#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

RSA *make_key(void) {
    RSA *rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    return rsa;
}

void hash_it(const unsigned char *data, size_t len, unsigned char *out) {
    MD5(data, len, out);
}

void hash_sha1(EVP_MD_CTX *ctx) {
    EVP_DigestInit(ctx, EVP_sha1());
}

void legacy_encrypt(const unsigned char *input, unsigned char *output, void *ks) {
    DES_ecb_encrypt(input, output, ks, DES_ENCRYPT);
}
