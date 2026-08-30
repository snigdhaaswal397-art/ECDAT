#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

RSA *generate_legacy_key() {
    RSA *rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    return rsa;
}

void hash_data(const unsigned char *data, size_t len, unsigned char *out) {
    MD5(data, len, out);
}

void sign_with_sha1(EVP_MD_CTX *ctx) {
    EVP_DigestInit(ctx, EVP_sha1());
}

void encrypt_with_des(DES_key_schedule *ks, const_DES_cblock *input, DES_cblock *output) {
    DES_ecb_encrypt(input, output, ks, DES_ENCRYPT);
}
