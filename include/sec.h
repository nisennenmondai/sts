#ifndef SEC_H
#define SEC_H

#include "sts.h"

#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"

/*
 * @brief               obfuscate data
 * @param data          data to obfuscate
 * @param size          size of data
 * @return              null
 */
void sts_obfuscate(unsigned char *data, size_t size);

/*
 * @brief               clarify data
 * @param data          data to clarify
 * @param size          size of data
 * @return              null
 */
void sts_clarify(unsigned char *data, size_t size);

/*
 * @brief               verify the length of derived_ley.
 * @param buf           derived key.
 * @param size          size of derived_key.
 * @param len           reference length we want to verify (256).
 * @return              != 0 if length of derived_ley is not equal to len.
 */
int sts_verify_keysize(const unsigned char *key, size_t size, size_t len);

/*
 * @brief               verify if hash is equal
 * @param digest_a      hash a
 * @param digest b      hash b
 * @return              != 0 if hash is not equal 
 */
int sts_verify_hash(unsigned char *digest_a, unsigned char *digest_b);

/*
 * @brief               encrypt data using aes-ecb block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param input         data to be encrypted.
 * @param ouput         encrypted data.
 * @param size          size of data to be encrypted.
 * @param ecb_len       size of encrypted data aligned with ecb block.
 * @return              != 0 if encryption fails.
 */
int sts_encrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size, size_t *ecb_len);

/*
 * @brief               decrypt data using aes-ecb block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param input         encrypted data.
 * @param ouput         decrypted data.
 * @param ecb_len       size of encrypted data aligned with ecb block.
 * @return              != 0 if decryption fails.
 */
int sts_decrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t ecb_len);

/*
 * @brief               encrypt data using aes-cbc block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param iv            cbc initialization vector, should be random value, in
 *                      our case derived_key is used.
 * @param input         data to be encrypted.
 * @param ouput         decrypted data.
 * @param cbc_len       size of encrypted data aligned with cbc block.
 * @return              != 0 if encryption fails.
 */
int sts_encrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, 
                size_t size, size_t *cbc_len);

/*
 * @brief               decrypt data using aes-cbc block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param iv            cbc initialization vector, should be random value, in
 *                      our case derived_key is used.
 * @param input         encrypted data.
 * @param ouput         decrypted data.
 * @param cbc_len       size of encrypted data aligned with cbc block.
 * @return              != 0 if encryption fails.
 */
int sts_decrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, size_t cbc_len);

/*
 * @brief               generate a random number for key generation.
 * @param rng_state     this callback isn't used.
 * @param ouput         random gen.
 * @param len           length of output.
 * @return              != 0 if genrand fails.
 */
int sts_drbg(void *rng_state, unsigned char *output, size_t len);

/*
 * @brief               compute derived_key
 * @param X             X remote public key
 * @param Y             Y remote public key
 * @return              -1 if fails
 */
int sts_compute_shared_secret(char *X, char *Y, struct sts_context *ctx);

#endif /* SEC_H */
