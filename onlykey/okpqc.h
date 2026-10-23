/*
 * okpqc.h - OnlyKey composite post-quantum PGP keys (ML-KEM-768 + ML-DSA-65).
 *
 * An RSA slot (1-4) holds one composite key as a 160-byte seed blob:
 *   [0:32]   Ed25519 secret   (sign, ECC half)
 *   [32:64]  ML-DSA-65 seed   (sign, PQC half)     FIPS 204 32-byte seed
 *   [64:96]  X25519 secret    (decrypt, ECC half)
 *   [96:160] ML-KEM-768 seed  (decrypt, PQC half)  FIPS 203 64-byte seed (d||z)
 *
 * The PQC keys are expanded from their seeds at use time. Only the seeds are
 * stored.
 *
 * ML-KEM-768: mlkem-native. ML-DSA-65: mldsa-native with MLD_CONFIG_REDUCE_RAM.
 * Ed25519 / X25519: the firmware's existing primitives.
 */
#ifndef OKPQC_H
#define OKPQC_H
#include <stdint.h>

/* slot key type (per-slot EEPROM nibble) */
#define KEYTYPE_PQC_PGP 7
#define PQC_PGP_BLOB_LEN 160

#define PQC_OFF_ED25519 0
#define PQC_OFF_MLDSA_SEED 32
#define PQC_OFF_X25519 64
#define PQC_OFF_MLKEM_SEED 96

#define MLDSA65_SEED_LEN 32
#define MLKEM768_SEED_LEN 64

/* component selector (buffer[6]): which half of the composite to run */
#define PQC_HALF_ECC 0 /* Ed25519 / X25519 */
#define PQC_HALF_PQC 1 /* ML-DSA-65 / ML-KEM-768 */
/* sign path: return the ML-DSA-65 public key */
#define PQC_HALF_PQC_PUBKEY 2
/* Return the stored ML-DSA seed. Only with DEBUG and OK_ALLOW_PQC_SEED_EXPORT. */
#define PQC_HALF_PQC_SEED 3

/* sizes (FIPS 203 / 204) */
#define MLKEM_CT_SIZE 1088
#define MLKEM_SS_SIZE 32
#define MLKEM_DK_SIZE 2400
#define MLKEM_PK_SIZE 1184
#define MLDSA_SK_SIZE 4032
#define MLDSA_PK_SIZE 1952
#define MLDSA_SIG_SIZE 3309
#define ED25519_SIG_SIZE 64
#define X25519_SS_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif
/* Called from okcrypto_sign / okcrypto_decrypt for a KEYTYPE_PQC_PGP slot,
 * after okcore_flashget_RSA() has loaded the seed blob into rsa_private_key. */
void okpqc_sign(uint8_t *buffer); /* OKSIGN:    selector -> Ed25519 sig(64) | ML-DSA sig(3309) */
void okpqc_decrypt(uint8_t *buffer); /* OKDECRYPT: selector -> X25519 ss(32)  | ML-KEM ss(32)     */
#ifdef __cplusplus
}
#endif
#endif /* OKPQC_H */
