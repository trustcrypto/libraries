/* okpqc.cpp - composite PQC PGP keys (ML-KEM-768 + ML-DSA-65). The slot
 * layout is in okpqc.h. */
#include "Arduino.h"
#include "okpqc.h"
#include <string.h>
#include <Ed25519.h>
#include "Curve25519.h"
#include <RNG.h>

#include "onlykey.h"

extern "C" int PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(uint8_t *pk, uint8_t *dk, const uint8_t *coins /*64B seed*/);
extern "C" int PQCP_MLKEM_NATIVE_MLKEM768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *dk);
extern "C" int PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
extern "C" int PQCP_MLDSA_NATIVE_MLDSA65_signature(uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);

extern "C" int onlykey_mldsa_randombytes(uint8_t *out, size_t outlen) {
    RNG.rand(out, (size_t)outlen);
    return 0;
}

extern uint8_t rsa_private_key[]; /* 160-byte blob after okcore_flashget_RSA */
extern uint8_t *large_buffer;
extern uint8_t *large_resp_buffer;
extern int large_buffer_offset;
extern uint8_t CRYPTO_AUTH;
extern uint8_t pending_operation;
extern int outputmode;
extern uint8_t packet_buffer_details[];
extern uint8_t profilekey[];
extern uint8_t ctap_buffer[]; /* large scratch (>= MLDSA_SIG_SIZE 3309) */


#ifndef OKDECRYPT_ERR_USER_ACTION_PENDING
#define OKDECRYPT_ERR_USER_ACTION_PENDING 0xF9
#endif
#ifndef CTAP2_ERR_OPERATION_PENDING
#define CTAP2_ERR_OPERATION_PENDING 0xF2
#endif
#ifndef CTAP2_ERR_DATA_READY
#define CTAP2_ERR_DATA_READY 0xF1
#endif
#ifndef LARGE_BUFFER_SIZE
#define LARGE_BUFFER_SIZE 1024
#endif

static int okpqc_ed25519_sign(uint8_t sig[64], const uint8_t *m, size_t mlen, const uint8_t sk[32]) {
    uint8_t priv[32], pub[32];
    memcpy(priv, sk, 32);
    Ed25519::derivePublicKey(pub, priv);
    Ed25519::sign(sig, priv, pub, m, mlen);
    memset(priv, 0, sizeof priv);
    return 0;
}

static int okpqc_x25519_shared(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t s[32], p[32];
    memcpy(s, scalar, 32);
    memcpy(p, point, 32);
    // Clamp the stored scalar (RFC 7748); Curve25519::eval() does not.
    s[0] &= 0xF8;
    s[31] = (s[31] & 0x7F) | 0x40;
    bool ok = Curve25519::eval(out, s, p);
    memset(s, 0, sizeof s);
    return ok ? 0 : -1;
}

/* One scratch for the expanded secret key: ML-DSA sk(4032) covers ML-KEM dk(2400);
 * never used simultaneously. In .bss so it isn't on the deep call stack. */
static uint8_t pqc_expanded_sk[MLDSA_SK_SIZE];


void okpqc_sign(uint8_t *buffer) {
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
        return;
    }
    if (CRYPTO_AUTH != 4) return;

    okcore_aes_gcm_decrypt(large_buffer, (uint8_t)packet_buffer_details[0],
        (uint8_t)packet_buffer_details[1], profilekey, large_buffer_offset);
    pending_operation = CTAP2_ERR_OPERATION_PENDING;
    outputmode = (int)packet_buffer_details[2];

    /* wire: large_buffer[0] = component selector, large_buffer[1..] = message digest */
    uint8_t sel = large_buffer[0];
    uint8_t *msg = large_buffer + 1;
    size_t msglen = (large_buffer_offset > 0) ? (size_t)(large_buffer_offset - 1) : 0;

    if (sel == PQC_HALF_PQC_PUBKEY) {
        uint8_t pk[MLDSA_PK_SIZE];
        int rc = PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(pk, pqc_expanded_sk,
            rsa_private_key + PQC_OFF_MLDSA_SEED);
        memset(pqc_expanded_sk, 0, sizeof pqc_expanded_sk);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) {
            pending_operation = 0;
            hidprint("Error ML-DSA keygen");
            return;
        }
        pending_operation = CTAP2_ERR_DATA_READY;
        /* Send rho, the first 32 bytes of the public key; the full 1952-byte key
         * does not fit in large_resp_buffer. rho identifies the key. */
        send_transport_response(pk, 32, true, true);
        fadeoff(85);
        return;
    }

    /* Exports private key material: DEBUG and OK_ALLOW_PQC_SEED_EXPORT builds only. */
#if defined(DEBUG) && defined(OK_ALLOW_PQC_SEED_EXPORT)
    if (sel == PQC_HALF_PQC_SEED) {
        pending_operation = CTAP2_ERR_DATA_READY;
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        send_transport_response(rsa_private_key + PQC_OFF_MLDSA_SEED, 32, true, true);
        fadeoff(85);
        return;
    }
#endif

    if (sel == PQC_HALF_ECC) { /* Ed25519 */
        uint8_t sig[ED25519_SIG_SIZE];
        okpqc_ed25519_sign(sig, msg, msglen, rsa_private_key + PQC_OFF_ED25519);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, ED25519_SIG_SIZE, true, true);
        memset(sig, 0, sizeof sig);
    } else { /* ML-DSA-65 */
        uint8_t pk[MLDSA_PK_SIZE];
        uint8_t *sig = ctap_buffer;
        size_t siglen = 0;
        int rc = PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(pk, pqc_expanded_sk,
            rsa_private_key + PQC_OFF_MLDSA_SEED);
        /* Sign the raw digest with an empty context string. */
        if (rc == 0) rc = PQCP_MLDSA_NATIVE_MLDSA65_signature(sig, &siglen, msg, msglen,
                         (const uint8_t *)0, 0, pqc_expanded_sk);
        memset(pqc_expanded_sk, 0, sizeof pqc_expanded_sk);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0 || siglen != MLDSA_SIG_SIZE) {
            pending_operation = 0;
            hidprint("Error ML-DSA sign");
            return;
        }
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, MLDSA_SIG_SIZE, true, true);
        memset(sig, 0, MLDSA_SIG_SIZE);
    }
    fadeoff(85);
}


void okpqc_decrypt(uint8_t *buffer) {
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
        return;
    }
    if (CRYPTO_AUTH != 4) return;

    okcore_aes_gcm_decrypt(large_buffer, (uint8_t)packet_buffer_details[0],
        (uint8_t)packet_buffer_details[1], profilekey, large_buffer_offset);
    pending_operation = CTAP2_ERR_OPERATION_PENDING;
    outputmode = (int)packet_buffer_details[2];

    /* component inferred from input size: 32 B ephemeral point -> X25519, 1088 B ct -> ML-KEM */
    if (large_buffer_offset == X25519_SS_SIZE) {
        uint8_t ss[X25519_SS_SIZE];
        int rc = okpqc_x25519_shared(ss, rsa_private_key + PQC_OFF_X25519, large_buffer);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) {
            pending_operation = 0;
            hidprint("Error X25519");
            return;
        }
        memcpy(large_resp_buffer, ss, X25519_SS_SIZE);
        memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, X25519_SS_SIZE, true, true);
    } else if (large_buffer_offset == MLKEM_CT_SIZE) {
        uint8_t pk[MLKEM_PK_SIZE], ss[MLKEM_SS_SIZE];
        /* The stored 64-byte seed is used directly as d||z. */
        int rc = PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(pk, pqc_expanded_sk, rsa_private_key + PQC_OFF_MLKEM_SEED);
        if (rc == 0) rc = PQCP_MLKEM_NATIVE_MLKEM768_dec(ss, large_buffer, pqc_expanded_sk);
        memset(pqc_expanded_sk, 0, MLKEM_DK_SIZE);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) {
            memset(ss, 0, sizeof ss);
            pending_operation = 0;
            hidprint("Error ML-KEM decaps");
            return;
        }
        memcpy(large_resp_buffer, ss, MLKEM_SS_SIZE);
        memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, MLKEM_SS_SIZE, true, true);
    } else {
        hidprint("Error PQC decrypt: bad input size");
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        pending_operation = 0;
    }
    fadeoff(85);
}
