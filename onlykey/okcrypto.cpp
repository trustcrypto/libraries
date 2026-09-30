/* 
 * Copyright (c) 2015-2022, CryptoTrust LLC.
 * All rights reserved.
 * 
 * Author : Tim Steiner <t@crp.to>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "CryptoTrust" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" or "CryptoTrust" appear in their names without
 *    specific prior written permission. For written permission, please
 *    contact admin@crp.to.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 7. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for this software and any
 *    accompanying software that uses this software. The source code
 *    must either be included in the distribution or be available for
 *    no more than the cost of distribution plus a nominal fee, and must
 *    be freely redistributable under reasonable conditions. For a
 *    binary file, complete source code means the source code for all
 *    modules it contains.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS
 * ARE GRANTED BY THIS LICENSE. IF SOFTWARE RECIPIENT INSTITUTES PATENT
 * LITIGATION AGAINST ANY ENTITY (INCLUDING A CROSS-CLAIM OR COUNTERCLAIM
 * IN A LAWSUIT) ALLEGING THAT THIS SOFTWARE (INCLUDING COMBINATIONS OF THE
 * SOFTWARE WITH OTHER SOFTWARE OR HARDWARE) INFRINGES SUCH SOFTWARE
 * RECIPIENT'S PATENT(S), THEN SUCH SOFTWARE RECIPIENT'S RIGHTS GRANTED BY
 * THIS LICENSE SHALL TERMINATE AS OF THE DATE SUCH LITIGATION IS FILED. IF
 * ANY PROVISION OF THIS AGREEMENT IS INVALID OR UNENFORCEABLE UNDER
 * APPLICABLE LAW, IT SHALL NOT AFFECT THE VALIDITY OR ENFORCEABILITY OF THE
 * REMAINDER OF THE TERMS OF THIS AGREEMENT, AND WITHOUT FURTHER ACTION
 * BY THE PARTIES HERETO, SUCH PROVISION SHALL BE REFORMED TO THE MINIMUM
 * EXTENT NECESSARY TO MAKE SUCH PROVISION VALID AND ENFORCEABLE. ALL
 * SOFTWARE RECIPIENT'S RIGHTS UNDER THIS AGREEMENT SHALL TERMINATE IF IT
 * FAILS TO COMPLY WITH ANY OF THE MATERIAL TERMS OR CONDITIONS OF THIS
 * AGREEMENT AND DOES NOT CURE SUCH FAILURE IN A REASONABLE PERIOD OF
 * TIME AFTER BECOMING AWARE OF SUCH NONCOMPLIANCE. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR  PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstring>
#include "Arduino.h"
#include "onlykey.h"
#ifdef STD_VERSION
#include <SoftTimer.h>
#include "T3MacLib.h"
#include <RNG.h>
#include <AES.h>
#include <CBC.h>
#include <GCM.h>
#include <ChaCha.h>
#include <Crypto.h>
#include "sha1.h"
#include "sha512.h"
#include "yubikey.h"
#include "device.h"
#include "okcrypto.h"

/*************************************/
//ML-KEM-768 (FIPS 203) support
/*************************************/
extern "C" {
#include "mlkem_native.h"
}

extern "C" {
void PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void PQCP_MLKEM_NATIVE_MLKEM768_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
}
#define xwing_sha3_256 PQCP_MLKEM_NATIVE_MLKEM768_sha3_256
#define xwing_shake256 PQCP_MLKEM_NATIVE_MLKEM768_shake256

// X-Wing label: "\./", "/^\" = hex 5c 2e 2f 2f 5e 5c
static const uint8_t XWingLabel[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

// X-Wing Combiner (draft-connolly-cfrg-xwing-kem-09 Section 5.3)
// SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
static void xwing_combiner(uint8_t ss[32],
    const uint8_t ss_M[32], const uint8_t ss_X[32],
    const uint8_t ct_X[32], const uint8_t pk_X[32]) {
    uint8_t buf[134]; // 32+32+32+32+6
    memcpy(buf, ss_M, 32);
    memcpy(buf + 32, ss_X, 32);
    memcpy(buf + 64, ct_X, 32);
    memcpy(buf + 96, pk_X, 32);
    memcpy(buf + 128, XWingLabel, 6);
    xwing_sha3_256(ss, buf, 134);
    memset(buf, 0, sizeof(buf));
}

extern "C" int onlykey_mlkem_randombytes(uint8_t *out, size_t outlen) {
    RNG.rand(out, (unsigned)outlen);
    return 0;
}

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "memory_buffer_alloc.h"
#endif

/*************************************/
//RSA assignments
/*************************************/
uint8_t rsa_publicN[MAX_RSA_KEY_SIZE];
uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
/*************************************/
//ECC Authentication assignments
/*************************************/
uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE * 2) + 1];
uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
/*************************************/
//HMACSHA1 assignments
/*************************************/
extern uint8_t keyboard_buffer[KEYBOARD_BUFFER_SIZE];
/*************************************/

extern uint8_t Challenge_button1;
extern uint8_t Challenge_button2;
extern uint8_t Challenge_button3;
extern uint8_t CRYPTO_AUTH;
uint8_t type;
extern int large_buffer_offset;
extern uint8_t resp_buffer[64];
extern uint8_t *large_buffer;
extern uint8_t recv_buffer[64];
extern int large_buffer_len;
extern uint8_t profilekey[32];
extern uint8_t packet_buffer_details[5];
extern uint8_t *large_resp_buffer;
extern int outputmode;
extern uint8_t pending_operation;
extern uint8_t transit_key[32];

void okcrypto_sign(uint8_t *buffer) {
    uECC_set_rng(&RNG2);
    uint8_t features = 0;
#ifdef DEBUG
    Serial.println();
    Serial.println("OKSIGN MESSAGE RECEIVED");
#endif
    if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
        features = okcore_flashget_RSA((int)buffer[5]);
        if (type == 0) {
            hidprint("Error no key set in this slot");
            fadeoff(0);
            return;
        }
#ifdef DEBUG
        Serial.print(features, BIN);
#endif
        if ((type & 0x0F) == KEYTYPE_PQC_PGP) {
            okpqc_sign(buffer);
            return;
        }
        if (is_bit_set(features, 6)) {
            okcrypto_rsasign(buffer);
        } else {
#ifdef DEBUG
            Serial.print("Error key not set as signature key");
#endif
            hidprint("Error key not set as signature key");
            fadeoff(0);
        }
        return;
    } else if ((buffer[5] > 200 && buffer[5] < 205) || (buffer[5] > DERIVATION_V2_CODE_BASE && buffer[5] < DERIVATION_V2_CODE_BASE + 5)) { // SSH/GPG Derive Key
        okcrypto_ecdsa_eddsa(buffer);
    } else {
        if (buffer[5] > 100 && buffer[5] < 117) { // Keys 117 - 132 reserved
            features = okcore_flashget_ECC((int)buffer[5]);
        }
        if (type == 0) {
            hidprint("Error no key set in this slot");
            fadeoff(0);
            return;
        }
#ifdef DEBUG
        Serial.print(features, BIN);
#endif
        if (is_bit_set(features, 6)) {
            okcrypto_ecdsa_eddsa(buffer);
        } else {
#ifdef DEBUG
            Serial.print("Error key not set as signature key");
#endif
            hidprint("Error key not set as signature key");
            fadeoff(0);
            return;
        }
    }
}

// Derived X-Wing: the keypair is derived on demand from the slot-128 key and
// a 32-byte label tag. Nothing is stored and the origin is not an input.
// seed = HKDF-SHA256(slot-128 key, label), expanded as for a stored slot.
// Only the public key and shared secrets leave the device.

/* HKDF-Expand (RFC 5869 section 2.3) with an explicit info string. */
void okcrypto_hkdf_expand(const uint8_t *prk, const uint8_t *info, size_t info_len,
    uint8_t *out, size_t L) {
    SHA256 hash;
    uint8_t T[32];
    size_t done = 0, Tlen = 0;
    uint8_t counter = 1;
    while (done < L) {
        hash.resetHMAC(prk, 32);
        if (Tlen) hash.update(T, Tlen); /* T(0) is empty, RFC 5869 */
        hash.update(info, info_len);
        hash.update(&counter, 1);
        hash.finalizeHMAC(prk, 32, T, 32);
        Tlen = 32;
        size_t n = (L - done < 32) ? (L - done) : 32;
        memcpy(out + done, T, n);
        done += n;
        counter++;
    }
    memset(T, 0, sizeof(T));
}

void okcrypto_xwing_derive_seed(const uint8_t *label32, uint8_t *seed_out) {
    static const char INFO[] = "onlykey/xwing/seed/v3";

    uint8_t salt[33] = {0}; /* [flag 0][label32] */
    memcpy(salt + 1, label32, 32);

    okcore_flashget_ECC(RESERVED_KEY_WEB_AGENT_DERIVATION);

    SHA256 h; /* HKDF-Extract, RFC 5869 2.2 */
    uint8_t prk[32];
    h.resetHMAC(salt, sizeof(salt));
    h.update(ecc_private_key, 32);
    h.finalizeHMAC(salt, sizeof(salt), prk, 32);

    okcrypto_hkdf_expand(prk, (const uint8_t *)INFO, sizeof(INFO) - 1, seed_out, 32);

#ifdef DEBUG
    Serial.println();
    Serial.println("X-Wing PRK");
    byteprint(prk, 32);
    Serial.println("X-Wing derived seed");
    byteprint(seed_out, 32);
#endif

    memset(prk, 0, sizeof(prk));
    memset(salt, 0, sizeof(salt));
    memset(ecc_private_key, 0, sizeof(ecc_private_key));
}

/* ML-KEM scratch for the derived X-Wing functions. They can run while a
 * CTAPHID request occupies the start of ctap_buffer, and the ciphertext is
 * staged in large_buffer at its end, so the scratch sits between the two.
 * Both bounds are checked at compile time.
 */
#define XWING_DERIVE_SCRATCH_SIZE (MLKEM_SK_SIZE + MLKEM_PK_SIZE) /* 3584 */
#define XWING_DERIVE_SCRATCH_OFF (CTAPHID_BUFFER_SIZE - LARGE_BUFFER_SIZE - XWING_DERIVE_SCRATCH_SIZE)
static_assert(XWING_DERIVE_SCRATCH_OFF >= 1024,
    "ctap_buffer scratch would collide with an in-flight CTAP request");
static_assert(XWING_DERIVE_SCRATCH_OFF + XWING_DERIVE_SCRATCH_SIZE <= CTAPHID_BUFFER_SIZE - LARGE_BUFFER_SIZE,
    "ctap_buffer scratch would overlap large_buffer - the staged ciphertext");

/* out: XWING_PK_SIZE bytes. */
void okcrypto_xwing_derive_getpubkey(const uint8_t *label32, uint8_t *out) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
    uint8_t seed[32];
    uint8_t expanded[96];

    okcrypto_xwing_derive_seed(label32, seed);
    xwing_shake256(expanded, 96, seed, XWING_SEED_SIZE);

    uint8_t *scratch = ctap_buffer + XWING_DERIVE_SCRATCH_OFF;
    uint8_t *sk_M = scratch;
    uint8_t *pk_M = scratch + MLKEM_SK_SIZE;
    if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
        memset(seed, 0, sizeof(seed));
        memset(expanded, 0, sizeof(expanded));
        memset(scratch, 0, XWING_DERIVE_SCRATCH_SIZE);
        memset(out, 0, XWING_PK_SIZE);
        hidprint("Error ML-KEM keygen");
        return;
    }

    memcpy(out, pk_M, MLKEM_PK_SIZE);
    crypto_scalarmult_base(out + MLKEM_PK_SIZE, expanded + 64); /* pk_X */

    memset(seed, 0, sizeof(seed));
    memset(expanded, 0, sizeof(expanded));
    memset(scratch, 0, XWING_DERIVE_SCRATCH_SIZE);
}

/* ct: XWING_CT_SIZE bytes; out: the 32-byte shared secret. Returns 0 on
 * success. */
int okcrypto_xwing_derive_decaps(const uint8_t *label32, const uint8_t *ct, uint8_t *out) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
    uint8_t seed[32];
    uint8_t expanded[96];
    uint8_t ss_M[32], ss_X[32], pk_X[32];
    uint8_t *scratch = ctap_buffer + XWING_DERIVE_SCRATCH_OFF;
    uint8_t *sk_M = scratch;
    uint8_t *pk_M = scratch + MLKEM_SK_SIZE;
    int rc = -1;

    okcrypto_xwing_derive_seed(label32, seed);
    xwing_shake256(expanded, 96, seed, XWING_SEED_SIZE);

    if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) == 0) {
        crypto_scalarmult_base(pk_X, expanded + 64);
        if (crypto_kem_dec(ss_M, ct, sk_M) == 0) {
            crypto_scalarmult(ss_X, expanded + 64, ct + MLKEM_CT_SIZE); /* ct_X */
            xwing_combiner(out, ss_M, ss_X, ct + MLKEM_CT_SIZE, pk_X);
            rc = 0;
        }
    }

    memset(seed, 0, sizeof(seed));
    memset(expanded, 0, sizeof(expanded));
    memset(ss_M, 0, sizeof(ss_M));
    memset(ss_X, 0, sizeof(ss_X));
    memset(pk_X, 0, sizeof(pk_X));
    memset(scratch, 0, XWING_DERIVE_SCRATCH_SIZE);
    return rc;
}

void okcrypto_getpubkey(uint8_t *buffer) {
#ifdef DEBUG
    Serial.println();
    Serial.println("OKGETPUBKEY MESSAGE RECEIVED");
#endif
    if (buffer[5] < 5 && !buffer[6]) { //Slot 101-132 are for ECC, 1-4 are for RSA
        if (okcore_flashget_RSA((int)buffer[5])) {
            if ((type & 0x0F) == KEYTYPE_PQC_PGP) {
                hidprint("Error use OKGETPUBKEY PQC for composite keys");
            } else {
                okcrypto_getrsapubkey(buffer);
            }
        }
    } else if (buffer[5] < 117) { //128-132 are reserved
        if (okcore_flashget_ECC((int)buffer[5])) {
            if (type == KEYTYPE_MLKEM768)
                okcrypto_mlkem_getpubkey(buffer);
            else if (type == KEYTYPE_XWING)
                okcrypto_xwing_getpubkey(buffer);
            else
                okcrypto_geteccpubkey(buffer);
        }
    } else if (buffer[5] == RESERVED_KEY_DERIVATION && buffer[6] <= KEYTYPE_CURVE25519) { // Generate key using provided data, return public
        okcrypto_derive_key(buffer[6], buffer + 7, 0);
        send_transport_response(ecc_public_key, 64, false, false);
    } else if (buffer[5] == DERIVATION_V2_PUBKEY_CODE && buffer[6] && buffer[6] <= KEYTYPE_CURVE25519) { // Agent derivation v2 (HKDF), same request shape as 132
        okcrypto_derive_key(buffer[6], buffer + 7, RESERVED_KEY_DERIVATION);
        send_transport_response(ecc_public_key, 64, false, false);
    } else if (buffer[5] == RESERVED_KEY_WEB_AGENT_DERIVATION && (buffer[6] & 0x0F) == KEYTYPE_XWING) {
        // buffer[7..39]: label tag. Returns pk_M | pk_X (XWING_PK_SIZE).
        okcrypto_xwing_derive_getpubkey(buffer + 7, large_resp_buffer);
        send_transport_response(large_resp_buffer, XWING_PK_SIZE, true, true);
    }
}

/* Derived X-Wing decapsulation request, kept across the confirmation wait. */
static uint8_t derive_label[32];
static int derive_offset = 0;
static uint8_t derive_pending = 0;

void okcrypto_derive_reset(void) {
    derive_offset = 0;
    derive_pending = 0;
    memset(derive_label, 0, sizeof(derive_label));
    memset(large_buffer, 0, LARGE_BUFFER_SIZE);
}

void okcrypto_decrypt(uint8_t *buffer) {
    uECC_set_rng(&RNG2);
    uint8_t features = 0;
#ifdef DEBUG
    Serial.println();
    Serial.println("OKDECRYPT MESSAGE RECEIVED");
#endif
    if (buffer[5] == RESERVED_KEY_WEB_AGENT_DERIVATION) {
        // Derived X-Wing decapsulation over HID (slot 128). Payload
        // [label32 | ct(1120)] in 57-byte reports (buffer[6] = 0xFF for more,
        // else the final chunk length); the reply is the 32-byte shared secret.
        // On the last chunk the confirmation is primed over SHA-256 of the
        // request; okcore_run_pending_op() calls back here with CRYPTO_AUTH == 4.
        if (CRYPTO_AUTH == 4) {
            outputmode = packet_buffer_details[2];
            if (derive_pending != 1) {
                hidprint("Error no derived decaps request pending");
                fadeoff(0);
                return;
            }
            derive_pending = 0;
            uint8_t ss[XWING_SS_SIZE];
            if (okcrypto_xwing_derive_decaps(derive_label, large_buffer, ss) != 0) {
                hidprint("Error X-Wing derived decaps failed");
                fadeoff(0);
            } else {
                send_transport_response(ss, XWING_SS_SIZE, true, true);
            }
            memset(ss, 0, sizeof(ss));
            memset(derive_label, 0, sizeof(derive_label));
            memset(large_buffer, 0, LARGE_BUFFER_SIZE);
            fadeoff(85);
            return;
        } else if (CRYPTO_AUTH) {
            return; // confirmation in progress, ignore stray traffic
        }

        const int derive_total = 32 + XWING_CT_SIZE;
        int n = (buffer[6] == 0xFF) ? 57 : buffer[6];

        if (buffer[6] != 0xFF && buffer[6] > 57) {
            okcrypto_derive_reset();
            hidprint("Error derived decaps chunk size");
            fadeoff(0);
            return;
        }

        // The final report over FIDO2 is zero-padded to 16 bytes of data. Accept
        // an overshoot of less than 16 bytes on the last report and use
        // derive_total.
        if (buffer[6] != 0xFF && derive_offset + n > derive_total && derive_offset + n - derive_total < 16) {
            n = derive_total - derive_offset;
        }

        if (n < 0 || derive_offset + n > derive_total) {
            okcrypto_derive_reset();
            hidprint("Error derived decaps payload size");
            fadeoff(0);
            return;
        }
        for (int i = 0; i < n; i++) {
            int pos = derive_offset + i;
            if (pos < 32)
                derive_label[pos] = buffer[7 + i];
            else
                large_buffer[pos - 32] = buffer[7 + i];
        }
        derive_offset += n;
        // Restart the 5-second wipe timer on each chunk.
        wipedata();
        if (buffer[6] == 0xFF) return;

        if (derive_offset != derive_total) {
            okcrypto_derive_reset();
            hidprint("Error derived decaps payload size");
            fadeoff(0);
            return;
        }
        derive_offset = 0;
        derive_pending = 1;

        {
            SHA256_CTX ch;
            uint8_t chmsg[32];
            sha256_init(&ch);
            sha256_update(&ch, derive_label, 32);
            sha256_update(&ch, large_buffer, XWING_CT_SIZE);
            sha256_final(&ch, chmsg);
            okcore_prime_user_confirmation(OKDECRYPT, RESERVED_KEY_WEB_AGENT_DERIVATION,
                chmsg, sizeof(chmsg));
            packet_buffer_details[2] = outputmode;
            memset(chmsg, 0, sizeof(chmsg));
        }
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
        extern uint8_t NEO_Color;
        fadeon(NEO_Color);
        return;
    }
    if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
        features = okcore_flashget_RSA(buffer[5]);
        if (type == 0) {
            hidprint("Error no key set in this slot");
            fadeoff(0);
            return;
        }
        if ((type & 0x0F) == KEYTYPE_PQC_PGP) {
            okpqc_decrypt(buffer);
            return;
        }
        if (is_bit_set(features, 5)) {
            okcrypto_rsadecrypt(buffer);
        } else {
#ifdef DEBUG
            Serial.print("Error key not set as decryption key");
#endif
            hidprint("Error key not set as decryption key");
            fadeoff(0);
            return;
        }
    } else if ((buffer[5] > 200 && buffer[5] < 205) || (buffer[5] > DERIVATION_V2_CODE_BASE && buffer[5] < DERIVATION_V2_CODE_BASE + 5)) { // SSH/GPG Derive Key
        okcrypto_ecdh(buffer);
    } else {
        if (buffer[5] > 100 && buffer[5] < 117) { // Keys 117 - 132 reserved
            // Before confirmation, read only the key type; the key is loaded and
            // decrypted once CRYPTO_AUTH == 4.
            if ((type == KEYTYPE_MLKEM768 || type == KEYTYPE_XWING) && CRYPTO_AUTH && CRYPTO_AUTH != 4) {
                okeeprom_eeget_ecckey(&type, buffer[5]);
                type = type & 0x0F;
            } else {
                features = okcore_flashget_ECC((int)buffer[5]);
            }
        }
        if (type == 0) {
            hidprint("Error no key set in this slot");
            fadeoff(0);
            return;
        }
        if (type == KEYTYPE_MLKEM768) {
            okcrypto_mlkem_decaps(buffer);
        } else if (type == KEYTYPE_XWING) {
            okcrypto_xwing_decaps(buffer);
        } else if (is_bit_set(features, 5)) {
            okcrypto_ecdh(buffer);
        } else {
#ifdef DEBUG
            Serial.print("Error key not set as decryption key");
#endif
            hidprint("Error key not set as decryption key");
            fadeoff(0);
            return;
        }
    }
}

void okcrypto_generate_random_key(uint8_t *buffer) {
    uECC_set_rng(&RNG2);
#ifdef DEBUG
    Serial.println();
    Serial.println("GENERATE KEY MESSAGE RECEIVED");
#endif
    if (buffer[5] > 100) { //Slot 101-132 are for ECC, 1-4 are for RSA
        if ((buffer[6] & 0x0F) == KEYTYPE_MLKEM768) {
            okcrypto_mlkem_keygen(buffer);
            return;
        } else if ((buffer[6] & 0x0F) == KEYTYPE_XWING) {
            okcrypto_xwing_keygen(buffer);
            return;
        } else if ((buffer[6] & 0x0F) == 1) {
            crypto_box_keypair(ecc_public_key, buffer + 7); //Curve25519
        } else if ((buffer[6] & 0x0F) == 2) {
            const struct uECC_Curve_t *curve = uECC_secp256r1(); //P-256
            uECC_make_key(ecc_public_key, buffer + 7, curve);
        } else if ((buffer[6] & 0x0F) == 3) {
            const struct uECC_Curve_t *curve = uECC_secp256k1();
            uECC_make_key(ecc_public_key, buffer + 7, curve);
        } else if ((buffer[6] & 0x0F) == KEYTYPE_CURVE25519) {
            RNG2(buffer + 7, 32);
            buffer[7 + 31] &= 0xF8;
            buffer[7] = (buffer[7] & 0x7F) | 0x40;
        }
        memset(ecc_public_key, 0, sizeof(ecc_public_key));
    }
    return;
}

void okcrypto_getrsapubkey(uint8_t *buffer) {
#ifdef DEBUG
    byteprint(rsa_publicN, (type * 128));
#endif
    send_transport_response(rsa_publicN, (type * 128), true, true);
}

void okcrypto_rsasign(uint8_t *buffer) {
    uint8_t rsa_signature[(type * 128)];
    uint8_t rsa_signaturetemp[64];
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKSIGN_ERR_USER_ACTION_PENDING;
    } else if (CRYPTO_AUTH == 4) {
        if (large_buffer_offset != 28 && large_buffer_offset != 32 && large_buffer_offset != 48 && large_buffer_offset != 64) {
            hidprint("Error with RSA data to sign invalid size");
#ifdef DEBUG
            Serial.println("Error with RSA data to sign invalid size");
            Serial.println(large_buffer_offset);
#endif
            fadeoff(1);
            large_buffer_offset = 0;
            memset(large_buffer, 0, LARGE_BUFFER_SIZE); //wipe buffer
            return;
        }
        okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
#ifdef DEBUG
        Serial.println();
        Serial.printf("RSA data to sign size=%d", large_buffer_offset);
        Serial.println();
        byteprint(large_buffer, large_buffer_offset);
#endif
        pending_operation = CTAP2_ERR_OPERATION_PENDING;
        memcpy(rsa_signaturetemp, large_buffer, large_buffer_offset);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rsa_sign(large_buffer_offset, rsa_signaturetemp, rsa_signature) == 0) {
            pending_operation = CTAP2_ERR_DATA_READY;
#ifdef DEBUG
            Serial.print("Signature = ");
            byteprint(rsa_signature, sizeof(rsa_signature));
#endif
            outputmode = packet_buffer_details[2]; // Outputmode set at start of operation
            if (outputmode == WEBAUTHN) {
                send_transport_response(rsa_signature, (type * 128), true, true);
            } else {
                send_transport_response(rsa_signature, (type * 128), false, false);
                wipetasks();
            }
        } else {
            pending_operation = 0;
            hidprint("Error with RSA signing");
        }
        fadeoff(85);
        memset(rsa_signature, 0, sizeof(rsa_signature));
        if (outputmode != WEBAUTHN) memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
        return;
    } else {
#ifdef DEBUG
        Serial.println("Waiting for challenge buttons to be pressed");
#endif
        pending_operation = CTAP2_ERR_USER_ACTION_PENDING;
    }
}

void okcrypto_rsadecrypt(uint8_t *buffer) {
    unsigned int plaintext_len = 0;
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
    } else if (CRYPTO_AUTH == 4) {
        if (large_buffer_offset != (type * 128)) {
            hidprint("Error with RSA data to decrypt invalid size");
#ifdef DEBUG
            Serial.println("Error with RSA data to decrypt invalid size");
            Serial.println(large_buffer_offset);
#endif
            fadeoff(1);
            large_buffer_offset = 0;
            memset(large_buffer, 0, LARGE_BUFFER_SIZE); //wipe buffer
            return;
        }
        okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
#ifdef DEBUG
        Serial.println();
        Serial.printf("RSA ciphertext blob size=%d", large_buffer_offset);
        Serial.println();
        byteprint(large_buffer, large_buffer_offset);
#endif
        // decrypt ciphertext in large_buffer to temp_buffer
        pending_operation = CTAP2_ERR_OPERATION_PENDING;
        uint8_t rsa_decrypttemp[(type * 128)];
        memcpy(rsa_decrypttemp, large_buffer, large_buffer_offset);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rsa_decrypt(&plaintext_len, rsa_decrypttemp, large_resp_buffer) == 0) {
            pending_operation = CTAP2_ERR_DATA_READY;
#ifdef DEBUG
            Serial.println();
            Serial.print("Plaintext len = ");
            Serial.println(plaintext_len);
            Serial.print("Plaintext = ");
            byteprint(large_resp_buffer, plaintext_len);
            Serial.println();
#endif
            outputmode = packet_buffer_details[2]; // Outputmode set at start of operation
            if (outputmode == WEBAUTHN) {
                send_transport_response(large_resp_buffer, plaintext_len, true, true);
            } else {
                send_transport_response(large_resp_buffer, plaintext_len, false, false);
                wipetasks();
            }
        } else {
            pending_operation = 0;
            hidprint("Error with RSA decryption");
        }
        fadeoff(85);
        if (outputmode != WEBAUTHN) memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
        return;
    } else {
#ifdef DEBUG
        Serial.println("Waiting for challenge buttons to be pressed");
#endif
        pending_operation = CTAP2_ERR_USER_ACTION_PENDING;
    }
}

void okcrypto_geteccpubkey(uint8_t *buffer) {
    uint8_t pubkeylen = 64;
    okcore_flashget_ECC(buffer[5]);
    if (type == KEYTYPE_NACL && buffer[6] == KEYTYPE_CURVE25519) {
        type = KEYTYPE_CURVE25519;
        okcrypto_compute_pubkey();
    }
#ifdef DEBUG
    Serial.println("okcrypto_geteccpubkey MESSAGE RECEIVED");
    byteprint(ecc_public_key, sizeof(ecc_public_key));
#endif
    if (type == KEYTYPE_CURVE25519 || type == KEYTYPE_ED25519) pubkeylen = 32;
    send_transport_response(ecc_public_key, pubkeylen, true, true);
    memset(ecc_public_key, 0, MAX_ECC_KEY_SIZE * 2); //wipe buffer
    memset(ecc_private_key, 0, MAX_ECC_KEY_SIZE); //wipe buffer
}

void okcrypto_derive_key(uint8_t ktype, uint8_t *data, uint8_t slot) {
    if (!slot) { //SHA256 KDF used for SSH and challenge-response
        okcore_flashget_ECC(RESERVED_KEY_DERIVATION); //Default Key stored in ECC slot 32
        memset(ecc_public_key, 0, sizeof(ecc_public_key));
        SHA256_CTX ekey;
        sha256_init(&ekey);
        sha256_update(&ekey, ecc_private_key, 32); //Add default key to ekey
        sha256_update(&ekey, data, 32); //Add provided data to ekey
        sha256_final(&ekey, ecc_private_key); //Create hash and store
#ifdef DEBUG
        Serial.println();
        Serial.println("Agent derivation private key");
        byteprint(ecc_private_key, 32);
#endif
    } else if (slot == RESERVED_KEY_WEB_AGENT_DERIVATION) { //HMAC SHA256 KDF used for web requests
        okcore_flashget_ECC(slot);
#ifdef DEBUG
        Serial.println();
        Serial.println("Web and agent derivation key");
        byteprint(ecc_private_key, 32);
        Serial.println("Other data");
        byteprint(data, 33);
#endif
        // HKDF Reference: RFC5869 - https://tools.ietf.org/html/rfc5869
        okcrypto_hkdf(data, ecc_private_key, ecc_private_key, 32);
#ifdef DEBUG
        Serial.println();
        Serial.println("HKDF Key");
        byteprint(ecc_private_key, 32);
#endif
    } else if (slot == RESERVED_KEY_DERIVATION) { // Agent derivation v2: HKDF from the same slot-132 key
        // sk = HKDF-SHA256(salt=[0x20|data32], IKM=K132, info="onlykey/agent/v2", L=32)
        // v1 (slot == 0 above) is SHA256(K132 || data32).
        uint8_t v2salt[33];
        static const char V2INFO[] = "onlykey/agent/v2";
        okcore_flashget_ECC(RESERVED_KEY_DERIVATION);
        memset(ecc_public_key, 0, sizeof(ecc_public_key));
        v2salt[0] = 0x20;
        memcpy(v2salt + 1, data, 32);
        okcrypto_hkdf_info(v2salt, ecc_private_key, ecc_private_key, 32, (const uint8_t *)V2INFO, sizeof(V2INFO) - 1);
        memset(v2salt, 0, sizeof(v2salt));
#ifdef DEBUG
        Serial.println();
        Serial.println("Agent derivation v2 private key");
        byteprint(ecc_private_key, 32);
#endif
    }
    if (slot && ktype == KEYTYPE_CURVE25519) {
        ecc_private_key[31] &= 0xF8;
        ecc_private_key[0] = (ecc_private_key[0] & 0x7F) | 0x40;
    }
    type = ktype;
    okcrypto_compute_pubkey();
}

void okcrypto_ecdsa_eddsa(uint8_t *buffer) {
    uint8_t ecc_signature[64];
    uint8_t hash[64];
#ifdef DEBUG
    Serial.println();
    Serial.println("OKECDSA_EDDSA SIGN MESSAGE RECEIVED");
#endif
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKSIGN_ERR_USER_ACTION_PENDING;
    } else if (CRYPTO_AUTH == 4) {
        //if (outputmode == RAW_USB && !derived_key_challenge_mode && !stored_key_challenge_mod) {

        //}
        okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
#ifdef DEBUG
        Serial.println();
        Serial.print("ECC blob size of ");
        Serial.println(large_buffer_offset);
        byteprint(large_buffer, large_buffer_offset);
#endif
        uint8_t tmp[32 + 32 + 64];
        SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
        if (buffer[5] > 200) {
            if (buffer[5] != 201 && buffer[5] != 202 && buffer[5] != 203 &&
                buffer[5] != 211 && buffer[5] != 212 && buffer[5] != 213 &&
                buffer[5] != 221 && buffer[5] != 222 && buffer[5] != 223) {
                hidprint("Error invalid derived key slot");
                fadeoff(0);
                return;
            }
            if (buffer[5] == 201) {
                //Used by SSH, old version used 132, new version uses 201 for type 1
                okcrypto_derive_key(1, large_buffer + (large_buffer_offset - 32), 0);
            } else if (buffer[5] == 202) {
                okcrypto_derive_key(2, large_buffer + (large_buffer_offset - 32), 0);
            } else if (buffer[5] == 203) {
                okcrypto_derive_key(3, large_buffer + (large_buffer_offset - 32), 0);
            } else if (buffer[5] == 211) {
                okcrypto_derive_key(1, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_WEB_AGENT_DERIVATION);
            } else if (buffer[5] == 212) {
                okcrypto_derive_key(2, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_WEB_AGENT_DERIVATION);
            } else if (buffer[5] == 213) {
                okcrypto_derive_key(3, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_WEB_AGENT_DERIVATION);
            } else if (buffer[5] > DERIVATION_V2_CODE_BASE && buffer[5] < DERIVATION_V2_CODE_BASE + 4) {
                // v2 (HKDF) agent derivation: 221 ed25519, 222 p256, 223 secp256k1
                okcrypto_derive_key(buffer[5] - DERIVATION_V2_CODE_BASE, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_DERIVATION);
            }
            large_buffer_offset = large_buffer_offset - 32;
        } else if (buffer[5] >= 101 && buffer[5] <= 116) {
            // Not using derived key, using stored key
            okcore_flashget_ECC(buffer[5]); //Default Key stored in ECC slot 32
        } else {
            return;
        }

        if (large_buffer_offset == 32 || large_buffer_offset == 64) { // Hash and sign data if larger than 32 bytes, if 32 bytes sign data
            memcpy(hash, large_buffer, large_buffer_offset);
        } else {
            SHA256_CTX msghash;
            sha256_init(&msghash);
            sha256_update(&msghash, large_buffer, large_buffer_offset);
            sha256_final(&msghash, hash); //Create hash and store
            if (type != 0x01) large_buffer_offset = 32;
        }

#ifdef DEBUG
        Serial.println("Signature Hash ");
        byteprint(hash, large_buffer_offset);
        Serial.print("Type");
        Serial.println(type);
        Serial.println("Private ");
        byteprint(ecc_private_key, sizeof(ecc_private_key));
#endif
        pending_operation = CTAP2_ERR_OPERATION_PENDING;
        if (type != 0x01 && type != 0x02 && type != 0x03) {
            hidprint("Error key not set as signature key");
            fadeoff(0);
            return;
        }
        if (type == 0x01)
            Ed25519::sign(ecc_signature, ecc_private_key, ecc_public_key, large_buffer, large_buffer_offset);
        else if (type == 0x02) {
            const struct uECC_Curve_t *curve = uECC_secp256r1(); //P-256
            if (!uECC_sign_deterministic(ecc_private_key,
                    hash,
                    large_buffer_offset,
                    &ectx.uECC,
                    ecc_signature,
                    curve)) {
#ifdef DEBUG
                Serial.println("Signature Failed ");
#endif
            }
        } else if (type == 0x03) {
            const struct uECC_Curve_t *curve = uECC_secp256k1();
            if (!uECC_sign_deterministic(ecc_private_key,
                    hash,
                    large_buffer_offset,
                    &ectx.uECC,
                    ecc_signature,
                    curve)) {
#ifdef DEBUG
                Serial.println("Signature Failed ");
#endif
            }
        }
#ifdef DEBUG
        Serial.print("Signature=");
        byteprint(ecc_signature, 64);
#endif
        pending_operation = CTAP2_ERR_DATA_READY;
        outputmode = packet_buffer_details[2]; // Outputmode set at start of operation
        if (outputmode == WEBAUTHN) {
            send_transport_response(ecc_signature, 64, true, true);
        } else {
            send_transport_response(ecc_signature, 64, true, true);
            wipetasks();
        }
        // Stop the fade in
        fadeoff(85);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        memset(ecc_public_key, 0, sizeof(ecc_public_key)); //wipe buffer
        memset(ecc_private_key, 0, sizeof(ecc_private_key)); //wipe buffer
        return;
    } else {
#ifdef DEBUG
        Serial.println("Waiting for challenge buttons to be pressed");
#endif
        pending_operation = CTAP2_ERR_USER_ACTION_PENDING;
    }
}

void okcrypto_ecdh(uint8_t *buffer) {
    uint8_t temp[65] = {0};
    uint8_t resplen = 64;
#ifdef DEBUG
    Serial.println();
    Serial.println("OKECDH MESSAGE RECEIVED");
#endif
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
    } else if (CRYPTO_AUTH == 4) {
        okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
#ifdef DEBUG
        Serial.println();
        Serial.print("ECC blob size of ");
        Serial.println(large_buffer_offset);
        byteprint(large_buffer, large_buffer_offset);
#endif
        if (buffer[5] > 200) {
            /* Ed25519 has no ECDH. */
            if (!((buffer[5] > 201 && buffer[5] < 205) || (buffer[5] > 211 && buffer[5] < 215) ||
                    (buffer[5] > DERIVATION_V2_CODE_BASE + 1 && buffer[5] < DERIVATION_V2_CODE_BASE + 5))) {
                hidprint("Error invalid derived key slot");
                fadeoff(0);
                return;
            }
            if (buffer[5] == 202) {
                okcrypto_derive_key(2, large_buffer + (large_buffer_offset - 32), 0);
            } else if (buffer[5] == 203) {
                okcrypto_derive_key(3, large_buffer + (large_buffer_offset - 32), 0);
            } else if (buffer[5] == 204) {
                okcrypto_derive_key(4, large_buffer + (large_buffer_offset - 32), 0);
            } else if (buffer[5] == 212) {
                okcrypto_derive_key(2, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_WEB_AGENT_DERIVATION);
            } else if (buffer[5] == 213) {
                okcrypto_derive_key(3, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_WEB_AGENT_DERIVATION);
            } else if (buffer[5] == 214) {
                okcrypto_derive_key(4, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_WEB_AGENT_DERIVATION);
            } else if (buffer[5] > DERIVATION_V2_CODE_BASE + 1 && buffer[5] < DERIVATION_V2_CODE_BASE + 5) {
                // v2 (HKDF) agent derivation: 222 p256, 223 secp256k1, 224 curve25519
                okcrypto_derive_key(buffer[5] - DERIVATION_V2_CODE_BASE, large_buffer + (large_buffer_offset - 32), RESERVED_KEY_DERIVATION);
            }
            large_buffer_offset = large_buffer_offset - 32; //Remove derivation data hash
        } else if (buffer[5] >= 101 && buffer[5] <= 116) {
            // Not using derived key, using stored key
            okcore_flashget_ECC(buffer[5]);
        } else {
            return;
        }

        if (type == 2 || type == 3) type += 100; // Different shared secret method required, multiply points and return x and y
        if (type == 1) {
            type = 4; // Use Curve25519 scalar multiply
            resplen = 32;
            okcrypto_compute_pubkey();
        }
        if (large_buffer_offset == 33 || large_buffer_offset == 65) { // Remove public key first byte 0x04 or 0x40 for Trezor agent
            large_buffer_offset--;
            memcpy(ecc_public_key, large_buffer + 1, large_buffer_offset);
        } else if (large_buffer_offset == 32 || large_buffer_offset == 64) {
            memcpy(ecc_public_key, large_buffer, large_buffer_offset);
        }

        pending_operation = CTAP2_ERR_USER_ACTION_PENDING;
        // Use ecc_private_key and provided pubkey to generate shared secret
        if (large_buffer_offset == 64 || large_buffer_offset == 32) { // Public key sizes
            if (okcrypto_shared_secret(ecc_public_key, temp)) {
                //Error
            }
        }

#ifdef DEBUG
        Serial.println("Input public");
        byteprint(ecc_public_key, large_buffer_offset);
        Serial.println("Private");
        byteprint(ecc_private_key, sizeof(ecc_private_key));
        Serial.print("Type");
        Serial.println(type);
        Serial.print("Shared Secret =");
        byteprint(temp, large_buffer_offset);
#endif
        pending_operation = CTAP2_ERR_DATA_READY;
        outputmode = packet_buffer_details[2]; // Outputmode set at start of operation
        if (outputmode == WEBAUTHN) {
            send_transport_response(temp, resplen, true, true);
        } else {
            send_transport_response(temp, resplen, true, true);
            wipetasks();
        }
        // Stop the fade in
        fadeoff(85);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        memset(ecc_public_key, 0, sizeof(ecc_public_key)); //wipe buffer
        memset(ecc_private_key, 0, sizeof(ecc_private_key)); //wipe buffer
        return;
    } else {
#ifdef DEBUG
        Serial.println("Waiting for challenge buttons to be pressed");
#endif
    }
}

void okcrypto_hmacsha1() {
    uint8_t temp[32];
    uint8_t inputlen;
    uint8_t slot = keyboard_buffer[64];
    uint16_t crc;
    extern uint8_t setBuffer[9];
    uint8_t *ptr;
#ifdef DEBUG
    Serial.println();
    Serial.println("GENERATE HMACSHA1 MESSAGE RECEIVED");
    Serial.print("SLOT = ");
    Serial.println(slot);
#endif
    if (CRYPTO_AUTH == 4) {
        if (!check_crc(keyboard_buffer)) {
            memset(setBuffer, 0, 9);
            memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
            return;
        }
        outputmode = RAW_USB;
        if (slot == 0x38) { //HMAC Slot 2 selected, 0x08 for slot 2, 0x00 for slot 1
            okcore_flashget_ECC(RESERVED_KEY_HMACSHA1_2); //ECC slot 129 reserved for HMAC Slot 2 key
        } else if (slot == 0x30) { //HMAC Slot 2 selected, 0x00 for slot 1
            okcore_flashget_ECC(RESERVED_KEY_HMACSHA1_1); //ECC slot 130 reserved for HMAC Slot 1 key
        } else if (slot >= 1 && slot <= 24) {
            okcore_flashget_hmac(ecc_private_key, slot);
        }
        if (type == 0) { //Generate a key using the default key in slot 132 if there is no key set in slot
            // Derive key from SHA256 hash of default key and added data temp
            for (int i = 0; i < 32; i++) {
                temp[i] = i + slot;
            }
            okcrypto_derive_key(0, temp, 0);
        }
        outputmode = KEYBOARD_USB;
        // Variable buffer size
        // Any challenge less than 16 bytes in size is treated as 16 bytes, this means response will be different than Yubikey response
        if (keyboard_buffer[57] == 0x20 && keyboard_buffer[58] == 0x20 && keyboard_buffer[59] == 0x20 && keyboard_buffer[60] == 0x20 && keyboard_buffer[61] == 0x20 && keyboard_buffer[62] == 0x20 && keyboard_buffer[63] == 0x20) {
            inputlen = 32; //KeepassXC uses 0x20 for empty buffer
        } else {
            int i;
            for (i = 63; i >= 15; i--) {
                if (keyboard_buffer[i] != 0) { //YubiKey personalization tool uses 0 for empty buffer
                    break;
                }
            }
            inputlen = i + 1;
        }
#ifdef DEBUG
        Serial.print("HMACSHA1 Input = ");
        byteprint(keyboard_buffer, 70);
        Serial.print("Input Length");
        Serial.println(inputlen);
#endif
        //Load HMAC Key
        Sha1.initHmac(ecc_private_key, 20);
        //Generate HMACSHA1
        Sha1.write(keyboard_buffer, inputlen);
        ptr = keyboard_buffer;
        ptr = Sha1.resultHmac();
        memcpy(temp, ptr, 20);
        memset(ecc_private_key, 0, 32);
#ifdef DEBUG
        Serial.print("HMAC for CRC Input = ");
        byteprint(temp, 20);
#endif
        //Generate CRC of Output
        crc = yubikey_crc16(temp, 20);
        memcpy(keyboard_buffer, temp, 7);
        keyboard_buffer[7] = 0xC0; //Part 1 of HMAC
        memcpy(keyboard_buffer + 8, temp + 7, 7);
        keyboard_buffer[15] = 0xC1; //Part 2 of HMAC
        memcpy(keyboard_buffer + 16, temp + 14, 6);
        keyboard_buffer[23] = 0xC2; //Part 3 of HMAC
        memset(keyboard_buffer + 24, 0, KEYBOARD_BUFFER_SIZE - 24);
        // CRC Bytes expected are CRC-16/X-25 but yubikey_crc16 generates CRC-16/MCRF4XX,
        // Weird that firmware uses a different CRC-16 than https://github.com/Yubico/yubikey-personalization/blob/master/ykcore/
        // We can XOR CRC-16/MCRF4XX output to convert to CRC-16/X-25
        crc ^= 0xFFFF;
        keyboard_buffer[22] = crc & 0xFF;
        keyboard_buffer[24] = crc >> 8;
        keyboard_buffer[31] = 0xC3; //Part 4 contains part of CRC and mystery byte keyboard_buffer[28]
        keyboard_buffer[28] = 0x4B;
#ifdef DEBUG
        Serial.print("HMACSHA1 Output = ");
        byteprint(keyboard_buffer, KEYBOARD_BUFFER_SIZE);
        Serial.print("CRC = ");
        Serial.println(crc);
#endif
        return;
    } else {
#ifdef DEBUG
        Serial.println("Waiting for challenge buttons to be pressed");
#endif
    }
}

int okcrypto_shared_secret(uint8_t *pub, uint8_t *secret) {
    const struct uECC_Curve_t *curve;
    switch (type) {
        case KEYTYPE_NACL:
            if (crypto_box_beforenm(secret, pub, ecc_private_key))
                return 1;
            else
                return 0;
        case KEYTYPE_P256R1:
            curve = uECC_secp256r1();
            if (uECC_shared_secret(pub, ecc_private_key, secret, curve)) {
                return 0;
            } else
                return 1;
        case KEYTYPE_P256K1:
            curve = uECC_secp256k1();
            if (uECC_shared_secret(pub, ecc_private_key, secret, curve)) {
                return 0;
            } else
                return 1;
        case KEYTYPE_CURVE25519: {
            uint8_t nonzero = 0;
            Curve25519::eval(secret, ecc_private_key, pub);
            for (int i = 0; i < 32; i++) nonzero |= secret[i];
            return nonzero ? 0 : 1;
        }
        case KEYTYPE_ECDH_P256R:
            curve = uECC_secp256r1();
            if (uECC_shared_secret2(pub, ecc_private_key, secret, curve)) {
                return 0;
            }
        case KEYTYPE_ECDH_P256K:
            curve = uECC_secp256k1();
            if (uECC_shared_secret2(pub, ecc_private_key, secret, curve)) {
                return 0;
            }

        case KEYTYPE_MLKEM768:
            hidprint("Error use ML-KEM decaps for this key type");
            return 1;

        case KEYTYPE_XWING:
            hidprint("Error use X-Wing decaps for this key type");
            return 1;

        default:
            hidprint("Error ECC type incorrect");
            return 1;
    }
}

mbedtls_md_context_t sha512_ctx;

void crypto_sha512_init() {
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA512;
    mbedtls_md_init(&sha512_ctx);
    mbedtls_md_setup(&sha512_ctx, mbedtls_md_info_from_type(md_type), 0); // 0 = not using HMAC
}

void crypto_sha512_update(const uint8_t *data, size_t len) {
    mbedtls_md_update(&sha512_ctx, data, len);
}

void crypto_sha512_final(uint8_t *hash) {
    mbedtls_md_finish(&sha512_ctx, hash);
    mbedtls_md_free(&sha512_ctx);
}

/* FIDO2 transit encryption v2: AES-GCM under the transit key set by
 * OKCONNECT, with a 16-byte tag.
 *
 *     IV    = [dir(1)][counter big-endian(4)][zero(7)]
 *     frame = [counter big-endian(4)][ciphertext(n)][tag(16)]
 *
 * dir 0 is device->host and dir 1 is host->device, so the two directions
 * never share an IV. Each frame carries its counter; a modified counter fails
 * the tag check. */
static uint32_t transit_ctr_out = 0; /* device -> host */

void okcrypto_transit_reset(void) {
    transit_ctr_out = 0;
}

static void okcrypto_transit_iv(uint8_t *iv, uint8_t dir, uint32_t ctr) {
    memset(iv, 0, 12);
    iv[0] = dir;
    iv[1] = (uint8_t)(ctr >> 24);
    iv[2] = (uint8_t)(ctr >> 16);
    iv[3] = (uint8_t)(ctr >> 8);
    iv[4] = (uint8_t)(ctr);
}

/* Seals in place. `frame` points at the counter; the len-byte plaintext
 * follows it, and the caller owns len + OKCRYPTO_TRANSIT_OVERHEAD bytes.
 * Returns the framed length. */
int okcrypto_transit_seal(uint8_t *frame, int len) {
#ifdef STD_VERSION
    uint8_t iv[12];
    uint32_t ctr = transit_ctr_out++;
    uint8_t *ct = frame + OKCRYPTO_TRANSIT_CTR_LEN;
    GCM<AES256> gcm;
    frame[0] = (uint8_t)(ctr >> 24);
    frame[1] = (uint8_t)(ctr >> 16);
    frame[2] = (uint8_t)(ctr >> 8);
    frame[3] = (uint8_t)(ctr);
    okcrypto_transit_iv(iv, OKCRYPTO_TRANSIT_DIR_OUT, ctr);
    gcm.clear();
    gcm.setKey(transit_key, 32);
    gcm.setIV(iv, 12);
    gcm.encrypt(ct, ct, len);
    gcm.computeTag(ct + len, OKCRYPTO_TRANSIT_TAG_LEN);
#ifdef DEBUG
    Serial.print("transit seal ctr=");
    Serial.print(ctr);
    Serial.print(" len=");
    Serial.println(len);
#endif
    return len + OKCRYPTO_TRANSIT_OVERHEAD;
#else
    return len;
#endif
}

/* Open a frame in place. `frame` is [counter(4)][ciphertext(n)][tag(16)] and
 * `len` is its whole length. On success the plaintext is moved to frame[0]
 * and its length is returned. On failure the buffer is wiped and -1 is
 * returned. */
int okcrypto_transit_open(uint8_t *frame, int len) {
#ifdef STD_VERSION
    uint8_t iv[12];
    uint8_t tag[OKCRYPTO_TRANSIT_TAG_LEN];
    uint8_t *ct = frame + OKCRYPTO_TRANSIT_CTR_LEN;
    uint32_t ctr;
    GCM<AES256> gcm;
    int ptlen = len - OKCRYPTO_TRANSIT_OVERHEAD;
    if (ptlen < 0) {
        memset(frame, 0, len > 0 ? len : 0);
        return -1;
    }
    ctr = ((uint32_t)frame[0] << 24) | ((uint32_t)frame[1] << 16) |
        ((uint32_t)frame[2] << 8) | (uint32_t)frame[3];
    memcpy(tag, ct + ptlen, OKCRYPTO_TRANSIT_TAG_LEN);
    okcrypto_transit_iv(iv, OKCRYPTO_TRANSIT_DIR_IN, ctr);
    gcm.clear();
    gcm.setKey(transit_key, 32);
    gcm.setIV(iv, 12);
    gcm.decrypt(ct, ct, ptlen);
    if (!gcm.checkTag(tag, OKCRYPTO_TRANSIT_TAG_LEN)) {
        /* Wipe rather than leave a plausible-looking plaintext behind. */
        memset(frame, 0, len);
        return -1;
    }
    memmove(frame, ct, ptlen);
    memset(frame + ptlen, 0, len - ptlen);
#ifdef DEBUG
    Serial.print("transit open ctr=");
    Serial.print(ctr);
    Serial.print(" len=");
    Serial.println(ptlen);
#endif
    return ptlen;
#else
    return len;
#endif
}


int rsa_sign(int mlen, const uint8_t *msg, uint8_t *out) {
    //mbedtls_rsa_self_test(1);
    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    int ret = 0;
    static mbedtls_rsa_context rsa;
    uint8_t rsa_ciphertext[(type * 128)];
    mbedtls_mpi P1, Q1, H;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&H);
    rsa.len = (type * 128);
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&rsa.E, 0x10001));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa.P, &rsa_private_key[0], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa.Q, &rsa_private_key[((type * 128) / 2)], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&rsa.N, &rsa.P, &rsa.Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&P1, &rsa.P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&Q1, &rsa.Q, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&H, &P1, &Q1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&rsa.D, &rsa.E, &H));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rsa.DP, &rsa.D, &P1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rsa.DQ, &rsa.D, &Q1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&rsa.QP, &rsa.Q, &rsa.P));

#ifdef DEBUG
    Serial.printf("\nRSA len = ");
    Serial.println(rsa.len);
#endif
    ret = mbedtls_rsa_check_privkey(&rsa);
cleanup:
    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&H);

    if (ret != 0) {
#ifdef DEBUG
        Serial.printf("Error with key check =%d", ret);
#endif
        hidprint("Error invalid key, key check failed");
        return -1;
    }
    if (ret == 0) {
#ifdef DEBUG
        Serial.print("RSA sign messege length = ");
        Serial.println(mlen);
#endif
        if (mlen > ((type * 128) - 11)) mlen = ((type * 128) - 11);

        switch (mlen) {
            case 64:
                md_type = MBEDTLS_MD_SHA512;
                break;

            case 48:
                md_type = MBEDTLS_MD_SHA384;
                break;

            case 32:
                md_type = MBEDTLS_MD_SHA256;
                break;

            case 28:
                md_type = MBEDTLS_MD_SHA224;
                break;

                //case 20:
                //	md_type = MBEDTLS_MD_RIPEMD160;
                //break;

            default:
                break;
        }

        ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, mbedtls_rand, NULL, MBEDTLS_RSA_PRIVATE, md_type, mlen, msg, rsa_ciphertext);
#ifdef DEBUG
        Serial.print("Hash Value = ");
        byteprint((uint8_t *)msg, mlen);
#endif
        memcpy(out, rsa_ciphertext, (type * 128));
        /*int ret2 = mbedtls_rsa_rsassa_pkcs1_v15_verify ( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, mlen, msg, rsa_ciphertext );
		#ifdef DEBUG
		Serial.print("Hash Value = ");
		byteprint((uint8_t *)msg, mlen);
		#endif
		if( ret2 != 0 ) {
			#ifdef DEBUG
			Serial.print("Signature Verification Failed ");
			Serial.println(ret2);
			#endif
			return -1;
		}*/
    }
    mbedtls_rsa_free(&rsa);
    if (ret == 0) {
#ifdef DEBUG
        Serial.println("completed successfully");
#endif
        return 0;
    } else {
#ifdef DEBUG
        Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
        Serial.println(ret);
#endif
        hidprint("invalid data, or data does not match key");
        return -1;
    }
}

int rsa_decrypt(unsigned int *olen, const uint8_t *in, uint8_t *out) {
    mbedtls_mpi P1, Q1, H;
    int ret = 0;
    static mbedtls_rsa_context rsa;
#ifdef DEBUG
    Serial.printf("\nRSA decrypt:");
    Serial.println((uint32_t)&ret);
#endif

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&H);
    rsa.len = (type * 128);
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&rsa.E, 0x10001));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa.P, &rsa_private_key[0], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa.Q, &rsa_private_key[((type * 128) / 2)], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&rsa.N, &rsa.P, &rsa.Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&P1, &rsa.P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&Q1, &rsa.Q, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&H, &P1, &Q1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&rsa.D, &rsa.E, &H));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rsa.DP, &rsa.D, &P1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rsa.DQ, &rsa.D, &Q1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&rsa.QP, &rsa.Q, &rsa.P));
#ifdef DEBUG
    Serial.println(rsa.len);
#endif
cleanup:
    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&H);

#ifdef DEBUG
    Serial.printf("\nRSA len = ");
    Serial.println(rsa.len);
#endif
    ret = mbedtls_rsa_check_privkey(&rsa);
    if (ret != 0) {
#ifdef DEBUG
        Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
        Serial.println(ret);
#endif
        hidprint("Error invalid key, key check failed");
    }
    if (ret == 0) {
#ifdef DEBUG
        Serial.print("RSA decrypt ");
#endif
        ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, olen, in, out, 512);
    }
    mbedtls_rsa_free(&rsa);
    if (ret == 0) {
#ifdef DEBUG
        Serial.println("completed successfully");
        Serial.print(*olen);
#endif
        return 0;
    } else {
#ifdef DEBUG
        Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
        Serial.println(ret);
#endif
        hidprint("Error invalid data, or data does not match key");
        return -1;
    }
}

void rsa_getpub(uint8_t type) {
    mbedtls_mpi P, Q, N;
    int ret = 0;
#ifdef DEBUG
    Serial.print("RSA generate public N:");
#endif
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&N);
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&P, &rsa_private_key[0], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Q, &rsa_private_key[((type * 128) / 2)], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&N, &P, &Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&N, &rsa_publicN[0], (type * 128)));
cleanup:
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&N);

    if (ret == 0) {
#ifdef DEBUG
        Serial.print("Storing RSA public ");
        byteprint(rsa_publicN, (type * 128));
#endif
    } else {
        hidprint("Error generating RSA public N");
#ifdef DEBUG
        Serial.print("Error generating RSA public");
        byteprint(rsa_publicN, (type * 128));
#endif
    }
}

int rsa_encrypt(int len, const uint8_t *in, uint8_t *out) {
    mbedtls_mpi P1, Q1, H;
    int ret = 0;
    static mbedtls_rsa_context rsa;
#ifdef DEBUG
    Serial.printf("\nRSA encrypt:");
    Serial.println((uint32_t)&ret);
#endif

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&H);
    rsa.len = (type * 128);
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&rsa.E, 0x10001));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa.P, &rsa_private_key[0], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa.Q, &rsa_private_key[((type * 128) / 2)], ((type * 128) / 2)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&rsa.N, &rsa.P, &rsa.Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&P1, &rsa.P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&Q1, &rsa.Q, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&H, &P1, &Q1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&rsa.D, &rsa.E, &H));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rsa.DP, &rsa.D, &P1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rsa.DQ, &rsa.D, &Q1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&rsa.QP, &rsa.Q, &rsa.P));
#ifdef DEBUG
    Serial.println(rsa.len);
#endif
cleanup:
    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&H);

#ifdef DEBUG
    Serial.printf("\nRSA len = ");
    Serial.println(rsa.len);
#endif
    ret = mbedtls_rsa_check_pubkey(&rsa);
    if (ret != 0) {
#ifdef DEBUG
        Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
        Serial.println(ret);
#endif
        return ret;
    }
    if (ret == 0) {
        ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(&rsa, mbedtls_rand, NULL, MBEDTLS_RSA_PUBLIC, len, in, out);
    }
    mbedtls_rsa_free(&rsa);
    if (ret == 0) {
#ifdef DEBUG
        Serial.print("completed successfully");
#endif
        return 0;
    } else {
#ifdef DEBUG
        Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
        Serial.println(ret);
#endif
        return ret;
    }
}

bool is_bit_set(unsigned char byte, int index) {
    return (byte >> index) & 1;
}

int mbedtls_rand(void *rng_state, unsigned char *output, size_t len) {
    if (rng_state != NULL)
        rng_state = NULL;
    RNG2(output, len);
    return (0);
}


/* Slot-128 derived ECC keys (P-256, secp256k1, X25519): FIDO2
 * DERIVE_PUBLIC_KEY / DERIVE_SHAREDSEC and HID slots 211-214.
 *
 *   PRK = HMAC-SHA256(salt = additional_data [flag | tag32], IKM = slot-128 key)
 *   key = HKDF-Expand(PRK, "onlykey/derive/ecc/v2", L)
 *
 * The origin is not part of the derivation; webcryptcheck() decides which
 * origins may ask. The info string separates these keys from derived X-Wing,
 * which uses the same salt for flag 0. */
void okcrypto_hkdf(const void *salt, const void *inputKey, void *outputKey, const size_t L) {
    static const char INFO[] = "onlykey/derive/ecc/v2";
    okcrypto_hkdf_info(salt, inputKey, outputKey, L, (const uint8_t *)INFO, sizeof(INFO) - 1);
}

/* okcrypto_hkdf() with the caller's info string. */
void okcrypto_hkdf_info(const void *salt, const void *inputKey, void *outputKey, const size_t L,
    const uint8_t *info, size_t info_len) {
    // Salt is 33 bytes ([flag][32-byte tag]); NULL means 33 zero bytes.
    uint8_t tmp[33];
    const uint8_t *s;
    if (salt == NULL) {
        memset(tmp, 0, sizeof(tmp));
        s = tmp;
    } else {
        s = (const uint8_t *)salt;
    }

#ifdef DEBUG
    Serial.print("salt");
    byteprint((uint8_t *)s, 33);
#endif

    SHA256 hash; /* HKDF-Extract, RFC 5869 2.2 */
    uint8_t PRK[32];
    hash.resetHMAC(s, 33);
    hash.update(inputKey, 32);
    hash.finalizeHMAC(s, 33, PRK, sizeof(PRK));
    hash.clear();

    okcrypto_hkdf_expand(PRK, info, info_len, (uint8_t *)outputKey, L);
    memset(PRK, 0, sizeof(PRK));
}


void okcrypto_aes_gcm_encrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len) {
#ifdef STD_VERSION
    GCM<AES256> gcm;
    uint8_t iv2[12];
    uint8_t aeskey[32];
    uint8_t data[2];
    uint8_t function1 = 1;
    uint8_t function2 = 2;
    data[0] = slot;
    data[1] = value;

    okcore_flashget_noncehash((uint8_t *)iv2, 12);

#ifdef DEBUG
    Serial.print("INPUT KEY ");
    byteprint((uint8_t *)key, 32);
#endif

#ifdef DEBUG
    Serial.println("SLOT");
    Serial.println(slot);
#endif

#ifdef DEBUG
    Serial.print("VALUE");
    Serial.print(value);
#endif

    SHA256_CTX iv;
    sha256_init(&iv);
    sha256_update(&iv, iv2, 12); //add nonce
    sha256_update(&iv, data, 2); //add data
    sha256_update(&iv, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
    sha256_final(&iv, aeskey); //Create hash and store in aeskey temporarily
    memcpy(iv2, aeskey, 12);
#ifdef DEBUG
    Serial.print("IV ");
    byteprint(iv2, 12);
#endif

    SHA256_CTX key2;
    sha256_init(&key2);
    sha256_update(&key2, key, 16); //add profilekey
    sha256_update(&key2, data, 2); //add slot
    sha256_update(&key2, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
    sha256_final(&key2, aeskey); //Create hash and store in aeskey

#ifdef DEBUG
    Serial.print("AES KEY ");
    byteprint(aeskey, 32);
    Serial.print("DECRYPTED STATE");
    byteprint(state, len);
#endif

#ifdef FACTORYKEYS
    // Even/Odd IV different encryption algorithms
    if (iv2[0] % 2 == 0) {
        function1 = 2;
        function2 = 1;
    }
    okcrypto_split_sundae(state, iv2, len, function1, true);
#endif

    gcm.clear();
    gcm.setKey(aeskey, 32);
    gcm.setIV(iv2, 12);
    gcm.encrypt(state, state, len);

#ifdef FACTORYKEYS
    okcrypto_split_sundae(state, iv2, len, function2, true);
#endif

#ifdef DEBUG
    Serial.print("ENCRYPTED STATE");
    byteprint(state, len);
#endif
//gcm.computeTag(tag, sizeof(tag));
#endif
}

void okcrypto_aes_gcm_decrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len) {
#ifdef STD_VERSION
    GCM<AES256> gcm;
    uint8_t iv2[12];
    uint8_t aeskey[32];
    uint8_t data[2];
    uint8_t function3 = 4;
    uint8_t function4 = 3;
    data[0] = slot;
    data[1] = value;

    okcore_flashget_noncehash((uint8_t *)iv2, 12);

#ifdef DEBUG
    Serial.print("INPUT KEY ");
    byteprint((uint8_t *)key, 32);
#endif

#ifdef DEBUG
    Serial.println("SLOT");
    Serial.println(slot);
#endif

#ifdef DEBUG
    Serial.print("VALUE");
    Serial.print(value);
#endif

    SHA256_CTX iv;
    sha256_init(&iv);
    sha256_update(&iv, iv2, 12); //add nonce
    sha256_update(&iv, data, 2); //add data
    sha256_update(&iv, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
    sha256_final(&iv, aeskey); //Create hash and store in aeskey temporarily
    memcpy(iv2, aeskey, 12);

#ifdef DEBUG
    Serial.print("IV ");
    byteprint(iv2, 12);
#endif

    SHA256_CTX key2;
    sha256_init(&key2);
    sha256_update(&key2, key, 16); //add profilekey
    sha256_update(&key2, data, 2); //add data
    sha256_update(&key2, (uint8_t *)ID, 32); //add first 32 bytes of Freescale CHIP ID
    sha256_final(&key2, aeskey); //Create hash and store in aeskey

#ifdef DEBUG
    Serial.print("AES KEY ");
    byteprint(aeskey, 32);
    Serial.print("ENCRYPTED STATE");
    byteprint(state, len);
#endif

#ifdef FACTORYKEYS
    // Even/Odd IV different encryption algorithms
    if (iv2[0] % 2 == 0) {
        function3 = 3;
        function4 = 4;
    }
    okcrypto_split_sundae(state, iv2, len, function3, true);
#endif

    gcm.clear();
    gcm.setKey(aeskey, 32);
    gcm.setIV(iv2, 12);
    gcm.decrypt(state, state, len);

#ifdef FACTORYKEYS
    okcrypto_split_sundae(state, iv2, len, function4, true);
#endif

#ifdef DEBUG
    Serial.print("DECRYPTED STATE");
    byteprint(state, len);
#endif
//if (!gcm.checkTag(tag, sizeof(tag))) {
//	return 1;
//}
#endif
}

void okcrypto_aes_gcm_encrypt2(uint8_t *state, uint8_t *iv1, const uint8_t *key, int len, bool s) {
#ifdef STD_VERSION
    GCM<AES256> gcm;
    //uint8_t tag[16];
    uint8_t function1 = 1;
    uint8_t function2 = 2;
#ifdef DEBUG
    Serial.print("DECRYPTED STATE");
    byteprint(state, len);
#endif

#ifdef FACTORYKEYS
    // Even/Odd IV different encryption algorithms
    if (iv1[0] % 2 == 0) {
        function1 = 2;
        function2 = 1;
    }
    okcrypto_split_sundae(state, iv1, len, function1, s);
#endif

    gcm.clear();
    gcm.setKey(key, 32);
    gcm.setIV(iv1, 12);
    gcm.encrypt(state, state, len);

#ifdef FACTORYKEYS
    okcrypto_split_sundae(state, iv1, len, function2, s);
#endif

#ifdef DEBUG
    Serial.print("ENCRYPTED STATE");
    byteprint(state, len);
#endif
//gcm.computeTag(tag, sizeof(tag));
#endif
}

void okcrypto_aes_gcm_decrypt2(uint8_t *state, uint8_t *iv1, const uint8_t *key, int len, bool s) {
#ifdef STD_VERSION
    GCM<AES256> gcm;
    //uint8_t tag[16];
    uint8_t function3 = 4;
    uint8_t function4 = 3;
#ifdef DEBUG
    Serial.print("ENCRYPTED STATE");
    byteprint(state, len);
#endif

#ifdef FACTORYKEYS
    // Even/Odd IV different encryption algorithm sequence
    if (iv1[0] % 2 == 0) {
        function3 = 3;
        function4 = 4;
    }
    okcrypto_split_sundae(state, iv1, len, function3, s);
#endif

    gcm.clear();
    gcm.setKey(key, 32);
    gcm.setIV(iv1, 12);
    gcm.decrypt(state, state, len);

#ifdef FACTORYKEYS
    okcrypto_split_sundae(state, iv1, len, function4, s);
#endif

#ifdef DEBUG
    Serial.print("DECRYPTED STATE");
    byteprint(state, len);
#endif
//if (!gcm.checkTag(tag, sizeof(tag))) {
//	return 1;
//}
#endif
}

void okcrypto_aes_cbc_encrypt(uint8_t *state, uint8_t *iv, const uint8_t *key, int len) {
#ifdef STD_VERSION
    CBC<AES256> cbc;
#ifdef DEBUG
    Serial.print("DECRYPTED STATE");
    byteprint(state, len);
#endif
    cbc.clear();
    cbc.setKey(key, 32);
    cbc.setIV(iv, 16);
    cbc.encrypt(state, state, len);
#ifdef DEBUG
    Serial.print("ENCRYPTED STATE");
    byteprint(state, len);
#endif
#endif
}

void okcrypto_aes_cbc_decrypt(uint8_t *state, uint8_t *iv, const uint8_t *key, int len) {
#ifdef STD_VERSION
    CBC<AES256> cbc;
#ifdef DEBUG
    Serial.print("ENCRYPTED STATE");
    byteprint(state, len);
#endif
    cbc.clear();
    cbc.setKey(key, 32);
    cbc.setIV(iv, 16);
    cbc.decrypt(state, state, len);
#ifdef DEBUG
    Serial.print("DECRYPTED STATE");
    byteprint(state, len);
#endif
#endif
}

/*
void newhope_test ()
{
	//unsigned long ran;
	char rand[32];
	csprng SRNG,CRNG;
	RAND_clean(&SRNG);
	RAND_clean(&CRNG);
	char s[1792],sb[1824],uc[2176],keyA[32],keyB[32];

	octet S= {0,sizeof(s),s};
	octet SB= {0,sizeof(sb),sb};
	octet UC= {0,sizeof(uc),uc};
	octet KEYA={0,sizeof(keyA),keyA};
	octet KEYB={0,sizeof(keyB),keyB};
	RNG2((uint8_t*)rand, 32);
	RAND_seed(&SRNG, rand);
	RNG2((uint8_t*)rand, 32);
	RAND_seed(&CRNG, rand);

	// NewHope Simple key exchange

	NHS_SERVER_1(&SRNG,&SB,&S);
	NHS_CLIENT(&CRNG,&SB,&UC,&KEYB);
	NHS_SERVER_2(&S,&UC,&KEYA);
#ifdef DEBUG
	Serial.println("NewHope Simple Implemetation from open source AMCL crypto library (https://github.com/MIRACL/amcl)");
	Serial.println("Ref. Alkim, Ducas, Popplemann and Schwabe (https://eprint.iacr.org/2016/1157)");
	Serial.printf("Alice shared secret= 0x");
	byteprint((uint8_t*)KEYA.val, KEYA.len);
	Serial.printf("Bob's shared secret= 0x");
	byteprint((uint8_t*)KEYB.val, KEYB.len);
#endif
	return;
} */

void okcrypto_split_sundae(uint8_t *state, uint8_t *iv, int len, uint8_t function, bool s) {
    // Just like an ice cream sundae, this function mixes the best crypto algorithms
    // together in variable order with multiple variable keys and in order to mitigate
    // side channel attacks against a single algorithm or key. State is split so that
    // each crypto function only has access to part of the state. Order of algorithms
    // vary depending on IV. Keys vary depending on the IV and shift 0-12 bytes.
    //
    // Here is how it works
    //
    // Each function only has access to half (or less) of the input/output
    //
    // 1 has access to first 1/3 bytes
    // 2 has access to last 1/3 bytes
    // 3 has access to middle 1/3 bytes
    //
    // AES-256 GCM has access to all bytes
    //
    // 1 has access to last 1/2 bytes
    // 2 has access to first 1/2 bytes
    //
    // Each byte is double or triple encrypted using different algorithms
    // The middle algorithm is a FIPS 140-2 compliant algorithm for FIPS compliance
    //
    // Encrypt usage:
    // okcrypto_split_sundae(<plaintext>, <plaintext len>, <iv>, <encrypt outer>)
    // return ciphertext
    // middle encryption is completed in calling function
    // okcrypto_split_sundae(<ciphertext>, <ciphertext len>, <iv>, <encrypt inner>)
    // return ciphertext
    //
    // Decrypt usage:
    // okcrypto_split_sundae(<ciphertext>, <ciphertext len>, <iv>, <decrypt inner>)
    // return ciphertext
    // middle decryption is completed in calling function
    // okcrypto_split_sundae(<ciphertext>, <ciphertext len>, <iv>, <decrypt outer>)
    // return plaintext

    // crypto_stream_xsalsa20 requires 24 NONCEBYTES, a difererent nonce is required for each message
    // "...crypto_stream_xor with a different nonce for each message, the ciphertexts are indistinguishable
    // from uniform random strings of the same length" https://nacl.cr.yp.to/stream.html

    if ((*certified_hw != 1 && *certified_hw != 3) || s == false) return;

    uint8_t iv2[24] = {0};
    memcpy(iv2, iv, 12);
    uint8_t tempkey[32];

    if (function == 1) {
        // chocolate_syrup[32] (ChaCha 256)
        // has access to last 1/3 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(chocolate_syrup + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        ChaCha chacha;
        uint8_t counter[8] = {0};
        chacha.clear();
        chacha.setKey(tempkey, 32);
        chacha.setIV(iv2, 8);
        chacha.setCounter(counter, 8);
        chacha.encrypt(state + (len - (len / 3)), state + (len - (len / 3)), len / 3);
        // whipped_cream[32]  (NACL crypto_stream_salsa20)
        // has access to first 1/3 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(whipped_cream + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        crypto_stream_salsa20_xor(state, state, (len / 3), iv2, tempkey);
        // cherry_on_top[32] (NACL crypto_stream_xsalsa20)
        // has access to middle 1/3 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(cherry_on_top + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        crypto_stream_xsalsa20_xor(state + (len / 3), state + (len / 3), len / 3, iv2, tempkey);

    } else if (function == 2) {
        // banana[32] (ChaCha)
        // has access to first 1/2 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(banana + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        ChaCha chacha;
        uint8_t counter[8] = {0};
        chacha.clear();
        chacha.setKey(tempkey, 32);
        chacha.setIV(iv2, 8);
        chacha.setCounter(counter, 8);
        chacha.encrypt(state, state, len / 2);
        // ice_cream[32] (NACL crypto_stream_salsa20)
        // has access to last 1/2 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(ice_cream + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        crypto_stream_salsa20_xor(state + (len - (len / 2)), state + (len - (len / 2)), (len / 2), iv2, tempkey);

    } else if (function == 3) {
        // cherry_on_top[32] - (NACL crypto_stream_xsalsa20)
        // has access to middle 1/3 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(cherry_on_top + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        crypto_stream_xsalsa20_xor(state + (len / 3), state + (len / 3), len / 3, iv2, tempkey);
        // whipped_cream[32] (NACL crypto_stream_salsa20)
        // has access to first 1/3 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(whipped_cream + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        crypto_stream_salsa20_xor(state, state, (len / 3), iv2, tempkey);
        // chocolate_syrup[32] (ChaCha 256)
        // has access to last 1/3 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(chocolate_syrup + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        ChaCha chacha;
        uint8_t counter[8] = {0};
        chacha.clear();
        chacha.setKey(tempkey, 32);
        chacha.setIV(iv2, 8);
        chacha.setCounter(counter, 8);
        chacha.decrypt(state + (len - (len / 3)), state + (len - (len / 3)), len / 3);

    } else if (function == 4) {
        // ice_cream[32](NACL crypto_stream_salsa20)
        // has access to last 1/2 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(ice_cream + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        crypto_stream_salsa20_xor(state + (len - (len / 2)), state + (len - (len / 2)), (len / 2), iv2, tempkey);
        // banana[32] (ChaCha 256)
        // has access to first 1/2 bytes
        memcpy((uint8_t *)tempkey, (uint8_t *)(banana + (((iv2[0] + iv2[1]) % 4) * 4)), 32);
        ChaCha chacha;
        uint8_t counter[8] = {0};
        chacha.clear();
        chacha.setKey(tempkey, 32);
        chacha.setIV(iv2, 8);
        chacha.setCounter(counter, 8);
        chacha.decrypt(state, state, len / 2);
    }
}

/*************************************/
//ML-KEM-768 operations
//Seed stored as 32-byte ECC key with KEYTYPE_MLKEM768
/*************************************/

void okcrypto_mlkem_keygen(uint8_t *buffer) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
#ifdef DEBUG
    Serial.println();
    Serial.println("MLKEM KEYGEN MESSAGE RECEIVED");
#endif
    /* No confirmation: keygen is reachable only through OKSETPRIV, in config
	 * mode or on first use. */

    // buffer[5] = slot, buffer[6] = type, buffer[7..38] = key
    uint8_t seed[32];
    RNG2(buffer + 7, 32);
    memcpy(seed, buffer + 7, 32); // ecc_priv_flash() encrypts buffer+7 in place; keep the plaintext seed
    buffer[6] = (KEYTYPE_MLKEM768 & 0x0F) | 0x20; // type with decrypt feature (bit 5)
    ecc_priv_flash(buffer, false, true); // quiet: the public key below IS the response

    uint8_t coins[64];
    xwing_shake256(coins, 64, seed, 32);
    memset(seed, 0, sizeof(seed));

    uint8_t *sk = ctap_buffer;
    uint8_t *pk = ctap_buffer + MLKEM_SK_SIZE;
    if (crypto_kem_keypair_derand(pk, sk, coins) != 0) {
        hidprint("Error ML-KEM keygen failed");
        fadeoff(0);
        memset(coins, 0, 64);
        memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
        return;
    }
#ifdef DEBUG
    Serial.println("ML-KEM keypair generated");
    Serial.print("PK first 16 bytes: ");
    byteprint(pk, 16);
#endif

    pending_operation = CTAP2_ERR_DATA_READY;
    send_transport_response(pk, MLKEM_PK_SIZE, true, true);

    memset(coins, 0, 64);
    memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
    fadeoff(85);
}

void okcrypto_mlkem_decaps(uint8_t *buffer) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
    uint8_t ss[MLKEM_SS_SIZE];
#ifdef DEBUG
    Serial.println();
    Serial.println("MLKEM DECAPS MESSAGE RECEIVED");
#endif
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
    } else if (CRYPTO_AUTH == 4) {
        okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
        if (large_buffer_offset != MLKEM_CT_SIZE) {
            hidprint("Error ML-KEM CT wrong size");
            fadeoff(0);
            memset(large_buffer, 0, LARGE_BUFFER_SIZE);
            return;
        }

        // Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
        uint8_t coins[64];
        xwing_shake256(coins, 64, ecc_private_key, 32);

        uint8_t *sk = ctap_buffer;
        uint8_t *pk = ctap_buffer + MLKEM_SK_SIZE;
        if (crypto_kem_keypair_derand(pk, sk, coins) != 0) {
            hidprint("Error ML-KEM key expansion failed");
            memset(coins, 0, 64);
            memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
            memset(large_buffer, 0, LARGE_BUFFER_SIZE);
            fadeoff(0);
            return;
        }
        memset(coins, 0, 64);

        if (crypto_kem_dec(ss, large_buffer, sk) != 0) {
            hidprint("Error ML-KEM decaps failed");
            memset(ss, 0, sizeof(ss));
            memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
            memset(large_buffer, 0, LARGE_BUFFER_SIZE);
            fadeoff(0);
            return;
        }
#ifdef DEBUG
        Serial.print("Shared secret: ");
        byteprint(ss, MLKEM_SS_SIZE);
#endif

        pending_operation = CTAP2_ERR_DATA_READY;
        outputmode = packet_buffer_details[2];
        send_transport_response(ss, MLKEM_SS_SIZE, true, true);
        if (outputmode != WEBAUTHN) {
            wipetasks();
        }

        memset(ss, 0, sizeof(ss));
        memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        fadeoff(85);
    } else {
#ifdef DEBUG
        Serial.println("Waiting for challenge buttons to be pressed");
#endif
    }
}

void okcrypto_mlkem_getpubkey(uint8_t *buffer) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
#ifdef DEBUG
    Serial.println();
    Serial.println("MLKEM GETPUBKEY MESSAGE RECEIVED");
#endif

    // Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
    uint8_t coins[64];
    xwing_shake256(coins, 64, ecc_private_key, 32);

    uint8_t *sk = ctap_buffer;
    uint8_t *pk = ctap_buffer + MLKEM_SK_SIZE;
    if (crypto_kem_keypair_derand(pk, sk, coins) != 0) {
        memset(coins, 0, 64);
        memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
        hidprint("Error ML-KEM keygen");
        return;
    }
    memset(coins, 0, 64);

    send_transport_response(pk, MLKEM_PK_SIZE, true, true);
    memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
}

/*************************************/
//X-Wing KEM operations (draft-connolly-cfrg-xwing-kem-09)
//Compatible with age v1.3.0 mlkem768x25519 recipient type
//Seed stored as 32-byte ECC key with KEYTYPE_XWING
/*************************************/

void okcrypto_xwing_keygen(uint8_t *buffer) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
#ifdef DEBUG
    Serial.println();
    Serial.println("XWING KEYGEN MESSAGE RECEIVED");
#endif
    /* No confirmation: keygen is reachable only through OKSETPRIV, in config
	 * mode or on first use. */

    uint8_t seed[XWING_SEED_SIZE];
    RNG2(buffer + 7, XWING_SEED_SIZE);
    memcpy(seed, buffer + 7, XWING_SEED_SIZE); // ecc_priv_flash() encrypts buffer+7 in place; keep the plaintext seed
    buffer[6] = (KEYTYPE_XWING & 0x0F) | 0x20; // type with decrypt feature (bit 5)
    ecc_priv_flash(buffer, false, true); // quiet: the public key below IS the response

    uint8_t expanded[96];
    xwing_shake256(expanded, 96, seed, XWING_SEED_SIZE);
    memset(seed, 0, sizeof(seed));

    uint8_t *sk_M = ctap_buffer;
    uint8_t *pk_M = ctap_buffer + MLKEM_SK_SIZE;
    if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
        hidprint("Error X-Wing ML-KEM keygen failed");
        fadeoff(0);
        memset(expanded, 0, 96);
        memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
        return;
    }

    uint8_t pk_X[32];
    crypto_scalarmult_base(pk_X, expanded + 64);

    memcpy(pk_M + MLKEM_PK_SIZE, pk_X, 32);

#ifdef DEBUG
    Serial.println("X-Wing keypair generated");
    Serial.print("PK_M first 16: ");
    byteprint(pk_M, 16);
    Serial.print("PK_X: ");
    byteprint(pk_X, 32);
#endif

    pending_operation = CTAP2_ERR_DATA_READY;
    send_transport_response(pk_M, XWING_PK_SIZE, true, true);

    memset(expanded, 0, 96);
    memset(pk_X, 0, 32);
    memset(ctap_buffer, 0, MLKEM_SK_SIZE + XWING_PK_SIZE);
    fadeoff(85);
}

void okcrypto_xwing_decaps(uint8_t *buffer) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
    uint8_t ss_M[32];
    uint8_t ss_X[32];
    uint8_t ss[XWING_SS_SIZE];
#ifdef DEBUG
    Serial.println();
    Serial.println("XWING DECAPS MESSAGE RECEIVED");
#endif
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
    } else if (CRYPTO_AUTH == 4) {
        okcore_aes_gcm_decrypt(large_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, large_buffer_offset);
        if (large_buffer_offset != XWING_CT_SIZE) {
            hidprint("Error X-Wing CT wrong size");
            fadeoff(0);
            memset(large_buffer, 0, LARGE_BUFFER_SIZE);
            return;
        }

        uint8_t *ct_M = large_buffer;
        uint8_t *ct_X = large_buffer + MLKEM_CT_SIZE;

        // Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
        uint8_t expanded[96];
        xwing_shake256(expanded, 96, ecc_private_key, XWING_SEED_SIZE);

        uint8_t *sk_M = ctap_buffer;
        uint8_t *pk_M = ctap_buffer + MLKEM_SK_SIZE;
        if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
            hidprint("Error X-Wing key expansion failed");
            memset(expanded, 0, 96);
            memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
            memset(large_buffer, 0, LARGE_BUFFER_SIZE);
            fadeoff(0);
            return;
        }

        uint8_t *sk_X = expanded + 64;
        uint8_t pk_X[32];
        crypto_scalarmult_base(pk_X, sk_X);

        if (crypto_kem_dec(ss_M, ct_M, sk_M) != 0) {
            hidprint("Error X-Wing ML-KEM decaps failed");
            memset(ss_M, 0, 32);
            memset(expanded, 0, 96);
            memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
            memset(large_buffer, 0, LARGE_BUFFER_SIZE);
            fadeoff(0);
            return;
        }

        crypto_scalarmult(ss_X, sk_X, ct_X);

        xwing_combiner(ss, ss_M, ss_X, ct_X, pk_X);

#ifdef DEBUG
        Serial.print("ss_M: ");
        byteprint(ss_M, 32);
        Serial.print("ss_X: ");
        byteprint(ss_X, 32);
        Serial.print("X-Wing SS: ");
        byteprint(ss, XWING_SS_SIZE);
#endif

        pending_operation = CTAP2_ERR_DATA_READY;
        outputmode = packet_buffer_details[2];
        send_transport_response(ss, XWING_SS_SIZE, true, true);
        if (outputmode != WEBAUTHN) {
            wipetasks();
        }

        memset(ss_M, 0, 32);
        memset(ss_X, 0, 32);
        memset(ss, 0, XWING_SS_SIZE);
        memset(expanded, 0, 96);
        memset(pk_X, 0, 32);
        memset(ctap_buffer, 0, MLKEM_SK_SIZE + MLKEM_PK_SIZE);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        fadeoff(85);
    } else {
#ifdef DEBUG
        Serial.println("Waiting for challenge buttons to be pressed");
#endif
    }
}

void okcrypto_xwing_getpubkey(uint8_t *buffer) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
#ifdef DEBUG
    Serial.println();
    Serial.println("XWING GETPUBKEY MESSAGE RECEIVED");
#endif

    // Seed already loaded into ecc_private_key by okcore_flashget_ECC in dispatch
    uint8_t expanded[96];
    xwing_shake256(expanded, 96, ecc_private_key, XWING_SEED_SIZE);

    uint8_t *sk_M = ctap_buffer;
    uint8_t *pk_M = ctap_buffer + MLKEM_SK_SIZE;
    if (crypto_kem_keypair_derand(pk_M, sk_M, expanded) != 0) {
        memset(expanded, 0, 96);
        memset(ctap_buffer, 0, MLKEM_SK_SIZE + XWING_PK_SIZE);
        hidprint("Error ML-KEM keygen");
        return;
    }

    uint8_t pk_X[32];
    crypto_scalarmult_base(pk_X, expanded + 64);

    memcpy(pk_M + MLKEM_PK_SIZE, pk_X, 32);

    send_transport_response(pk_M, XWING_PK_SIZE, true, true);

    memset(expanded, 0, 96);
    memset(pk_X, 0, 32);
    memset(ctap_buffer, 0, MLKEM_SK_SIZE + XWING_PK_SIZE);
}

void okcrypto_compute_pubkey() {
    memset(ecc_public_key, 0, sizeof(ecc_public_key));

    // PQC slots hold seeds; their public keys are computed on demand.
    if (type == KEYTYPE_MLKEM768 || type == KEYTYPE_XWING) return;

    if (type == KEYTYPE_ED25519) {
        Ed25519::derivePublicKey(ecc_public_key, ecc_private_key);
    } else if (type == KEYTYPE_P256R1) {
        const struct uECC_Curve_t *curve = uECC_secp256r1();
        uECC_compute_public_key(ecc_private_key, ecc_public_key, curve);
    } else if (type == KEYTYPE_P256K1) {
        const struct uECC_Curve_t *curve = uECC_secp256k1();
        uECC_compute_public_key(ecc_private_key, ecc_public_key, curve);
    } else if (type == KEYTYPE_CURVE25519) {
        swap_buffer(0, 31, ecc_private_key);
        Curve25519::eval(ecc_public_key, ecc_private_key, 0);
    }
#ifdef DEBUG
    Serial.println("Computed Public");
    byteprint(ecc_public_key, sizeof(ecc_public_key));
#endif
}

void swap_buffer(uint8_t start, uint8_t end, uint8_t *buffer) {
    // Swap buffer
    // http://gnupg.10057.n7.nabble.com/Correct-method-to-generate-a-Curve25519-keypair-td56013.html
    uint8_t tmp;
    while (start < end) {
        tmp = buffer[start];
        buffer[start] = buffer[end];
        buffer[end] = tmp;
        start++;
        end--;
    }
}

#endif
