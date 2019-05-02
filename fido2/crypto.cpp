// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*
 *  Wrapper for crypto implementation on device
 *
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "crypto.h"
#include "WProgram.h"

#ifdef USE_SOFTWARE_IMPLEMENTATION

#include "sha256.h"
#include "uECC.h"
//#include "aes.h"
#include "device.h"
#include "log.h"
//#include APP_CONFIG
#include "ctap.h"
#include "oku2f.h"


//#ifdef USING_PC
typedef enum
{
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    MBEDTLS_ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    MBEDTLS_ECP_DP_CURVE25519,           /*!< Curve25519               */
    MBEDTLS_ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
} mbedtls_ecp_group_id;
//#endif


//const uint8_t attestation_cert_der[];
//const uint16_t attestation_cert_der_size;
//const uint8_t attestation_key[];
//const uint16_t attestation_key_size;



static SHA256_CTX sha256_ctx;
static const struct uECC_Curve_t * _es256_curve = NULL;
static const uint8_t * _signing_key = NULL;
static int _key_len = 0;

// Secrets for testing only
static uint8_t master_secret[64];

static uint8_t transport_secret[32];



void crypto_sha256_init()
{
    sha256_init(&sha256_ctx);
}

void crypto_reset_master_secret()
{
    ctap_generate_rng(master_secret, 64);
    ctap_generate_rng(transport_secret, 32);
}

void crypto_load_master_secret(uint8_t * key)
{
    #if KEY_SPACE_BYTES < 96
    //#error "need more key bytes"
    #endif
    memmove(master_secret, key, 64);
    memmove(transport_secret, key+64, 32);
}

void crypto_sha256_update(uint8_t * data, size_t len)
{
    sha256_update(&sha256_ctx, data, len);
}

void crypto_sha256_update_secret()
{
    sha256_update(&sha256_ctx, master_secret, 32);
}

void crypto_sha256_final(uint8_t * hash)
{
    sha256_final(&sha256_ctx, hash);
}

void crypto_sha256_hmac_init(uint8_t * key, uint32_t klen, uint8_t * hmac)
{
    uint8_t buf[64];
    int i;
    memset(buf, 0, sizeof(buf));

    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret);
    }
    else if (key == CRYPTO_TRANSPORT_KEY)
    {
        key = transport_secret;
        klen = 32;
    }

    if(klen > 64)
    {
        printf2(TAG_ERR,"Error, key size must be <= 64\n");
        exit(1);
    }

    memmove(buf, key, klen);

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = buf[i] ^ 0x36;
    }

    crypto_sha256_init();
    crypto_sha256_update(buf, 64);
}

void crypto_sha256_hmac_final(uint8_t * key, uint32_t klen, uint8_t * hmac)
{
    uint8_t buf[64];
    int i;
    crypto_sha256_final(hmac);
    memset(buf, 0, sizeof(buf));
    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret);
    }


    if(klen > 64)
    {
        printf2(TAG_ERR,"Error, key size must be <= 64\n");
        exit(1);
    }
    memmove(buf, key, klen);

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = buf[i] ^ 0x5c;
    }

    crypto_sha256_init();
    crypto_sha256_update(buf, 64);
    crypto_sha256_update(hmac, 32);
    crypto_sha256_final(hmac);
}


void crypto_ecc256_init()
{
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    _es256_curve = uECC_secp256r1();
}


void crypto_ecc256_load_attestation_key()
{
    _signing_key = attestation_key;
    _key_len = 32;
}

void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig)
{

	//use deterministic signing
	//uint8_t tmp[32 + 32 + 64];
	//SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
  //if ( uECC_sign_deterministic(_signing_key, data, len, &ectx.uECC, sig, _es256_curve)== 0)
  Serial.print("Data to sign ");
  byteprint(data, len);
  if ( uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0)
    {
        printf2(TAG_ERR,"error, uECC failed\n");
        exit(1);
    }
    Serial.print("Sig");
    byteprint(sig, 64);
}

void crypto_ecc256_load_key(uint8_t * data, int len, uint8_t * data2, int len2)
{
    static uint8_t privkey[32];
    generate_private_key(data,len,data2,len2,privkey);
    _signing_key = privkey;
    _key_len = 32;
}

void crypto_ecdsa_sign(uint8_t * data, int len, uint8_t * sig, int MBEDTLS_ECP_ID)
{

    const struct uECC_Curve_t * curve = NULL;
	//use deterministic signing
	//uint8_t tmp[32 + 32 + 64];
	//SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};

    switch(MBEDTLS_ECP_ID)
    {
        case MBEDTLS_ECP_DP_SECP192R1:
            curve = uECC_secp192r1();
            if (_key_len != 24)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP224R1:
            curve = uECC_secp224r1();
            if (_key_len != 28)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP256R1:
            curve = uECC_secp256r1();
            if (_key_len != 32)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP256K1:
            curve = uECC_secp256k1();
            if (_key_len != 32)  goto fail;
            break;
        default:
            printf2(TAG_ERR,"error, invalid ECDSA alg specifier\n");
            exit(1);
    }
	  //if ( uECC_sign_deterministic(_signing_key, data, len, &ectx.uECC, sig, curve)== 0)
    Serial.print("Data to sign ");
    byteprint(data, len);
    if ( uECC_sign(_signing_key, data, len, sig, curve) == 0)
    {
        printf2(TAG_ERR,"error, uECC failed\n");
        exit(1);
    }
    Serial.print("Sig");
    byteprint(sig, 64);
    return;

fail:
    printf2(TAG_ERR,"error, invalid key length\n");
    exit(1);

}

void generate_private_key(uint8_t * data, int len, uint8_t * data2, int len2, uint8_t * privkey)
{
    crypto_sha256_hmac_init(CRYPTO_MASTER_KEY, 0, privkey);
    crypto_sha256_update(data, len);
    crypto_sha256_update(data2, len2);
    crypto_sha256_update(master_secret, 32);
    crypto_sha256_hmac_final(CRYPTO_MASTER_KEY, 0, privkey);
}


/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);*/
void crypto_ecc256_derive_public_key(uint8_t * data, int len, uint8_t * x, uint8_t * y)
{
    uint8_t privkey[32];
    uint8_t pubkey[64];

    generate_private_key(data,len,NULL,0,privkey);
	Serial.println("crypto_ecc256_derive_public_key start");
    memset(pubkey,0,sizeof(pubkey));
	//const struct uECC_Curve_t * curve = uECC_secp256r1();
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
	  //memset(pubkey, 0, sizeof(pubkey));
      //memset(privkey, 0, sizeof(privkey));
      //uECC_make_key(pubkey, privkey, _es256_curve);

      Serial.println(F("Public K"));
	  byteprint(pubkey, sizeof(pubkey));
      Serial.println();
      Serial.println(F("Private K"));
	  byteprint(privkey, sizeof(privkey));
      Serial.println();

	Serial.println("crypto_ecc256_derive_public_key finish");
    memmove(x,pubkey,32);
    memmove(y,pubkey+32,32);
}

void crypto_load_external_key(uint8_t * key, int len)
{
    _signing_key = key;
    _key_len = len;
}


void crypto_ecc256_make_key_pair(uint8_t * pubkey, uint8_t * privkey)
{
    if (uECC_make_key(pubkey, privkey, _es256_curve) != 1)
    {
        printf2(TAG_ERR,"Error, uECC_make_key failed\n");
        exit(1);
    }
}

void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret)
{
    if (uECC_shared_secret(pubkey, privkey, shared_secret, _es256_curve) != 1)
    {
        printf2(TAG_ERR,"Error, uECC_shared_secret failed\n");
        exit(1);
    }

}

/*
struct AES_ctx aes_ctx;
void crypto_aes256_init(uint8_t * key, uint8_t * nonce)
{
    if (key == CRYPTO_TRANSPORT_KEY)
    {
        AES_init_ctx(&aes_ctx, transport_secret);
    }
    else
    {
        AES_init_ctx(&aes_ctx, key);
    }
    if (nonce == NULL)
    {
        memset(aes_ctx.Iv, 0, 16);
    }
    else
    {
        memmove(aes_ctx.Iv, nonce, 16);
    }
}

// prevent round key recomputation
void crypto_aes256_reset_iv(uint8_t * nonce)
{
    if (nonce == NULL)
    {
        memset(aes_ctx.Iv, 0, 16);
    }
    else
    {
        memmove(aes_ctx.Iv, nonce, 16);
    }
}

void crypto_aes256_decrypt(uint8_t * buf, int length)
{

}

void crypto_aes256_encrypt(uint8_t * buf, int length)
{
    AES_CBC_encrypt_buffer(&aes_ctx, buf, length);
}
*/

uint8_t attestation_cert_der[768] =
"\x30\x82\x02\x88\x30\x82\x02\x2e\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x6c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4e\x43\x31\x10\x30\x0e"
"\x06\x03\x55\x04\x0a\x0c\x07\x4f\x4e\x4c\x59\x4b\x45\x59\x31\x10\x30\x0e\x06\x03"
"\x55\x04\x0b\x0c\x07\x52\x6f\x6f\x74\x20\x43\x41\x31\x0f\x30\x0d\x06\x03\x55\x04"
"\x03\x0c\x06\x63\x72\x70\x2e\x74\x6f\x31\x1b\x30\x19\x06\x09\x2a\x86\x48\x86\xf7"
"\x0d\x01\x09\x01\x16\x0c\x61\x64\x6d\x69\x6e\x40\x63\x72\x70\x2e\x74\x6f\x30\x20"
"\x17\x0d\x31\x39\x30\x35\x30\x32\x31\x38\x32\x33\x30\x35\x5a\x18\x0f\x32\x30\x36"
"\x39\x30\x34\x31\x39\x31\x38\x32\x33\x30\x35\x5a\x30\x5a\x31\x0b\x30\x09\x06\x03"
"\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4e\x43"
"\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x0c\x07\x4f\x4e\x4c\x59\x4b\x45\x59\x31\x0f"
"\x30\x0d\x06\x03\x55\x04\x03\x0c\x06\x63\x72\x70\x2e\x74\x6f\x31\x1b\x30\x19\x06"
"\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x0c\x61\x64\x6d\x69\x6e\x40\x63\x72"
"\x70\x2e\x74\x6f\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a"
"\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x77\x78\xaa\x92\xb1\xa0\xfa\xfd\xdf"
"\xc9\x23\x8d\x3a\xcd\x21\xa3\x6f\x34\x7d\x63\xa0\x32\xf1\x49\x2a\x5b\x27\x13\xcf"
"\x6e\x85\x9c\x55\x7b\x01\x7f\x63\xfa\x32\xb3\x96\x96\x7b\x4d\x84\x9e\x3e\xba\xa1"
"\xcb\x05\x04\xb2\xc8\x3e\x4e\xc3\x0a\x4c\x7d\xfe\x42\xf5\xa6\xa3\x81\xd0\x30\x81"
"\xcd\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x1b\x39\x85\xf2\x23\x2f\xf9\x8a"
"\xe7\xf4\x6e\x20\x25\xcf\x3f\xb6\x08\x66\x63\xea\x30\x81\x93\x06\x03\x55\x1d\x23"
"\x04\x81\x8b\x30\x81\x88\xa1\x70\xa4\x6e\x30\x6c\x31\x0b\x30\x09\x06\x03\x55\x04"
"\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4e\x43\x31\x10"
"\x30\x0e\x06\x03\x55\x04\x0a\x0c\x07\x4f\x4e\x4c\x59\x4b\x45\x59\x31\x10\x30\x0e"
"\x06\x03\x55\x04\x0b\x0c\x07\x52\x6f\x6f\x74\x20\x43\x41\x31\x0f\x30\x0d\x06\x03"
"\x55\x04\x03\x0c\x06\x63\x72\x70\x2e\x74\x6f\x31\x1b\x30\x19\x06\x09\x2a\x86\x48"
"\x86\xf7\x0d\x01\x09\x01\x16\x0c\x61\x64\x6d\x69\x6e\x40\x63\x72\x70\x2e\x74\x6f"
"\x82\x14\x50\x6b\x36\x41\x99\x2d\x57\x4d\xa3\x17\xaa\x92\x34\x6c\x4a\x54\x3c\x4b"
"\x8b\x75\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f"
"\x04\x04\x03\x02\x04\xf0\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48"
"\x00\x30\x45\x02\x20\x32\x2e\xcd\xea\xe7\xd8\x60\xa3\x00\x56\x7d\xd9\x46\xae\x40"
"\x84\x84\x2f\x9d\x9e\xad\xdd\x58\xe9\x9e\x19\xc6\xba\x56\x24\xfc\x7c\x02\x21\x00"
"\x9c\x1e\x22\x87\xb0\x2c\xca\x13\xe5\x12\xd6\xaf\xf3\xa6\x4e\xd8\x0a\x06\xde\x6a"
"\xe3\x2f\xc7\x22\x0a\x14\xcd\x53\xed\xf5\x91\x86"
;

// If changing attestation cert change 116 to offset size
uint16_t attestation_cert_der_size = sizeof(attestation_cert_der)-116;

uint8_t attestation_key[33] = "\x1e\xfd\xda\x08\xee\x26\x06\x0e\xf1\xf9\x25\xfe\x57\x1d\xa0\x0d\xa9\x4b\xe8\xce\x29\x79\xb2\x79\xdf\x33\xa9\xfb\x6a\xe8\xcc\x90";

uint16_t attestation_key_size = sizeof(attestation_key)-1;


#else
#error "No crypto implementation defined"
#endif
