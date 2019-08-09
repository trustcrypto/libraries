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


static SHA256_CTX sha256_ctx;
static const struct uECC_Curve_t * _es256_curve = NULL;
static const uint8_t * _signing_key = NULL;
static int _key_len = 0;


static uint8_t master_secret[64];
static uint8_t transport_secret[32];


void crypto_sha256_init()
{
    sha256_init(&sha256_ctx);
}

void crypto_load_master_secret(uint8_t * key)
{
    #if KEY_SPACE_BYTES < 96
    //#error "need more key bytes"
    #endif
    memmove(master_secret, key, 64);
    memmove(transport_secret, key+64, 32);
}

void crypto_reset_master_secret()
{
	memset(master_secret, 0, 64);
    memset(transport_secret, 0, 32);
    ctap_generate_rng(master_secret, 64);
    ctap_generate_rng(transport_secret, 32);
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
    unsigned int i;
    memset(buf, 0, sizeof(buf));

    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret)/2;
    }
    else if (key == CRYPTO_TRANSPORT_KEY)
    {
        key = transport_secret;
        klen = 32;
    }

    if(klen > 64)
    {
        printf2(TAG_ERR, "Error, key size must be <= 64\n");
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
    unsigned int i;
    crypto_sha256_final(hmac);
    memset(buf, 0, sizeof(buf));
    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret)/2;
    }
    else if (key == CRYPTO_TRANSPORT_KEY2)
    {
        key = transport_secret;
        klen = 32;
    }


    if(klen > 64)
    {
        printf2(TAG_ERR, "Error, key size must be <= 64\n");
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
{ //use deterministic signing
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
  if ( uECC_sign_deterministic(_signing_key, data, len, &ectx.uECC, sig, _es256_curve)== 0)
    {
        printf2(TAG_ERR,"error, uECC failed\n");
        exit(1);
    }
}
void crypto_ecc256_load_key(uint8_t * data, int len, uint8_t * data2, int len2)
{
    static uint8_t privkey[32];
    generate_private_key(data,len,data2,len2,privkey);
    _signing_key = privkey;
    _key_len = 32;
}
void crypto_ecdsa_sign(uint8_t * data, int len, uint8_t * sig, int MBEDTLS_ECP_ID)
{ //use deterministic signing
  const struct uECC_Curve_t * curve = NULL;
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
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
            printf2(TAG_ERR, "error, invalid ECDSA alg specifier\n");
            exit(1);
    }
    
	if ( uECC_sign_deterministic(_signing_key, data, len, &ectx.uECC, sig, curve)== 0)
    {
        printf2(TAG_ERR,"error, uECC failed\n");
        exit(1);
    }
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
    crypto_sha256_update(master_secret, 32);    // TODO AES
    crypto_sha256_hmac_final(CRYPTO_MASTER_KEY, 0, privkey);

	//crypto_aes256_init(master_secret + 32, NULL);
    //crypto_aes256_encrypt(privkey, 32);
    //Replacing SOLO AES-CBC with OnlyKey AES-CBC
	crypto_aes256_encrypt(privkey, master_secret + 32, 32);

 }


/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);*/
void crypto_ecc256_derive_public_key(uint8_t * data, int len, uint8_t * x, uint8_t * y)
{
    uint8_t privkey[32];
    uint8_t pubkey[64];

    generate_private_key(data,len,NULL,0,privkey);
	//Serial.println("crypto_ecc256_derive_public_key start");
    memset(pubkey,0,sizeof(pubkey));
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
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
        printf2(TAG_ERR, "Error, uECC_make_key failed\n");
        exit(1);
    }
}

void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret)
{
    if (uECC_shared_secret(pubkey, privkey, shared_secret, _es256_curve) != 1)
    {
        printf2(TAG_ERR, "Error, uECC_shared_secret failed\n");
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
"\x30\x82\x02\xcf\x30\x82\x02\x75\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x7b\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x08\x0c\x0e\x4e\x6f\x72\x74\x68\x20"
"\x43\x61\x72\x6f\x6c\x69\x6e\x61\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0b\x43"
"\x72\x79\x70\x74\x6f\x54\x72\x75\x73\x74\x31\x10\x30\x0e\x06\x03\x55\x04\x0b\x0c"
"\x07\x52\x6f\x6f\x74\x20\x43\x41\x31\x0f\x30\x0d\x06\x03\x55\x04\x03\x0c\x06\x63"
"\x72\x70\x2e\x74\x6f\x31\x1a\x30\x18\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01"
"\x16\x0b\x69\x6e\x66\x6f\x40\x63\x72\x70\x2e\x74\x6f\x30\x20\x17\x0d\x31\x39\x30"
"\x38\x30\x39\x31\x32\x32\x36\x30\x38\x5a\x18\x0f\x32\x30\x36\x39\x30\x37\x32\x37"
"\x31\x32\x32\x36\x30\x38\x5a\x30\x81\x8d\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x08\x0c\x0e\x4e\x6f\x72\x74\x68\x20"
"\x43\x61\x72\x6f\x6c\x69\x6e\x61\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0b\x43"
"\x72\x79\x70\x74\x6f\x54\x72\x75\x73\x74\x31\x22\x30\x20\x06\x03\x55\x04\x0b\x0c"
"\x19\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72\x20\x41\x74\x74\x65\x73"
"\x74\x61\x74\x69\x6f\x6e\x31\x0f\x30\x0d\x06\x03\x55\x04\x03\x0c\x06\x63\x72\x70"
"\x2e\x74\x6f\x31\x1a\x30\x18\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x0b"
"\x69\x6e\x66\x6f\x40\x63\x72\x70\x2e\x74\x6f\x30\x59\x30\x13\x06\x07\x2a\x86\x48"
"\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x78\x07"
"\x66\x10\xcf\x5b\x05\x07\x95\xd2\xb6\x42\x5d\x4e\xad\xf0\x65\x34\x0a\x90\xc8\xaa"
"\x8a\x62\x13\xdb\x95\xa0\x4b\x0c\x95\xfc\x82\x8f\x2d\xf8\x4b\x79\xdd\x3e\xe9\xf0"
"\x02\x28\xa6\x8c\xe8\x62\x15\x4e\x3b\xa9\xe6\x84\x60\x2d\x75\x76\xdd\x9d\x9a\x2c"
"\x4c\x6a\xa3\x81\xd4\x30\x81\xd1\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\xdb"
"\xa0\x67\x63\x63\xc4\xf7\xf5\x71\xed\x00\x82\x0f\x92\xd3\x65\x65\x76\x87\x48\x30"
"\x81\x97\x06\x03\x55\x1d\x23\x04\x81\x8f\x30\x81\x8c\xa1\x7f\xa4\x7d\x30\x7b\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04"
"\x08\x0c\x0e\x4e\x6f\x72\x74\x68\x20\x43\x61\x72\x6f\x6c\x69\x6e\x61\x31\x14\x30"
"\x12\x06\x03\x55\x04\x0a\x0c\x0b\x43\x72\x79\x70\x74\x6f\x54\x72\x75\x73\x74\x31"
"\x10\x30\x0e\x06\x03\x55\x04\x0b\x0c\x07\x52\x6f\x6f\x74\x20\x43\x41\x31\x0f\x30"
"\x0d\x06\x03\x55\x04\x03\x0c\x06\x63\x72\x70\x2e\x74\x6f\x31\x1a\x30\x18\x06\x09"
"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x0b\x69\x6e\x66\x6f\x40\x63\x72\x70\x2e"
"\x74\x6f\x82\x09\x00\xa5\x85\x7b\x46\x32\x5a\xe6\xe1\x30\x09\x06\x03\x55\x1d\x13"
"\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04\x04\x03\x02\x04\xf0\x30\x0a\x06"
"\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00\x30\x45\x02\x21\x00\xa5\x6a\x92"
"\x50\x6a\x98\x18\x21\xe5\x9b\x3c\x2e\x76\x52\xc9\xce\xd1\xb4\x0f\x96\x29\xbc\x3c"
"\x89\x1d\x24\x15\x89\xb3\xff\x93\x36\x02\x20\x39\xdd\x74\x35\xfd\x8b\xef\x38\x1e"
"\xc3\x8d\xe5\x3f\x74\xcd\x68\xb0\x77\x18\x41\x84\xa2\x40\x8f\x58\x28\x1b\xa8\x17"
"\x15\xb7\x32"
;

// If changing attestation cert change to offset size add -1
uint16_t attestation_cert_der_size = sizeof(attestation_cert_der)-45;

uint8_t attestation_key[33] = "\x11\xc5\xd7\xe3\x2b\xd5\x64\x2d\xf8\x1c\xea\x3b\xcd\xa7\x9a\x64\xb7\x88\xee\xca\x97\x76\x03\xad\x44\xed\x32\x7a\x61\xc7\x1f\x92";
//uint8_t attestation_key[33] = "\x1e\xfd\xda\x08\xee\x26\x06\x0e\xf1\xf9\x25\xfe\x57\x1d\xa0\x0d\xa9\x4b\xe8\xce\x29\x79\xb2\x79\xdf\x33\xa9\xfb\x6a\xe8\xcc\x90";

uint16_t attestation_key_size = sizeof(attestation_key)-1;


#else
#error "No crypto implementation defined"
#endif
