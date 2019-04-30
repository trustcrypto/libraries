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
	Serial.println(" crypto_ecc256_sign start");
	//use deterministic signing 
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
    if ( uECC_sign_deterministic(_signing_key, data, len, &ectx.uECC, sig, _es256_curve)== 0)
	//if ( uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0)
    {
        printf2(TAG_ERR,"error, uECC failed\n");
        exit(1);
    }
	Serial.println(" crypto_ecc256_sign finish");
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
            printf2(TAG_ERR,"error, invalid ECDSA alg specifier\n");
            exit(1);
    }
	if ( uECC_sign_deterministic(_signing_key, data, len, &ectx.uECC, sig, curve)== 0)
    //if ( uECC_sign(_signing_key, data, len, sig, curve) == 0)
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
"\x30\x82\x02\xe9\x30\x82\x02\x8e\xa0\x03\x02\x01\x02\x02\x01\x01\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x81\x82\x31\x0b\x30\x09\x06\x03\x55\x04\x06"
"\x13\x02\x55\x53\x31\x11\x30\x0f\x06\x03\x55\x04\x08\x0c\x08\x4d\x61\x72\x79\x6c"
"\x61\x6e\x64\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0b\x53\x4f\x4c\x4f\x20\x48"
"\x41\x43\x4b\x45\x52\x31\x10\x30\x0e\x06\x03\x55\x04\x0b\x0c\x07\x52\x6f\x6f\x74"
"\x20\x43\x41\x31\x15\x30\x13\x06\x03\x55\x04\x03\x0c\x0c\x73\x6f\x6c\x6f\x6b\x65"
"\x79\x73\x2e\x63\x6f\x6d\x31\x21\x30\x1f\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09"
"\x01\x16\x12\x68\x65\x6c\x6c\x6f\x40\x73\x6f\x6c\x6f\x6b\x65\x79\x73\x2e\x63\x6f"
"\x6d\x30\x20\x17\x0d\x31\x38\x31\x32\x31\x31\x30\x32\x32\x30\x31\x32\x5a\x18\x0f"
"\x32\x30\x36\x38\x31\x31\x32\x38\x30\x32\x32\x30\x31\x32\x5a\x30\x81\x94\x31\x0b"
"\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x11\x30\x0f\x06\x03\x55\x04\x08"
"\x0c\x08\x4d\x61\x72\x79\x6c\x61\x6e\x64\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c"
"\x0b\x53\x4f\x4c\x4f\x20\x48\x41\x43\x4b\x45\x52\x31\x22\x30\x20\x06\x03\x55\x04"
"\x0b\x0c\x19\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72\x20\x41\x74\x74"
"\x65\x73\x74\x61\x74\x69\x6f\x6e\x31\x15\x30\x13\x06\x03\x55\x04\x03\x0c\x0c\x73"
"\x6f\x6c\x6f\x6b\x65\x79\x73\x2e\x63\x6f\x6d\x31\x21\x30\x1f\x06\x09\x2a\x86\x48"
"\x86\xf7\x0d\x01\x09\x01\x16\x12\x68\x65\x6c\x6c\x6f\x40\x73\x6f\x6c\x6f\x6b\x65"
"\x79\x73\x2e\x63\x6f\x6d\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06"
"\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x7d\x78\xf6\xbe\xca\x40\x76"
"\x3b\xc7\x5c\xe3\xac\xf4\x27\x12\xc3\x94\x98\x13\x37\xa6\x41\x0e\x92\xf6\x9a\x3b"
"\x15\x47\x8d\xb6\xce\xd9\xd3\x4f\x39\x13\xed\x12\x7b\x81\x14\x3b\xe8\xf9\x4c\x96"
"\x38\xfe\xe3\xd6\xcb\x1b\x53\x93\xa2\x74\xf7\x13\x9a\x0f\x9d\x5e\xa6\xa3\x81\xde"
"\x30\x81\xdb\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x9a\xfb\xa2\x21\x09\x23"
"\xb5\xe4\x7a\x2a\x1d\x7a\x6c\x4e\x03\x89\x92\xa3\x0e\xc2\x30\x81\xa1\x06\x03\x55"
"\x1d\x23\x04\x81\x99\x30\x81\x96\xa1\x81\x88\xa4\x81\x85\x30\x81\x82\x31\x0b\x30"
"\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x11\x30\x0f\x06\x03\x55\x04\x08\x0c"
"\x08\x4d\x61\x72\x79\x6c\x61\x6e\x64\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0b"
"\x53\x4f\x4c\x4f\x20\x48\x41\x43\x4b\x45\x52\x31\x10\x30\x0e\x06\x03\x55\x04\x0b"
"\x0c\x07\x52\x6f\x6f\x74\x20\x43\x41\x31\x15\x30\x13\x06\x03\x55\x04\x03\x0c\x0c"
"\x73\x6f\x6c\x6f\x6b\x65\x79\x73\x2e\x63\x6f\x6d\x31\x21\x30\x1f\x06\x09\x2a\x86"
"\x48\x86\xf7\x0d\x01\x09\x01\x16\x12\x68\x65\x6c\x6c\x6f\x40\x73\x6f\x6c\x6f\x6b"
"\x65\x79\x73\x2e\x63\x6f\x6d\x82\x09\x00\xeb\xd4\x84\x50\x14\xab\xd1\x57\x30\x09"
"\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04\x04\x03\x02"
"\x04\xf0\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x49\x00\x30\x46\x02"
"\x21\x00\xa1\x7b\x2a\x1d\x4e\x42\xa8\x68\x6d\x65\x61\x1e\xf5\xfe\x6d\xc6\x99\xae"
"\x7c\x20\x83\x16\xba\xd6\xe5\x0f\xd7\x0d\x7e\x05\xda\xc9\x02\x21\x00\x92\x49\xf3"
"\x0b\x57\xd1\x19\x72\xf2\x75\x5a\xa2\xe0\xb6\xbd\x0f\x07\x38\xd0\xe5\xa2\x4f\xa0"
"\xf3\x87\x61\x82\xd8\xcd\x48\xfc\x57"
;


uint16_t attestation_cert_der_size = sizeof(attestation_cert_der)-1;


uint8_t attestation_key[33] = "\xcd\x67\xaa\x31\x0d\x09\x1e\xd1\x6e\x7e\x98\x92\xaa\x07\x0e\x19\x94\xfc\xd7\x14\xae\x7c\x40\x8f\xb9\x46\xb7\x2e\x5f\xe7\x5d\x30";
uint16_t attestation_key_size = sizeof(attestation_key)-1;


#else
#error "No crypto implementation defined"
#endif