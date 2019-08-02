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

    // Check if klen, it might be possible for key to
    // have a 1 or 0 as first byte
    if (key == CRYPTO_MASTER_KEY && klen == 0)
    {
        key = master_secret;
        klen = sizeof(master_secret);
        //Serial.println("using master secret");
        //byteprint(master_secret, 64);
    }
    // Check if klen, it might be possible for key to
    // have a 1 or 0 as first byte
    else if (key == CRYPTO_TRANSPORT_KEY && klen == 0)
    {
        key = transport_secret;
        klen = 32;
        //Serial.println("using transport secret");
        //byteprint(transport_secret, 32);
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
    unsigned int i;
    crypto_sha256_final(hmac);
    memset(buf, 0, sizeof(buf));
    // Check if klen, it might be possible for key to
    // have a 1 or 0 as first byte
    if (key == CRYPTO_MASTER_KEY && klen == 0)
    {
        key = master_secret;
        klen = sizeof(master_secret);
    }
    // TODO
    // Why is this not checking if transport key?
    // buf is just full of zeros


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
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
  if ( uECC_sign_deterministic(_signing_key, data, len, &ectx.uECC, sig, _es256_curve)== 0)
  //if ( uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0)
    {
        printf2(TAG_ERR,"error, uECC failed\n");
        exit(1);
    }
    //Serial.print("Sig");
    //byteprint(sig, 64);
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
    //Serial.print("Sig");
    //byteprint(sig, 64);
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
	//Serial.println("crypto_ecc256_derive_public_key start");
    memset(pubkey,0,sizeof(pubkey));
	//const struct uECC_Curve_t * curve = uECC_secp256r1();
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
	  //memset(pubkey, 0, sizeof(pubkey));
      //memset(privkey, 0, sizeof(privkey));
      //uECC_make_key(pubkey, privkey, _es256_curve);

      //Serial.println(F("Public K"));
	  //byteprint(pubkey, sizeof(pubkey));
      //Serial.println();
      //Serial.println(F("Private K"));
	  //byteprint(privkey, sizeof(privkey));
      //Serial.println();

	//Serial.println("crypto_ecc256_derive_public_key finish");
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
"\x30\x82\x02\xaa\x30\x82\x02\x50\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x7b\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x08\x0c\x0e\x4e\x6f\x72\x74\x68\x20"
"\x43\x61\x72\x6f\x6c\x69\x6e\x61\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0b\x43"
"\x72\x79\x70\x74\x6f\x54\x72\x75\x73\x74\x31\x10\x30\x0e\x06\x03\x55\x04\x0b\x0c"
"\x07\x52\x6f\x6f\x74\x20\x43\x41\x31\x0f\x30\x0d\x06\x03\x55\x04\x03\x0c\x06\x63"
"\x72\x70\x2e\x74\x6f\x31\x1a\x30\x18\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01"
"\x16\x0b\x69\x6e\x66\x6f\x40\x63\x72\x70\x2e\x74\x6f\x30\x20\x17\x0d\x31\x39\x30"
"\x37\x33\x30\x32\x31\x30\x30\x35\x36\x5a\x18\x0f\x32\x30\x36\x39\x30\x37\x31\x37"
"\x32\x31\x30\x30\x35\x36\x5a\x30\x69\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02"
"\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x08\x0c\x0e\x4e\x6f\x72\x74\x68\x20\x43"
"\x61\x72\x6f\x6c\x69\x6e\x61\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0b\x43\x72"
"\x79\x70\x74\x6f\x54\x72\x75\x73\x74\x31\x0f\x30\x0d\x06\x03\x55\x04\x03\x0c\x06"
"\x63\x72\x70\x2e\x74\x6f\x31\x1a\x30\x18\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09"
"\x01\x16\x0b\x69\x6e\x66\x6f\x40\x63\x72\x70\x2e\x74\x6f\x30\x59\x30\x13\x06\x07"
"\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
"\x04\xcb\xb6\x8d\x13\x48\x7f\x45\xf8\x3e\xa3\x0f\xa7\x36\xf1\x16\x9d\x87\xf5\x27"
"\x4b\x81\x71\xff\x68\xfe\xe2\xc7\x76\x22\xc1\x99\xd3\x17\xc0\xce\x8d\xdc\xa3\x9f"
"\x36\x8a\x35\xa2\xaf\x30\xad\x89\x17\x24\xe5\x1b\x59\x27\x53\xd1\x60\xf8\xb3\x4a"
"\xc7\xa5\x1e\xf8\xf0\xa3\x81\xd4\x30\x81\xd1\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16"
"\x04\x14\x35\xfc\x6b\x84\x33\xdb\xfc\xda\xf8\x49\x5a\xd1\xee\x1b\x3b\xa1\x3a\xa1"
"\xb2\x87\x30\x81\x97\x06\x03\x55\x1d\x23\x04\x81\x8f\x30\x81\x8c\xa1\x7f\xa4\x7d"
"\x30\x7b\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x17\x30\x15\x06"
"\x03\x55\x04\x08\x0c\x0e\x4e\x6f\x72\x74\x68\x20\x43\x61\x72\x6f\x6c\x69\x6e\x61"
"\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0b\x43\x72\x79\x70\x74\x6f\x54\x72\x75"
"\x73\x74\x31\x10\x30\x0e\x06\x03\x55\x04\x0b\x0c\x07\x52\x6f\x6f\x74\x20\x43\x41"
"\x31\x0f\x30\x0d\x06\x03\x55\x04\x03\x0c\x06\x63\x72\x70\x2e\x74\x6f\x31\x1a\x30"
"\x18\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x0b\x69\x6e\x66\x6f\x40\x63"
"\x72\x70\x2e\x74\x6f\x82\x09\x00\xb1\x14\xdc\x47\x30\xbe\x98\x80\x30\x09\x06\x03"
"\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04\x04\x03\x02\x04\xf0"
"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00\x30\x45\x02\x20\x57"
"\x91\x0b\xa2\x8b\xc5\xed\x5d\x96\xdf\x0e\x8a\xfd\x33\xf4\x8c\xc7\xbc\x37\x30\x9f"
"\x04\x3b\x60\xed\x5c\xcb\x2c\x88\x4e\x39\x76\x02\x21\x00\xe4\x52\xa8\x05\x15\x45"
"\x52\xfa\x31\x94\x5d\xa4\xc7\x9a\x15\x81\xd3\xd0\x76\x68\xbd\xee\x1b\x24\x76\xee"
"\xcc\xe0\x02\xfc\x8e\x9e"
;

// If changing attestation cert change to offset size add -1
uint16_t attestation_cert_der_size = sizeof(attestation_cert_der)-82;

uint8_t attestation_key[33] = "\xfc\xf5\x1b\x23\x7b\xfc\x18\x9f\xd5\xf7\x53\xf3\x0c\xf9\x41\xba\x90\x46\x7e\x0e\x65\xb6\x75\xd6\x56\xe6\x6c\x3b\x86\xe3\x01\xe8";

//uint8_t attestation_key[33] = "\x1e\xfd\xda\x08\xee\x26\x06\x0e\xf1\xf9\x25\xfe\x57\x1d\xa0\x0d\xa9\x4b\xe8\xce\x29\x79\xb2\x79\xdf\x33\xa9\xfb\x6a\xe8\xcc\x90";

uint16_t attestation_key_size = sizeof(attestation_key)-1;


#else
#error "No crypto implementation defined"
#endif
