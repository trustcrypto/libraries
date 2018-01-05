
/* Tim Steiner
 * Copyright (c) 2016 , CryptoTrust LLC.
 * All rights reserved.
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
 *    "This product includes software developed by the OnlyKey Project
 *    (http://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "OnlyKey Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" appear in their names without prior written
 *    permission of the OnlyKey Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OnlyKey Project
 *    (http://www.crp.to/ok)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OnlyKey PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OnlyKey PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef US_VERSION

 
#ifndef OKCRYPTO_H
#define OKCRYPTO_H

#include <Ed25519.h>
#include <Curve25519.h>
#include "rsa.h"
#include "tweetnacl.h"

#ifdef __cplusplus
extern "C"
{
#endif
#define MAX_RSA_KEY_SIZE 512
#define MAX_ECC_KEY_SIZE 32

extern void SIGN (uint8_t *buffer);
extern void GETPUBKEY (uint8_t *buffer);
extern void GENERATE_KEY (uint8_t *buffer);
extern void DERIVEKEY (uint8_t type, uint8_t *data);
extern void GETECCPUBKEY (uint8_t *buffer);
extern void GETRSAPUBKEY (uint8_t *buffer);
extern void DECRYPT (uint8_t *buffer);
extern void ECDH (uint8_t *buffer);
extern void RSADECRYPT(uint8_t *buffer);
extern void RSASIGN (uint8_t *buffer);
extern void ECDSA_EDDSA (uint8_t *buffer);
extern uint8_t Challenge_button1;
extern uint8_t Challenge_button2;
extern uint8_t Challenge_button3;
extern uint8_t CRYPTO_AUTH;
extern int rsa_decrypt (unsigned int *olen, const uint8_t *in, uint8_t *out);
extern int rsa_sign (int mlen, const uint8_t *msg, uint8_t *out);
extern void rsa_getpub (uint8_t type);
extern bool is_bit_set(unsigned char byte, int index);
extern int mbedtls_rand( void *rng_state, unsigned char *output, size_t len);
extern int RNG2(uint8_t *dest, unsigned size);
extern int rsa_encrypt (int len, const uint8_t *in, uint8_t *out);
extern int shared_secret (uint8_t *ephemeral_pub, uint8_t *secret);
extern void aes_crypto_box (uint8_t *buffer, int len, bool open);

#ifdef __cplusplus
}
#endif
#endif
#endif
