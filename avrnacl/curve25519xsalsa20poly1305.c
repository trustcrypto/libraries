/*
 * File:    avrnacl_small/crypto_box/curve25519xsalsa20poly1305.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Wed Aug 6 13:19:40 2014 +0200
 * Public Domain
 */

#include "avrnacl.h"
#include "randombytes.h"

static const unsigned char _0[16];
static const unsigned char sigma[16] = "expand 32-byte k";


int crypto_box_curve25519xsalsa20poly1305_keypair(
    unsigned char *pk,
    unsigned char *sk
    )
{
  randombytes(sk,32);
  return crypto_scalarmult_curve25519_base(pk,sk);
}

int crypto_box_curve25519xsalsa20poly1305_beforenm(
    unsigned char *k,
    const unsigned char *pk,
    const unsigned char *sk
    )
{
  unsigned char s[32];
  crypto_scalarmult_curve25519(s,sk,pk);
  return crypto_core_hsalsa20(k,_0,s,sigma);
}

int crypto_box_curve25519xsalsa20poly1305_afternm(
    unsigned char *c,
    const unsigned char *m,crypto_uint16 mlen,
    const unsigned char *n,
    const unsigned char *k
    )
{
  return crypto_secretbox_xsalsa20poly1305(c,m,mlen,n,k);
}

int crypto_box_curve25519xsalsa20poly1305_open_afternm(
    unsigned char *m,
    const unsigned char *c,crypto_uint16 clen,
    const unsigned char *n,
    const unsigned char *k
    )
{
  return crypto_secretbox_xsalsa20poly1305_open(m,c,clen,n,k);
}

int crypto_box_curve25519xsalsa20poly1305(
    unsigned char *c,
    const unsigned char *m,crypto_uint16 mlen,
    const unsigned char *n,
    const unsigned char *pk,
    const unsigned char *sk
    )
{
  unsigned char k[32];
  crypto_box_curve25519xsalsa20poly1305_beforenm(k,pk,sk);
  return crypto_box_curve25519xsalsa20poly1305_afternm(c,m,mlen,n,k);
}

int crypto_box_curve25519xsalsa20poly1305_open(
    unsigned char *m,
    const unsigned char *c,crypto_uint16 clen,
    const unsigned char *n,
    const unsigned char *pk,
    const unsigned char *sk
    )
{
  unsigned char k[32];
  crypto_box_curve25519xsalsa20poly1305_beforenm(k,pk,sk);
  return crypto_box_curve25519xsalsa20poly1305_open_afternm(m,c,clen,n,k);
}
