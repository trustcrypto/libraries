/*
 * File:    avrnacl_small/crypto_stream/xsalsa20.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Wed Aug 6 13:39:23 2014 +0200
 * Public Domain
 */

#include "avrnacl.h"

static const unsigned char sigma[16] = "expand 32-byte k";

int crypto_stream_xsalsa20_xor(
    unsigned char *c,
    const unsigned char *m,crypto_uint16 mlen,
    const unsigned char *n,
    const unsigned char *k
    )
{
  unsigned char s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20_xor(c,m,mlen,n+16,s);
}

int crypto_stream_xsalsa20(
    unsigned char *c,crypto_uint16 clen,
    const unsigned char *n,
    const unsigned char *k
    )
{
  unsigned char s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,clen,n+16,s);
}

