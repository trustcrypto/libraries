/*
 * File:    avrnacl_small/crypto_secretbox/xsalsa20poly1305.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Tue Aug 12 08:23:16 2014 +0200
 * Public Domain
 */

/*
 * Based on tweetnacl.c version 20140427.
 * by Daniel J. Bernstein, Wesley Janssen, Tanja Lange, and Peter Schwabe
 */

#include "avrnacl.h"

int crypto_secretbox_xsalsa20poly1305(
    unsigned char *c,
    const unsigned char *m, crypto_uint16 mlen,
    const unsigned char *n,
    const unsigned char *k
    )
{
  int i;
  if (mlen < 32) return -1;
  crypto_stream_xsalsa20_xor(c,m,mlen,n,k);
  crypto_onetimeauth_poly1305(c + 16,c + 32,mlen - 32,c);
  for(i=0;i<16;i++)
    c[i] = 0;
  return 0;
}

int crypto_secretbox_xsalsa20poly1305_open(
    unsigned char *m,
    const unsigned char *c,crypto_uint16 clen,
    const unsigned char *n,
    const unsigned char *k
    )
{
  int i;
  unsigned char x[32];
  if (clen < 32) return -1;
  crypto_stream_xsalsa20(x,32,n,k);
  if (crypto_onetimeauth_poly1305_verify(c + 16,c + 32,clen - 32,x) != 0) return -1;
  crypto_stream_xsalsa20_xor(m,c,clen,n,k);
  for(i=0;i<32;i++)
    m[i] = 0;
  return 0;
}

