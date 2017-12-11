/*
 * File:    avrnacl_small/crypto_dh/curve25519.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Mon Aug 11 11:45:26 2014 +0200
 * Public Domain
 */

#include "avrnacl.h"

int crypto_dh_curve25519_keypair(
    unsigned char *pk,
    unsigned char *sk
    )
{
  RNG2(sk,crypto_scalarmult_curve25519_SCALARBYTES);
  crypto_scalarmult_curve25519_base(pk,sk);
  return 0;
}

int crypto_dh_curve25519(
    unsigned char *s,
    const unsigned char *pk,
    const unsigned char *sk
    )
{
  crypto_scalarmult_curve25519(s,sk,pk);
  return 0;
}
