/*
 * File:    avrnacl_small/crypto_core/hsalsa20.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Mon Aug 11 18:51:42 2014 +0200
 * Public Domain
 */

#include "avrnacl.h"

#define ROUNDS 20

extern void avrnacl_calc_rounds(unsigned char *xj, unsigned char *out, int rounds);
extern void avrnacl_init_core(unsigned char *xj, const unsigned char *c, const unsigned char *k, const unsigned char *in);
extern void avrnacl_hsalsa20(unsigned char *out, unsigned char *tmp, const unsigned char *in, const unsigned char *c);

int crypto_core_hsalsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  unsigned char xj[128];
  unsigned char tmp[64];
  avrnacl_init_core(xj, c, k, in);
  avrnacl_calc_rounds(xj, tmp, ROUNDS);
  avrnacl_hsalsa20(out, tmp, in, c);

  return 0;
}
