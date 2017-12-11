/*
 * File:    avrnacl_small/crypto_core/salsa20.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Tue Aug 5 08:32:01 2014 +0200
 * Public Domain
 */

#include "avrnacl.h"

#define ROUNDS 20

extern void avrnacl_calc_rounds(unsigned char *xj, unsigned char *out, int rounds);
extern void avrnacl_init_core(unsigned char *xj, const unsigned char *c, const unsigned char *k, const unsigned char *in);

int crypto_core_salsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  unsigned char xj[128];
  avrnacl_init_core(xj, c, k, in);      
  avrnacl_calc_rounds(xj, out, ROUNDS); 
  return 0;
}
