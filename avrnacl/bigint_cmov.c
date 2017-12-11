/*
 * File:    avrnacl_small/shared/bigint_cmov.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Fri Aug 1 09:07:46 2014 +0200
 * Public Domain
 */

#include "bigint.h"

void bigint_cmov(unsigned char *r, const unsigned char *x, unsigned char b, unsigned char len)
{
  unsigned char i;
  unsigned char mask = b;
  mask = -mask;
  for(i=0;i<len;i++)
    r[i] ^= mask & (x[i] ^ r[i]);
}

