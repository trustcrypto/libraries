/*
 * File:    avrnacl_small/shared/fe25519.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Fri Aug 1 09:07:46 2014 +0200
 * Public Domain
 */

#include <stdio.h>

#include "bigint.h"
#include "fe25519.h"

/* m = 2^255-19 = 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed */
static const unsigned char ECCParam_p[32] = {0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};

/* m = 2^255-19 = 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed */
// --------------------------- modulo-arithmetic operations -----------------------------

static unsigned char equal(unsigned char a, unsigned char b)
{
  unsigned char x = a ^ b; /* 0: yes; >1: no */
  x -= 1; /* 255: yes; 0..254: no */
  x >>= 7; /* 1: yes; 0: no */
  return x;
}

/* reduction modulo 2^255-19 */
void fe25519_freeze(fe25519 *r)
{
  unsigned char c;
  fe25519 rt;
  c = bigint_sub(rt.v, r->v, ECCParam_p, 32);
  fe25519_cmov(r,&rt,1-c);
  c = bigint_sub(rt.v, r->v, ECCParam_p, 32);
  fe25519_cmov(r,&rt,1-c);
}

void fe25519_setzero(fe25519 *r)
{
  unsigned char i;
  for(i=0;i<32;i++)
    r->v[i]=0;
}

void fe25519_setone(fe25519 *r)
{
  unsigned char i;
  r->v[0] = 1;
  for(i=1;i<32;i++)
    r->v[i]=0;
}

unsigned char fe25519_getparity(const fe25519 *x)
{
  fe25519 t = *x;
  fe25519_freeze(&t);
  return t.v[0] & 1;
}

int fe25519_iszero(const fe25519 *x)
{
  unsigned char i;
  fe25519 t = *x;
  fe25519_freeze(&t);
  int r = equal(t.v[0],0);
  for(i=1;i<32;i++)
    r &= equal(t.v[i],0);
  return r;
}

int fe25519_iseq_vartime(const fe25519 *x, const fe25519 *y)
{
  fe25519 t1 = *x;
  fe25519 t2 = *y;
  fe25519_freeze(&t1);
  fe25519_freeze(&t2);
  unsigned char i;
  for(i=0;i<32;i++)
    if(t1.v[i] != t2.v[i]) return 0;
  return 1;
}

void fe25519_neg(fe25519 *r, const fe25519 *x)
{
  fe25519 t;
  fe25519_setzero(&t);
  fe25519_sub(r, &t, x);
}

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b)
{
  unsigned char i;
  unsigned long mask = b;
  mask = -mask;
  for(i=0;i<32;i++)
    r->v[i] ^= mask & (x->v[i] ^ r->v[i]);
}

void fe25519_unpack(fe25519 *r, const unsigned char x[32])
{
  unsigned char i;
  for(i=0;i<32;i++)
    r->v[i] = x[i];
  r->v[31] &= 127;
}

/* Assumes input x being reduced below 2^255 */
void fe25519_pack(unsigned char r[32], const fe25519 *x)
{
  unsigned char i;
  fe25519 y = *x;
  fe25519_freeze(&y);
  for(i=0;i<32;i++)
    r[i] = y.v[i];
}

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
  unsigned char t[64];
  bigint_mul256(t,x->v,y->v);
  fe25519_red(r,t);
}


void fe25519_square(fe25519 *r, const fe25519 *x)
{
  fe25519_mul(r,x,x);
}


