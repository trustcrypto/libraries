/*
 * File:    avrnacl_small/crypto_sign/sc25519.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Tue Aug 5 08:32:01 2014 +0200
 * Public Domain
 */

#include "bigint.h"
#include "sc25519.h"

/*Arithmetic modulo the group order m = 2^252 +  27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989 */

static const unsigned char m[32] = {0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/* Barrett reduction algorithm. Reduces an integer according to the modulus 2^252+.... See Hankerson et al. [p. 36] for more details. */
static void barrett_reduction(unsigned char* r, unsigned char* a) 
{
  unsigned char q1[66], q2[66], n1[33];
  unsigned char c;
  unsigned char q3[33] = {0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21,
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F};
  unsigned char i;
  for (i=0; i<32; i++) n1[i] = m[i];
  n1[32] = 0;
  bigint_mul(q2, a+31, q3, 33);
  bigint_mul(q1, q2+33, n1, 33);

  /* m has only 253 bits, so q2 fits into 32 bytes */
  bigint_sub(r, a, q1, 32);

  c = bigint_sub(q2, r, m, 32);
  bigint_cmov(r, q2, 1-c, 32);
  c = bigint_sub(q2, r, m, 32);
  bigint_cmov(r, q2, 1-c, 32);
}

void sc25519_from32bytes(sc25519 *r, const unsigned char x[32])
{
  unsigned char i;
  unsigned char t[64];
  for(i=0;i<32;i++) 
    t[i] = x[i];
  for(i=32;i<64;++i) 
    t[i] = 0;
  barrett_reduction(r->v, t);
}

void sc25519_from64bytes(sc25519 *r, const unsigned char x[64])
{
  unsigned char i;
  unsigned char t[64];
  for(i=0;i<64;i++) 
    t[i] = x[i];
  barrett_reduction(r->v, t);
}

void sc25519_to32bytes(unsigned char r[32], const sc25519 *x)
{
  unsigned char i;
  for(i=0;i<32;i++) 
    r[i] = x->v[i];
}

void sc25519_add(sc25519 *r, const sc25519 *x, const sc25519 *y)
{
  unsigned char c;
  unsigned char t[32];
  bigint_add(r->v,x->v,y->v,32);
  c = bigint_sub(t,r->v,m,32);
  bigint_cmov(r->v,t,1-c,32);
}

void sc25519_mul(sc25519 *r, const sc25519 *x, const sc25519 *y)
{
  unsigned char t[64];
  bigint_mul256(t, x->v, y->v);
  barrett_reduction(r->v, t);
}

void sc25519_window2(signed char r[128], const sc25519 *s)
{
  char carry;
  unsigned char i;
  for(i=0;i<32;i++)
  {
    r[4*i]   = (s->v[i] & 3);
    r[4*i+1] = (s->v[i] >> 2) & 3;
    r[4*i+2] = (s->v[i] >> 4) & 3;
    r[4*i+3] = (s->v[i] >> 6) & 3;
  }

  /* Making it signed */
  carry = 0;
  for(i=0;i<127;i++)
  {
    r[i] += carry;
    r[i+1] += r[i] >> 2;
    r[i] &= 3;
    carry = r[i] >> 1;
    r[i] -= carry << 2;
  }
  r[127] += carry;
}




void sc25519_2interleave1(unsigned char r[255], const sc25519 *s1, const sc25519 *s2)
{
  unsigned char i;
  for(i=0;i<31;i++)
  {
    r[8*i]   = ( s1->v[i]       & 1) ^ (( s2->v[i]       & 1) << 1);
    r[8*i+1] = ((s1->v[i] >> 1) & 1) ^ (((s2->v[i] >> 1) & 1) << 1);
    r[8*i+2] = ((s1->v[i] >> 2) & 1) ^ (((s2->v[i] >> 2) & 1) << 1);
    r[8*i+3] = ((s1->v[i] >> 3) & 1) ^ (((s2->v[i] >> 3) & 1) << 1);
    r[8*i+4] = ((s1->v[i] >> 4) & 1) ^ (((s2->v[i] >> 4) & 1) << 1);
    r[8*i+5] = ((s1->v[i] >> 5) & 1) ^ (((s2->v[i] >> 5) & 1) << 1);
    r[8*i+6] = ((s1->v[i] >> 6) & 1) ^ (((s2->v[i] >> 6) & 1) << 1);
    r[8*i+7] = ((s1->v[i] >> 7) & 1) ^ (((s2->v[i] >> 7) & 1) << 1);
  }
  r[248] = ( s1->v[31]       & 1) ^ (( s2->v[31]       & 1) << 1);
  r[249] = ((s1->v[31] >> 1) & 1) ^ (((s2->v[31] >> 1) & 1) << 1);
  r[250] = ((s1->v[31] >> 2) & 1) ^ (((s2->v[31] >> 2) & 1) << 1);
  r[251] = ((s1->v[31] >> 3) & 1) ^ (((s2->v[31] >> 3) & 1) << 1);
  r[252] = ((s1->v[31] >> 4) & 1) ^ (((s2->v[31] >> 4) & 1) << 1);
  r[253] = ((s1->v[31] >> 5) & 1) ^ (((s2->v[31] >> 5) & 1) << 1);
  r[254] = ((s1->v[31] >> 6) & 1) ^ (((s2->v[31] >> 6) & 1) << 1);
}
