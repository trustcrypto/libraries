/*
 * File:    avrnacl_small/crypto_onetimeauth/poly1305.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Wed Aug 6 13:39:23 2014 +0200
 * Public Domain
 */

#include "avrnacl.h"
#include "bigint.h"

extern void avrnacl_onetimeauth_loop(unsigned char *r, unsigned char *h, unsigned char *hr, const unsigned char *in, unsigned int inlen);

//freeze reduces numbers < 2^133 to 2^130-5
static void freeze(unsigned char h[17]) {
  unsigned char i;
  unsigned char c;
  unsigned char m[17] = {0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,0x3f};
  unsigned char high_h[17];
  for(i=0;i<17;i++) high_h[i]=0;
  high_h[0]=(h[16]>>2)*5; 
  h[16]=h[16] & 3;
  bigint_add(h,h,high_h,17);
  c = bigint_sub(high_h,h,m,17);
  bigint_cmov(h,high_h,1-c,17);
}

int crypto_onetimeauth_poly1305(
    unsigned char *out,
    const unsigned char *in,crypto_uint16 inlen,
    const unsigned char *k
    )
{
  unsigned char j;
  unsigned char r[17];  
  unsigned char h[17];
  unsigned char hr[34];

  r[0] = k[0];
  r[1] = k[1];
  r[2] = k[2];
  r[3] = k[3] & 15;
  r[4] = k[4] & 252;
  r[5] = k[5];
  r[6] = k[6];
  r[7] = k[7] & 15;
  r[8] = k[8] & 252;
  r[9] = k[9];
  r[10] = k[10];
  r[11] = k[11] & 15;
  r[12] = k[12] & 252;
  r[13] = k[13];
  r[14] = k[14];
  r[15] = k[15] & 15;
  r[16] = 0;

  avrnacl_onetimeauth_loop(r, h, hr, in, inlen);  
  freeze(h);

  for (j = 0;j < 16;++j) hr[j] = k[j + 16];
  hr[16]=0;
  bigint_add(h,h,hr,17);      
  for (j = 0;j < 16;++j) out[j] = h[j];
  return 0;
}

int crypto_onetimeauth_poly1305_verify(
    const unsigned char *h,
    const unsigned char *in,crypto_uint16 inlen,
    const unsigned char *k
    )
{
  unsigned char correct[16];
  crypto_onetimeauth_poly1305(correct,in,inlen,k);
  return crypto_verify_16(h,correct);
}
