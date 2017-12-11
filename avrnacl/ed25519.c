/*
 * File:    avrnacl_small/crypto_sign/ed25519.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Wed Aug 6 13:19:40 2014 +0200
 * Public Domain
 */

#include "avrnacl.h"
#include "randombytes.h"

#include "ge25519.h"
#include "sc25519.h"

#include <avr/pgmspace.h>

static void get_hram(unsigned char *hram, const unsigned char *sm, const unsigned char *pk, unsigned char *playground, crypto_uint16 smlen)
{
  crypto_uint16 i;

  for (i =  0;i < 32;++i)    playground[i] = sm[i];
  for (i = 32;i < 64;++i)    playground[i] = pk[i-32];
  for (i = 64;i < smlen;++i) playground[i] = sm[i];

  crypto_hash_sha512(hram,playground,smlen);
}


int crypto_sign_ed25519_keypair(
    unsigned char *pk,
    unsigned char *sk
    )
{
  sc25519 scsk;
  ge25519 gepk;
  unsigned char extsk[64];
  unsigned char i;

  randombytes(sk, 32);

  crypto_hash_sha512(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;

  sc25519_from32bytes(&scsk,extsk);

  ge25519_scalarmult_base(&gepk, &scsk);
  ge25519_pack(pk, &gepk);
  for(i=0;i<32;i++)
    sk[32 + i] = pk[i];

  return 0;
}

static void generate_sck(unsigned char *sm, sc25519 *sck, sc25519 *scsk, const unsigned char *m, const unsigned char *sk, unsigned char mlen) 
{
  unsigned char extsk[64];
  const unsigned char *sk_RAM = sk;
  unsigned char hmg[crypto_hash_sha512_BYTES]; //64 bytes
  unsigned char i;
  
  crypto_hash_sha512(extsk, sk_RAM, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;
  
  for(i=0;i<mlen;i++)
    sm[64 + i] = m[i];
  for(i=0;i<32;i++)
    sm[32 + i] = extsk[32+i];
	
  crypto_hash_sha512(hmg, sm+32, mlen+32); // Generate k as h(extsk[32],...,extsk[63],m) 
  sc25519_from64bytes(sck, hmg);
  sc25519_from32bytes(scsk, extsk);
}

static void generate_scs(sc25519 *scs, unsigned char *sm, const unsigned char *pk, unsigned char mlen) 
{
  unsigned char hmg[crypto_hash_sha512_BYTES]; //64 bytes
  get_hram(hmg, sm, pk, sm, mlen+64);
  sc25519_from64bytes(scs, hmg);
}

int crypto_sign_ed25519(
    unsigned char *sm, crypto_uint16 *smlen,
    const unsigned char *m, crypto_uint16 mlen,
    const unsigned char *sk
    )
{	
  crypto_uint16 i;
  sc25519 sck, scs, scsk;
  ge25519 ger;
  
  generate_sck(sm, &sck, &scsk, m, sk, mlen); 
 
  ge25519_scalarmult_base(&ger, &sck);

  ge25519_pack(sm, &ger);

  generate_scs(&scs, sm, sk+32, mlen);
  
  sc25519_mul(&scs, &scs, &scsk);

  sc25519_add(&scs, &scs, &sck);

  sc25519_to32bytes(sm+32,&scs);

  for(i=0;i<mlen;i++)
    sm[i+64] = m[i];
  *smlen = mlen+64;
  
  return 0;
}

static void generate_schram(sc25519 *schram, const unsigned char *sm, const unsigned char *pk, crypto_uint16 smlen, unsigned char *m) {
  unsigned char hram[crypto_hash_sha512_BYTES]; //64 bytes
  get_hram(hram, sm, pk, m, smlen);
  sc25519_from64bytes(schram, hram);
}

int crypto_sign_ed25519_open(
    unsigned char *m,crypto_uint16 *mlen,
    const unsigned char *sm,crypto_uint16 smlen,
    const unsigned char *pk
    )
{
  crypto_uint16 i;
  int ret;
  ge25519 get1, get2;
  sc25519 schram, scs;
  
  if (smlen < crypto_sign_ed25519_BYTES) return -1;
  if (ge25519_unpackneg_vartime(&get1, pk)) return -1;

  generate_schram(&schram, sm, pk, smlen, m);

  sc25519_from32bytes(&scs, sm+32);

  ge25519_double_scalarmult_vartime(&get2, &get1, &schram, &scs); 
  //now reuse variable get1..
  ge25519_pack(get1.x.v, &get2); 

  ret = crypto_verify_32(sm, get1.x.v);

  if (!ret)
  {
    for(i=0;i<smlen-crypto_sign_ed25519_BYTES;i++)
      m[i] = sm[i + crypto_sign_ed25519_BYTES];
    *mlen = smlen-crypto_sign_ed25519_BYTES;
  }
  else
  {
    for(i=0;i<smlen-crypto_sign_ed25519_BYTES;i++)
      m[i] = 0;
    *mlen = (unsigned char) -1;
  }
  return ret;
}
