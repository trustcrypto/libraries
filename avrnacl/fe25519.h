#ifndef FE25519_H
#define FE25519_H

#define fe25519_freeze avrnacl_fe25519_freeze
#define fe25519_unpack avrnacl_fe25519_unpack
#define fe25519_pack avrnacl_fe25519_pack
#define fe25519_iszero avrnacl_fe25519_iszero
#define fe25519_iseq_vartime avrnacl_fe25519_iseq_vartime
#define fe25519_cmov avrnacl_fe25519_cmov
#define fe25519_setone avrnacl_fe25519_setone
#define fe25519_setzero avrnacl_fe25519_setzero
#define fe25519_neg avrnacl_fe25519_neg
#define fe25519_getparity avrnacl_fe25519_getparity
#define fe25519_mul avrnacl_fe25519_mul
#define fe25519_square avrnacl_fe25519_square
#define fe25519_invert avrnacl_fe25519_invert
#define fe25519_pow2523 avrnacl_fe25519_pow2523
#define fe25519_add avrnacl_fe25519_add
#define fe25519_sub avrnacl_fe25519_sub
#define fe25519_red avrnacl_fe25519_red

typedef struct
{
  unsigned char v[32];
}
fe25519;

void fe25519_freeze(fe25519 *r);

void fe25519_unpack(fe25519 *r, const unsigned char x[32]);

void fe25519_pack(unsigned char r[32], const fe25519 *x);

int fe25519_iszero(const fe25519 *x);

int fe25519_iseq_vartime(const fe25519 *x, const fe25519 *y);

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b);

void fe25519_setone(fe25519 *r);

void fe25519_setzero(fe25519 *r);

void fe25519_neg(fe25519 *r, const fe25519 *x);

unsigned char fe25519_getparity(const fe25519 *x);

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y);

void fe25519_square(fe25519 *r, const fe25519 *x);

void fe25519_invert(fe25519 *r, const fe25519 *x);

void fe25519_pow2523(fe25519 *r, const fe25519 *x);

//Assembler Routines
extern void fe25519_add(fe25519 *r, const fe25519 *x, const fe25519 *y);

extern void fe25519_sub(fe25519 *r, const fe25519 *x, const fe25519 *y);

extern void fe25519_red(fe25519 *r, unsigned char *C);


#endif
