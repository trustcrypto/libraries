#ifndef BIGINT_H
#define BIGINT_H

#define bigint_add avrnacl_bigint_add
#define bigint_xor avrnacl_bigint_xor
#define bigint_add64 avrnacl_bigint_add64
#define bigint_and64 avrnacl_bigint_and64
#define bigint_xor64 avrnacl_bigint_xor64
#define bigint_not64 avrnacl_bigint_not64
#define bigint_rol64 avrnacl_bigint_rol64
#define bigint_ror64 avrnacl_bigint_ror64
#define bigint_shr64 avrnacl_bigint_shr64
#define bigint_sub avrnacl_bigint_sub
#define bigint_mul avrnacl_bigint_mul
#define bigint_mul128 avrnacl_bigint_mul128
#define bigint_mul136 avrnacl_bigint_mul136
#define bigint_mul256 avrnacl_bigint_mul256
#define bigint_cmov avrnacl_bigint_cmov

/* Arithmetic on big integers represented as arrays of unsigned char */

extern char bigint_add(unsigned char* r, const unsigned char* a, const unsigned char* b, int length);

extern char bigint_xor(unsigned char* r, const unsigned char* a, const unsigned char* b, int length);

extern char bigint_add64(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern char bigint_and64(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern char bigint_xor64(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern char bigint_not64(unsigned char* r, const unsigned char* a);

extern char bigint_rol64(unsigned char* r, unsigned char length);

extern char bigint_ror64(unsigned char* r, unsigned char length);

extern char bigint_shr64(unsigned char* r, unsigned char length);

extern char bigint_sub(unsigned char* r, const unsigned char* a, const unsigned char* b, int length);

extern void bigint_mul(unsigned char* r, const unsigned char* a, const unsigned char* b, int length);

extern void bigint_mul128(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern void bigint_mul136(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern void bigint_mul256(unsigned char* r, const unsigned char* a, const unsigned char* b);

void bigint_cmov(unsigned char *r, const unsigned char *x, unsigned char b, unsigned char len);

#endif
