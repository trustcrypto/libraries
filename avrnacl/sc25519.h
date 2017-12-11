#ifndef SC25519_H
#define SC25519_H

#define sc25519_from32bytes avrnacl_sc25519_from32bytes
#define sc25519_from64bytes avrnacl_sc25519_from64bytes
#define sc25519_to32bytes avrnacl_sc25519_to32bytes
#define sc25519_iszero_vartime avrnacl_sc25519_iszero_vartime
#define sc25519_add avrnacl_sc25519_add
#define sc25519_mul avrnacl_sc25519_mul
#define sc25519_window2 avrnacl_sc25519_window2
#define sc25519_2interleave1 avrnacl_sc25519_2interleave1

typedef struct 
{
  unsigned char v[32];
}
sc25519;

void sc25519_from32bytes(sc25519 *r, const unsigned char x[32]);

void sc25519_from64bytes(sc25519 *r, const unsigned char x[64]);

void sc25519_to32bytes(unsigned char r[32], const sc25519 *x);

int sc25519_iszero_vartime(const sc25519 *x);

void sc25519_add(sc25519 *r, const sc25519 *x, const sc25519 *y);

void sc25519_mul(sc25519 *r, const sc25519 *x, const sc25519 *y);

void sc25519_window2(signed char r[64], const sc25519 *s);

void sc25519_2interleave1(unsigned char r[255], const sc25519 *s1, const sc25519 *s2);

#endif
