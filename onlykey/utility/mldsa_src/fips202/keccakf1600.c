/*
 * Shared Keccak: forward ML-DSA's Keccak-f[1600] to ML-KEM-native's identical
 * implementation, removing the duplicate permutation from flash. The (xor,
 * permute, extract) triple is internally consistent, so this is layout-safe.
 * OnlyKey size optimization.
 */
#include <stdint.h>
#include "keccakf1600.h"

extern void PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600_permute(uint64_t *s);
extern void PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600_xor_bytes(uint64_t *s, const unsigned char *d, unsigned o, unsigned l);
extern void PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600_extract_bytes(uint64_t *s, unsigned char *d, unsigned o, unsigned l);
extern void PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600x4_permute(uint64_t *s);
extern void PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600x4_xor_bytes(uint64_t *s, const unsigned char *d0, const unsigned char *d1, const unsigned char *d2, const unsigned char *d3, unsigned o, unsigned l);
extern void PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600x4_extract_bytes(uint64_t *s, unsigned char *d0, unsigned char *d1, unsigned char *d2, unsigned char *d3, unsigned o, unsigned l);

void mld_keccakf1600_permute(uint64_t *s) { PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600_permute(s); }
void mld_keccakf1600_xor_bytes(uint64_t *s, const unsigned char *d, unsigned o, unsigned l) { PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600_xor_bytes(s, d, o, l); }
void mld_keccakf1600_extract_bytes(uint64_t *s, unsigned char *d, unsigned o, unsigned l) { PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600_extract_bytes(s, d, o, l); }
void mld_keccakf1600x4_permute(uint64_t *s) { PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600x4_permute(s); }
void mld_keccakf1600x4_xor_bytes(uint64_t *s, const unsigned char *d0, const unsigned char *d1, const unsigned char *d2, const unsigned char *d3, unsigned o, unsigned l) { PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600x4_xor_bytes(s, d0,d1,d2,d3, o, l); }
void mld_keccakf1600x4_extract_bytes(uint64_t *s, unsigned char *d0, unsigned char *d1, unsigned char *d2, unsigned char *d3, unsigned o, unsigned l) { PQCP_MLKEM_NATIVE_MLKEM768_keccakf1600x4_extract_bytes(s, d0,d1,d2,d3, o, l); }
