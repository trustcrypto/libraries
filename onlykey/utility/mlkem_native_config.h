/*
 * mlkem-native configuration for OnlyKey (NXP MK20DX256, Cortex-M4)
 * ML-KEM-768 (FIPS 203), C-only portable backend
 *
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLK_CONFIG_H
#define MLK_CONFIG_H

/* ML-KEM-768 (NIST Level 3) */
#ifndef MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_PARAMETER_SET 768
#endif

/* Namespace prefix for symbols */
#if !defined(MLK_CONFIG_NAMESPACE_PREFIX)
#define MLK_CONFIG_NAMESPACE_PREFIX MLK_DEFAULT_NAMESPACE_PREFIX
#endif

/* No native assembly backends — Cortex-M4 not supported by existing
 * AArch64/x86_64/RVV/Helium backends. Pure portable C. */

/* Build-only options */
#if defined(MLK_BUILD_INTERNAL)

/*
 * Custom randombytes wrapper
 *
 * OnlyKey's existing randombytes has signature:
 *   void randombytes(unsigned char *x, unsigned long long xlen)
 *
 * mlkem-native expects:
 *   int mlk_randombytes(uint8_t *out, size_t outlen) — returns 0 on success
 *
 * We bridge with a custom wrapper. Implement onlykey_mlkem_randombytes()
 * in okcrypto.cpp using your preferred entropy source.
 */
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__)
#include <stdint.h>
#include <stddef.h>
#include "src/sys.h"

extern int onlykey_mlkem_randombytes(uint8_t *out, size_t outlen);

static MLK_INLINE int mlk_randombytes(uint8_t *out, size_t outlen)
{
    return onlykey_mlkem_randombytes(out, outlen);
}
#endif /* !__ASSEMBLER__ */

#endif /* MLK_BUILD_INTERNAL */

/* Default namespace */
#if MLK_CONFIG_PARAMETER_SET == 512
#define MLK_DEFAULT_NAMESPACE_PREFIX PQCP_MLKEM_NATIVE_MLKEM512
#elif MLK_CONFIG_PARAMETER_SET == 768
#define MLK_DEFAULT_NAMESPACE_PREFIX PQCP_MLKEM_NATIVE_MLKEM768
#elif MLK_CONFIG_PARAMETER_SET == 1024
#define MLK_DEFAULT_NAMESPACE_PREFIX PQCP_MLKEM_NATIVE_MLKEM1024
#endif

#endif /* !MLK_CONFIG_H */
