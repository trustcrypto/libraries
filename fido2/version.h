#ifndef _VERSION_H_
#define _VERSION_H_

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef SOLO_VERSION_MAJ

#define SOLO_VERSION_MAJ    2
#define SOLO_VERSION_MIN    4
#define SOLO_VERSION_PATCH    2

#endif

#define __STR_HELPER(x) #x
#define __STR(x) __STR_HELPER(x)

#ifndef SOLO_VERSION
#define SOLO_VERSION     __STR(SOLO_VERSION_MAJ) "." __STR(SOLO_VERSION_MIN) "." __STR(SOLO_VERSION_PATCH)
#endif

#ifdef __cplusplus
}
#endif

#endif
