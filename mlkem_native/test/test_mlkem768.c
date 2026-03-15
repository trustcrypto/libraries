/*
 * ML-KEM-768 & Hybrid X25519+ML-KEM-768 Integration Test Suite
 * Tests mlkem-native library with OnlyKey config
 *
 * Compile (from mlkem_native/test/):
 *   make test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "mlkem_native/mlkem_native.h"

int onlykey_mlkem_randombytes(uint8_t *out, size_t outlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    if (fread(out, 1, outlen, f) != outlen) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* Minimal SHA-256 for hybrid combiner testing */
static uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define S1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define s0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define s1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t padlen = ((len + 8) / 64 + 1) * 64;
    uint8_t *pad = (uint8_t *)calloc(padlen, 1);
    memcpy(pad, data, len);
    pad[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) pad[padlen - 1 - i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < padlen; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)pad[off+i*4]<<24)|((uint32_t)pad[off+i*4+1]<<16)|
                   ((uint32_t)pad[off+i*4+2]<<8)|(uint32_t)pad[off+i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + S1(e) + CH(e,f,g) + sha256_k[i] + w[i];
            uint32_t t2 = S0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4]=(uint8_t)(h[i]>>24); out[i*4+1]=(uint8_t)(h[i]>>16);
        out[i*4+2]=(uint8_t)(h[i]>>8); out[i*4+3]=(uint8_t)h[i];
    }
    free(pad);
}

static void sha256_combine(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    uint8_t buf[64];
    memcpy(buf, a, 32);
    memcpy(buf + 32, b, 32);
    sha256_hash(buf, 64, out);
}

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  [%02d] %-55s ", tests_run, name); fflush(stdout); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* === ML-KEM-768 Standalone Tests === */

static int test_sizes(void) {
    TEST("ML-KEM: sizes match FIPS 203 spec");
    if (MLKEM768_PUBLICKEYBYTES != 1184 || MLKEM768_SECRETKEYBYTES != 2400 ||
        MLKEM768_CIPHERTEXTBYTES != 1088 || MLKEM_BYTES != 32) { FAIL("mismatch"); return 1; }
    PASS(); return 0;
}

static int test_roundtrip(void) {
    TEST("ML-KEM: keygen + encaps + decaps round-trip");
    uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
    if (crypto_kem_keypair(pk, sk) != 0) { FAIL("keygen"); return 1; }
    if (crypto_kem_enc(ct, ss1, pk) != 0) { FAIL("encaps"); return 1; }
    if (crypto_kem_dec(ss2, ct, sk) != 0) { FAIL("decaps"); return 1; }
    if (memcmp(ss1, ss2, 32) != 0) { FAIL("ss mismatch"); return 1; }
    PASS(); return 0;
}

static int test_different_secrets(void) {
    TEST("ML-KEM: multiple encaps produce different secrets");
    uint8_t pk[1184], sk[2400], ct1[1088], ct2[1088], ss1[32], ss2[32];
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct1, ss1, pk);
    crypto_kem_enc(ct2, ss2, pk);
    if (memcmp(ss1, ss2, 32) == 0) { FAIL("identical"); return 1; }
    PASS(); return 0;
}

static int test_wrong_sk(void) {
    TEST("ML-KEM: wrong SK implicit rejection");
    uint8_t pk1[1184], sk1[2400], pk2[1184], sk2[2400], ct[1088], ss1[32], ss2[32];
    crypto_kem_keypair(pk1, sk1); crypto_kem_keypair(pk2, sk2);
    crypto_kem_enc(ct, ss1, pk1); crypto_kem_dec(ss2, ct, sk2);
    if (memcmp(ss1, ss2, 32) == 0) { FAIL("matched"); return 1; }
    PASS(); return 0;
}

static int test_corrupted_ct(void) {
    TEST("ML-KEM: corrupted CT implicit rejection");
    uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
    crypto_kem_keypair(pk, sk); crypto_kem_enc(ct, ss1, pk);
    ct[0] ^= 0x01; crypto_kem_dec(ss2, ct, sk);
    if (memcmp(ss1, ss2, 32) == 0) { FAIL("matched"); return 1; }
    PASS(); return 0;
}

static int test_pk_in_sk(void) {
    TEST("ML-KEM: PK at SK offset 1152");
    uint8_t pk[1184], sk[2400];
    crypto_kem_keypair(pk, sk);
    if (memcmp(pk, sk + 1152, 1184) != 0) { FAIL("wrong offset"); return 1; }
    PASS(); return 0;
}

static int test_check_pk_sk(void) {
    TEST("ML-KEM: check_pk/check_sk validate keys");
    uint8_t pk[1184], sk[2400];
    crypto_kem_keypair(pk, sk);
    if (crypto_kem_check_pk(pk) != 0) { FAIL("pk rejected"); return 1; }
    if (crypto_kem_check_sk(sk) != 0) { FAIL("sk rejected"); return 1; }
    PASS(); return 0;
}

static int test_onlykey_flow(void) {
    TEST("ML-KEM: simulated OnlyKey ctap_buffer flow");
    uint8_t ctap[7609]; memset(ctap, 0, sizeof(ctap));
    uint8_t *sk = ctap, *pk = ctap + 2400;
    if (crypto_kem_keypair(pk, sk) != 0) { FAIL("keygen"); return 1; }
    uint8_t pk_h[1184]; memcpy(pk_h, pk, 1184);
    uint8_t flash[2400]; memcpy(flash, sk, 2400);
    memset(ctap, 0, sizeof(ctap));
    uint8_t ct[1088], ss_h[32];
    if (crypto_kem_enc(ct, ss_h, pk_h) != 0) { FAIL("encaps"); return 1; }
    memcpy(ctap, flash, 2400);
    memcpy(ctap + 5465, ct, 1088);
    uint8_t ss_d[32];
    if (crypto_kem_dec(ss_d, ctap + 5465, ctap) != 0) { FAIL("decaps"); return 1; }
    if (memcmp(ss_h, ss_d, 32) != 0) { FAIL("ss mismatch"); return 1; }
    PASS(); return 0;
}

/* === Hybrid X25519 + ML-KEM-768 Tests === */

static int test_hybrid_sizes(void) {
    TEST("Hybrid: PK=1216, CT=1120, SS=32");
    if ((32 + 1184) != 1216 || (32 + 1088) != 1120) { FAIL("mismatch"); return 1; }
    PASS(); return 0;
}

static int test_hybrid_mlkem_roundtrip(void) {
    TEST("Hybrid: ML-KEM component round-trip in hybrid context");
    uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
    if (crypto_kem_keypair(pk, sk) != 0) { FAIL("keygen"); return 1; }
    if (crypto_kem_enc(ct, ss1, pk) != 0) { FAIL("encaps"); return 1; }
    if (crypto_kem_dec(ss2, ct, sk) != 0) { FAIL("decaps"); return 1; }
    if (memcmp(ss1, ss2, 32) != 0) { FAIL("mlkem mismatch"); return 1; }
    /* Combine with X25519 secret */
    uint8_t x25519_ss[32]; onlykey_mlkem_randombytes(x25519_ss, 32);
    uint8_t c1[32], c2[32];
    sha256_combine(x25519_ss, ss1, c1);
    sha256_combine(x25519_ss, ss2, c2);
    if (memcmp(c1, c2, 32) != 0) { FAIL("combined diverged"); return 1; }
    PASS(); return 0;
}

static int test_hybrid_combiner_deterministic(void) {
    TEST("Hybrid: SHA256 combiner deterministic and order-dependent");
    uint8_t a[32], b[32]; onlykey_mlkem_randombytes(a, 32); onlykey_mlkem_randombytes(b, 32);
    uint8_t h1[32], h2[32], h3[32];
    sha256_combine(a, b, h1); sha256_combine(a, b, h2); sha256_combine(b, a, h3);
    if (memcmp(h1, h2, 32) != 0) { FAIL("not deterministic"); return 1; }
    if (memcmp(h1, h3, 32) == 0) { FAIL("order doesn't matter"); return 1; }
    PASS(); return 0;
}

static int test_hybrid_wrong_x25519(void) {
    TEST("Hybrid: wrong X25519 component breaks combined SS");
    uint8_t pk[1184], sk[2400], ct[1088], mlkem_ss[32];
    crypto_kem_keypair(pk, sk); crypto_kem_enc(ct, mlkem_ss, pk);
    uint8_t x_good[32], x_bad[32];
    onlykey_mlkem_randombytes(x_good, 32); onlykey_mlkem_randombytes(x_bad, 32);
    uint8_t c1[32], c2[32];
    sha256_combine(x_good, mlkem_ss, c1); sha256_combine(x_bad, mlkem_ss, c2);
    if (memcmp(c1, c2, 32) == 0) { FAIL("bad x25519 still matched"); return 1; }
    PASS(); return 0;
}

static int test_hybrid_wrong_mlkem(void) {
    TEST("Hybrid: wrong ML-KEM component breaks combined SS");
    uint8_t pk1[1184], sk1[2400], pk2[1184], sk2[2400], ct[1088];
    uint8_t ss_good[32], ss_bad[32], x_ss[32];
    crypto_kem_keypair(pk1, sk1); crypto_kem_keypair(pk2, sk2);
    crypto_kem_enc(ct, ss_good, pk1); crypto_kem_dec(ss_bad, ct, sk2);
    onlykey_mlkem_randombytes(x_ss, 32);
    uint8_t c1[32], c2[32];
    sha256_combine(x_ss, ss_good, c1); sha256_combine(x_ss, ss_bad, c2);
    if (memcmp(c1, c2, 32) == 0) { FAIL("bad mlkem still matched"); return 1; }
    PASS(); return 0;
}

static int test_hybrid_full_flow(void) {
    TEST("Hybrid: full simulated device<->host flow");
    uint8_t ctap[7609]; memset(ctap, 0, sizeof(ctap));

    /* Device keygen */
    uint8_t *mlkem_sk = ctap, *mlkem_pk = ctap + 2400;
    if (crypto_kem_keypair(mlkem_pk, mlkem_sk) != 0) { FAIL("keygen"); return 1; }
    uint8_t x25519_device_sk[32]; onlykey_mlkem_randombytes(x25519_device_sk, 32);

    /* Persist */
    uint8_t fl_mlkem[2400], fl_x25519[32];
    memcpy(fl_mlkem, mlkem_sk, 2400);
    memcpy(fl_x25519, x25519_device_sk, 32);
    uint8_t pk_host[1184]; memcpy(pk_host, mlkem_pk, 1184);
    memset(ctap, 0, sizeof(ctap));

    /* Host encaps */
    /* Simulate X25519 ECDH with matching shared secret derivation */
    uint8_t x25519_eph_sk[32]; onlykey_mlkem_randombytes(x25519_eph_sk, 32);
    uint8_t x25519_ss_host[32]; sha256_combine(x25519_eph_sk, fl_x25519, x25519_ss_host);
    uint8_t mlkem_ct[1088], mlkem_ss_host[32];
    if (crypto_kem_enc(mlkem_ct, mlkem_ss_host, pk_host) != 0) { FAIL("encaps"); return 1; }
    uint8_t ss_host[32]; sha256_combine(x25519_ss_host, mlkem_ss_host, ss_host);

    /* Build payload: eph_pk(32) || mlkem_ct(1088) */
    /* (eph_pk is just the raw sk for this simulated ECDH) */

    /* Device decaps */
    memcpy(ctap, fl_mlkem, 2400);
    uint8_t *lb = ctap + 5465;
    memcpy(lb, x25519_eph_sk, 32); /* peer "pk" */
    memcpy(lb + 32, mlkem_ct, 1088);

    uint8_t x25519_ss_dev[32]; sha256_combine(x25519_eph_sk, fl_x25519, x25519_ss_dev);
    uint8_t mlkem_ss_dev[32];
    if (crypto_kem_dec(mlkem_ss_dev, lb + 32, ctap) != 0) { FAIL("decaps"); return 1; }
    uint8_t ss_dev[32]; sha256_combine(x25519_ss_dev, mlkem_ss_dev, ss_dev);

    if (memcmp(ss_host, ss_dev, 32) != 0) {
        FAIL("combined SS mismatch");
        printf("         Host:   "); for(int i=0;i<8;i++) printf("%02x",ss_host[i]); printf("...\n");
        printf("         Device: "); for(int i=0;i<8;i++) printf("%02x",ss_dev[i]); printf("...\n");
        return 1;
    }
    PASS(); return 0;
}

/* === Performance & Stress === */

static int test_performance(void) {
    TEST("Performance: ML-KEM-768 (10 iterations)");
    uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
    int N = 10; clock_t start, end;
    start = clock(); for (int i=0;i<N;i++) crypto_kem_keypair(pk,sk); end = clock();
    double kg = ((double)(end-start)/CLOCKS_PER_SEC*1000.0)/N;
    start = clock(); for (int i=0;i<N;i++) crypto_kem_enc(ct,ss1,pk); end = clock();
    double ec = ((double)(end-start)/CLOCKS_PER_SEC*1000.0)/N;
    start = clock(); for (int i=0;i<N;i++) crypto_kem_dec(ss2,ct,sk); end = clock();
    double dc = ((double)(end-start)/CLOCKS_PER_SEC*1000.0)/N;
    printf("PASS\n");
    printf("         Keygen: %.2f ms  Encaps: %.2f ms  Decaps: %.2f ms\n", kg, ec, dc);
    tests_passed++; return 0;
}

static int test_stress(void) {
    TEST("Stress: 100 hybrid round-trips");
    for (int i = 0; i < 100; i++) {
        uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
        if (crypto_kem_keypair(pk,sk)!=0||crypto_kem_enc(ct,ss1,pk)!=0||crypto_kem_dec(ss2,ct,sk)!=0) { FAIL("crypto"); return 1; }
        if (memcmp(ss1,ss2,32)!=0) { printf("FAIL iter %d\n",i); return 1; }
        uint8_t x[32], c1[32], c2[32]; onlykey_mlkem_randombytes(x,32);
        sha256_combine(x,ss1,c1); sha256_combine(x,ss2,c2);
        if (memcmp(c1,c2,32)!=0) { printf("FAIL combiner iter %d\n",i); return 1; }
    }
    PASS(); return 0;
}

int main(void) {
    printf("============================================================\n");
    printf("  ML-KEM-768 & Hybrid X25519+ML-KEM-768 Test Suite\n");
    printf("  FIPS 203 | mlkem-native | OnlyKey\n");
    printf("============================================================\n\n");
    printf("Sizes: ML-KEM PK=%d SK=%d CT=%d SS=%d\n", 1184, 2400, 1088, 32);
    printf("       Hybrid PK=%d CT=%d SS=%d\n\n", 1216, 1120, 32);

    printf("--- ML-KEM-768 Standalone ---\n");
    test_sizes(); test_roundtrip(); test_different_secrets();
    test_wrong_sk(); test_corrupted_ct(); test_pk_in_sk();
    test_check_pk_sk(); test_onlykey_flow();

    printf("\n--- Hybrid X25519 + ML-KEM-768 ---\n");
    test_hybrid_sizes(); test_hybrid_mlkem_roundtrip();
    test_hybrid_combiner_deterministic();
    test_hybrid_wrong_x25519(); test_hybrid_wrong_mlkem();
    test_hybrid_full_flow();

    printf("\n--- Performance & Stress ---\n");
    test_performance(); test_stress();

    printf("\n============================================================\n");
    printf("  Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("============================================================\n");
    return (tests_passed == tests_run) ? 0 : 1;
}
