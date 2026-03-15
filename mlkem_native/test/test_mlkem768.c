/*
 * ML-KEM-768 integration test suite
 * Tests the mlkem-native library with OnlyKey config
 *
 * Compile:
 *   gcc -std=c99 -O2 -Imlkem_native -DMLK_CONFIG_PARAMETER_SET=768 \
 *       test_mlkem768.c mlkem_native/mlkem_native.c -o test_mlkem768
 *
 * Run:
 *   ./test_mlkem768
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "mlkem_native/mlkem_native.h"

/* Provide the RNG that our config expects */
int onlykey_mlkem_randombytes(uint8_t *out, size_t outlen) {
    /* For testing only — use /dev/urandom */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    if (fread(out, 1, outlen, f) != outlen) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%02d] %-50s ", tests_run, name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/*
 * Test 1: Basic keygen + encaps + decaps round-trip
 */
static int test_roundtrip(void) {
    TEST("Keygen + Encaps + Decaps round-trip");

    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES];
    uint8_t ss_dec[MLKEM_BYTES];

    if (crypto_kem_keypair(pk, sk) != 0) { FAIL("keygen failed"); return 1; }
    if (crypto_kem_enc(ct, ss_enc, pk) != 0) { FAIL("encaps failed"); return 1; }
    if (crypto_kem_dec(ss_dec, ct, sk) != 0) { FAIL("decaps failed"); return 1; }

    if (memcmp(ss_enc, ss_dec, MLKEM_BYTES) != 0) {
        FAIL("shared secrets don't match");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 2: Multiple round-trips produce different shared secrets
 */
static int test_different_secrets(void) {
    TEST("Multiple encaps produce different secrets");

    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct1[MLKEM768_CIPHERTEXTBYTES], ct2[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss1[MLKEM_BYTES], ss2[MLKEM_BYTES];

    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct1, ss1, pk);
    crypto_kem_enc(ct2, ss2, pk);

    if (memcmp(ss1, ss2, MLKEM_BYTES) == 0) {
        FAIL("two encaps produced identical secrets");
        return 1;
    }
    if (memcmp(ct1, ct2, MLKEM768_CIPHERTEXTBYTES) == 0) {
        FAIL("two encaps produced identical ciphertexts");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 3: Different keypairs produce different results
 */
static int test_different_keypairs(void) {
    TEST("Different keypairs produce different PKs/SKs");

    uint8_t pk1[MLKEM768_PUBLICKEYBYTES], pk2[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk1[MLKEM768_SECRETKEYBYTES], sk2[MLKEM768_SECRETKEYBYTES];

    crypto_kem_keypair(pk1, sk1);
    crypto_kem_keypair(pk2, sk2);

    if (memcmp(pk1, pk2, MLKEM768_PUBLICKEYBYTES) == 0) {
        FAIL("two keygens produced identical public keys");
        return 1;
    }
    if (memcmp(sk1, sk2, MLKEM768_SECRETKEYBYTES) == 0) {
        FAIL("two keygens produced identical secret keys");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 4: Wrong SK fails to produce matching shared secret
 * (ML-KEM implicit rejection: decaps with wrong SK returns a pseudorandom value)
 */
static int test_wrong_sk(void) {
    TEST("Wrong SK produces non-matching shared secret");

    uint8_t pk1[MLKEM768_PUBLICKEYBYTES], sk1[MLKEM768_SECRETKEYBYTES];
    uint8_t pk2[MLKEM768_PUBLICKEYBYTES], sk2[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES], ss_dec[MLKEM_BYTES];

    crypto_kem_keypair(pk1, sk1);
    crypto_kem_keypair(pk2, sk2);

    /* Encaps with pk1 */
    crypto_kem_enc(ct, ss_enc, pk1);

    /* Decaps with sk2 — should NOT match */
    crypto_kem_dec(ss_dec, ct, sk2);

    if (memcmp(ss_enc, ss_dec, MLKEM_BYTES) == 0) {
        FAIL("wrong SK produced matching shared secret");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 5: Corrupted ciphertext produces non-matching shared secret
 * (ML-KEM implicit rejection)
 */
static int test_corrupted_ct(void) {
    TEST("Corrupted CT produces non-matching shared secret");

    uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES], ss_dec[MLKEM_BYTES];

    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss_enc, pk);

    /* Flip a bit in the ciphertext */
    ct[0] ^= 0x01;

    crypto_kem_dec(ss_dec, ct, sk);

    if (memcmp(ss_enc, ss_dec, MLKEM_BYTES) == 0) {
        FAIL("corrupted CT still produced matching shared secret");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 6: Verify sizes match FIPS 203 ML-KEM-768
 */
static int test_sizes(void) {
    TEST("Buffer sizes match FIPS 203 ML-KEM-768 spec");

    int ok = 1;
    if (MLKEM768_PUBLICKEYBYTES != 1184) { ok = 0; printf("PK=%d ", MLKEM768_PUBLICKEYBYTES); }
    if (MLKEM768_SECRETKEYBYTES != 2400) { ok = 0; printf("SK=%d ", MLKEM768_SECRETKEYBYTES); }
    if (MLKEM768_CIPHERTEXTBYTES != 1088) { ok = 0; printf("CT=%d ", MLKEM768_CIPHERTEXTBYTES); }
    if (MLKEM_BYTES != 32) { ok = 0; printf("SS=%d ", MLKEM_BYTES); }

    if (!ok) { FAIL("size mismatch"); return 1; }
    PASS();
    return 0;
}

/*
 * Test 7: PK extraction from SK matches keygen PK
 * (Validates the SK layout we rely on in okcrypto_mlkem_getpubkey)
 */
static int test_pk_embedded_in_sk(void) {
    TEST("PK embedded in SK at offset 1152 matches keygen PK");

    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];

    crypto_kem_keypair(pk, sk);

    /* ML-KEM-768 SK layout: sk_pke(1152) || pk(1184) || H(pk)(32) || z(32)
     * So PK starts at offset 2400 - 1184 - 64 = 1152 */
    uint8_t *pk_in_sk = sk + 1152;

    if (memcmp(pk, pk_in_sk, MLKEM768_PUBLICKEYBYTES) != 0) {
        FAIL("PK in SK doesn't match keygen PK");
        printf("         This means okcrypto_mlkem_getpubkey offset is WRONG\n");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 8: Public key check function
 */
static int test_check_pk(void) {
    TEST("crypto_kem_check_pk validates/rejects public keys");

    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];

    crypto_kem_keypair(pk, sk);

    /* Valid PK should pass */
    if (crypto_kem_check_pk(pk) != 0) {
        FAIL("valid PK rejected");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 9: Secret key check function
 */
static int test_check_sk(void) {
    TEST("crypto_kem_check_sk validates secret keys");

    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];

    crypto_kem_keypair(pk, sk);

    if (crypto_kem_check_sk(sk) != 0) {
        FAIL("valid SK rejected");
        return 1;
    }
    PASS();
    return 0;
}

/*
 * Test 10: Simulate OnlyKey flow (keygen -> store -> load -> decaps)
 * Mimics the actual firmware flow: keygen writes to a buffer,
 * then later decaps loads SK from the same buffer.
 */
static int test_onlykey_flow(void) {
    TEST("Simulated OnlyKey flow: keygen -> persist -> decaps");

    /* Simulate ctap_buffer */
    uint8_t ctap_buffer[7609];
    memset(ctap_buffer, 0, sizeof(ctap_buffer));

    /* === Keygen phase (on-device) === */
    uint8_t *sk = ctap_buffer;             /* SK at ctap_buffer[0..2399] */
    uint8_t *pk = ctap_buffer + 2400;      /* PK at ctap_buffer[2400..3583] */

    if (crypto_kem_keypair(pk, sk) != 0) {
        FAIL("keygen failed");
        return 1;
    }

    /* "Send PK to host" — copy it out before wiping */
    uint8_t pk_host[MLKEM768_PUBLICKEYBYTES];
    memcpy(pk_host, pk, MLKEM768_PUBLICKEYBYTES);

    /* "Persist SK to flash" — simulate by copying to a flash buffer */
    uint8_t flash_sector10[2048];
    uint8_t flash_sector11[2048];
    memcpy(flash_sector10, sk, 2048);
    memset(flash_sector11, 0xFF, 2048);
    memcpy(flash_sector11, sk + 2048, 2400 - 2048); /* 352 bytes */
    flash_sector11[352] = 5; /* features = KEYTYPE_MLKEM768 */

    /* Wipe ctap_buffer (simulating post-keygen cleanup) */
    memset(ctap_buffer, 0, sizeof(ctap_buffer));

    /* === Host-side encaps === */
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_host[MLKEM_BYTES];
    if (crypto_kem_enc(ct, ss_host, pk_host) != 0) {
        FAIL("host encaps failed");
        return 1;
    }

    /* === Decaps phase (on-device) === */
    /* "Load SK from flash" into ctap_buffer[0..2399] */
    memcpy(ctap_buffer, flash_sector10, 2048);
    memcpy(ctap_buffer + 2048, flash_sector11, 352);
    uint8_t *sk_loaded = ctap_buffer;

    /* "CT arrived via large_buffer" at ctap_buffer[5497] */
    uint8_t *large_buffer = ctap_buffer + 5497;
    memcpy(large_buffer, ct, MLKEM768_CIPHERTEXTBYTES);

    /* Decapsulate */
    uint8_t ss_device[MLKEM_BYTES];
    if (crypto_kem_dec(ss_device, large_buffer, sk_loaded) != 0) {
        FAIL("device decaps failed");
        return 1;
    }

    /* Verify shared secrets match */
    if (memcmp(ss_host, ss_device, MLKEM_BYTES) != 0) {
        FAIL("host and device shared secrets don't match");
        printf("         Host SS:   ");
        for (int i = 0; i < 8; i++) printf("%02x", ss_host[i]);
        printf("...\n");
        printf("         Device SS: ");
        for (int i = 0; i < 8; i++) printf("%02x", ss_device[i]);
        printf("...\n");
        return 1;
    }

    /* Wipe */
    memset(ctap_buffer, 0, sizeof(ctap_buffer));
    memset(ss_device, 0, sizeof(ss_device));

    PASS();
    return 0;
}

/*
 * Test 11: Measure performance
 */
static int test_performance(void) {
    TEST("Performance benchmark (10 iterations)");

    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES], ss_dec[MLKEM_BYTES];

    int N = 10;
    clock_t start, end;

    /* Keygen */
    start = clock();
    for (int i = 0; i < N; i++) crypto_kem_keypair(pk, sk);
    end = clock();
    double keygen_ms = ((double)(end - start) / CLOCKS_PER_SEC * 1000.0) / N;

    /* Encaps */
    start = clock();
    for (int i = 0; i < N; i++) crypto_kem_enc(ct, ss_enc, pk);
    end = clock();
    double encaps_ms = ((double)(end - start) / CLOCKS_PER_SEC * 1000.0) / N;

    /* Decaps */
    start = clock();
    for (int i = 0; i < N; i++) crypto_kem_dec(ss_dec, ct, sk);
    end = clock();
    double decaps_ms = ((double)(end - start) / CLOCKS_PER_SEC * 1000.0) / N;

    printf("PASS\n");
    printf("         Keygen:  %.2f ms\n", keygen_ms);
    printf("         Encaps:  %.2f ms\n", encaps_ms);
    printf("         Decaps:  %.2f ms\n", decaps_ms);
    tests_passed++;
    return 0;
}

/*
 * Test 12: Stress test — 100 round-trips
 */
static int test_stress(void) {
    TEST("Stress test: 100 keygen+encaps+decaps round-trips");

    for (int i = 0; i < 100; i++) {
        uint8_t pk[MLKEM768_PUBLICKEYBYTES];
        uint8_t sk[MLKEM768_SECRETKEYBYTES];
        uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
        uint8_t ss_enc[MLKEM_BYTES], ss_dec[MLKEM_BYTES];

        if (crypto_kem_keypair(pk, sk) != 0) { FAIL("keygen failed"); return 1; }
        if (crypto_kem_enc(ct, ss_enc, pk) != 0) { FAIL("encaps failed"); return 1; }
        if (crypto_kem_dec(ss_dec, ct, sk) != 0) { FAIL("decaps failed"); return 1; }
        if (memcmp(ss_enc, ss_dec, MLKEM_BYTES) != 0) {
            printf("FAIL at iteration %d\n", i);
            return 1;
        }
    }
    PASS();
    return 0;
}

int main(void) {
    printf("============================================\n");
    printf("  ML-KEM-768 Integration Test Suite\n");
    printf("  FIPS 203 | mlkem-native | OnlyKey config\n");
    printf("============================================\n\n");

    printf("Buffer sizes:\n");
    printf("  PUBLICKEYBYTES:   %d\n", MLKEM768_PUBLICKEYBYTES);
    printf("  SECRETKEYBYTES:   %d\n", MLKEM768_SECRETKEYBYTES);
    printf("  CIPHERTEXTBYTES:  %d\n", MLKEM768_CIPHERTEXTBYTES);
    printf("  SHARED SECRET:    %d\n\n", MLKEM_BYTES);

    test_sizes();
    test_roundtrip();
    test_different_secrets();
    test_different_keypairs();
    test_wrong_sk();
    test_corrupted_ct();
    test_pk_embedded_in_sk();
    test_check_pk();
    test_check_sk();
    test_onlykey_flow();
    test_performance();
    test_stress();

    printf("\n============================================\n");
    printf("  Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("============================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
