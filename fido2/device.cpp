// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include "device.h"
#include "onlykey.h"
#ifdef STD_VERSION
#include "util.h"
#include "log.h"
#include "ctaphid.h"
#include "ctap.h"
#include "crypto.h"
#include "Time.h"
#include "Adafruit_NeoPixel.h"


//#define LOW_FREQUENCY        1
//#define HIGH_FREQUENCY       0

//void wait_for_usb_tether();


uint32_t __90_ms = 0;
uint32_t __device_status = 0;
uint32_t __last_update = 0;
//extern PCD_HandleTypeDef hpcd;
//static int _NFC_status = 0;
//static bool isLowFreq = 0;
//static bool _RequestComeFromNFC = false;

#define IS_BUTTON_PRESSED() (u2f_button == 1)

extern uint8_t profilemode;
extern int large_buffer_offset;
extern uint8_t *large_resp_buffer;
extern int large_resp_buffer_offset;
extern int large_resp_buffer_cursor;
extern uint8_t large_resp_buffer_last_opt3;
extern int packet_buffer_offset;
extern uint8_t recv_buffer[64];
extern uint8_t resp_buffer[64];
extern uint8_t CRYPTO_AUTH;

int u2f_button = 0;

void U2Finit() {
    uint8_t tempbuf[513];
#ifdef FACTORYKEYS
    if (*certified_hw == 1) {
        // New method decrypt attestation with device keys
        okcore_flashget_common(tempbuf, (unsigned long *)enckeysectoradr, 513);
        okcrypto_aes_gcm_decrypt2(tempbuf + 480, tempbuf + 436, tempbuf + 448, 32, true);
        memcpy(attestation_key, tempbuf + 480, 32);
    }
#endif
    device_init();
}

void fido_msg_timeout() {
    ctaphid_check_timeouts();
}

void recv_fido_msg(uint8_t *buffer) {
    ctaphid_handle_packet(buffer);
    memset(recv_buffer, 0, sizeof(recv_buffer));
}

void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}
void update_SHA256(const uECC_HashContext *base, const uint8_t *message, unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, message_size);
}
void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}

int webcryptcheck(uint8_t *_appid, uint8_t *buffer) {
    /* Trusted webcrypt origins, compiled in. hash: SHA-256 of the rpId.
     * name: the rpId followed by 0x02, compared with ctap_buffer+4. */
    struct trusted_origin {
        const char *hash;
        const char *name;
        uint8_t namelen;
    };
    static const struct trusted_origin trusted[] = {
        {/* apps.crp.to */
            "\xEB\xAE\xE3\x29\x09\x0A\x5B\x51\x92\xE0\xBD\x13\x2D\x5C\x22\xC6"
            "\xD1\x8A\x4D\x23\xFC\x8E\xFD\x4A\x21\xAF\xA8\xE4\xC8\xFD\x93\x54",
            "\x61\x70\x70\x73\x2E\x63\x72\x70\x2E\x74\x6F\x02", 12},
        {/* apps.onlykey.io */
            "\xAE\x3C\x14\xA6\x10\xDE\xE7\xC1\x61\x1C\x8B\xDC\xE6\x53\x70\x5E"
            "\x43\xB5\x4D\x08\x9D\x25\x31\x7C\x94\x2C\xF0\x51\x69\xDC\xC7\xAA",
            "\x61\x70\x70\x73\x2E\x6F\x6E\x6C\x79\x6B\x65\x79\x2E\x69\x6F\x02", 16},
    };
#define TRUSTED_ORIGIN_COUNT ((int)(sizeof(trusted) / sizeof(trusted[0])))
#define TRUSTED_NAME_MAX 16

    //const char stored_appid_u2f[] = "\x23\xCD\xF4\x07\xFD\x90\x4F\xEE\x8B\x96\x40\x08\xB0\x49\xC5\x5E\xA8\x81\x13\x36\xA3\xA5\x17\x1B\x58\xD6\x6A\xEC\xF3\x79\xE7\x4A";
    //const char stored_clientDataHash[] = "\x57\x81\xAF\x14\xB9\x71\x6D\x87\x24\x61\x8E\x8A\x6F\xD6\x50\xEB\x6B\x02\x6B\xEC\x6B\xAD\xB3\xB1\xA3\x01\xAA\x0D\x75\xF6\x0C\x14";
    //const char stored_clientDataHash_u2f[] = "\x78\x4E\x39\xF2\xDA\xF8\xE6\xA4\xBB\xD7\x15\x0D\x39\x34\xCC\x81\x5F\x6E\xE7\x6F\x57\xBC\x02\x6A\x0E\x49\x33\x13\xF4\x36\x63\x47";
    uint8_t rpid[TRUSTED_NAME_MAX];
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
    memcpy(rpid, ctap_buffer + 4, TRUSTED_NAME_MAX);
    uint8_t wc_policy = okcore_webcrypt_policy();
#ifdef DEBUG
    Serial.println("Ctap buffer:");
    byteprint(ctap_buffer, 12);
    Serial.println("rpid seen:");
    byteprint((uint8_t *)rpid, TRUSTED_NAME_MAX);
    Serial.println("_appid seen:");
    byteprint(_appid, 32);
    for (int t = 0; t < TRUSTED_ORIGIN_COUNT; t++) {
        Serial.print("trusted origin ");
        Serial.print(t);
        Serial.println(" name/hash:");
        byteprint((uint8_t *)trusted[t].name, trusted[t].namelen);
        byteprint((uint8_t *)trusted[t].hash, 32);
    }
    return 2; // Trust all origins for debug firmware
#endif

    /* _appid is NULL when called from add_existing_user_info() (ctap.cpp);
     * only the name is compared then. */
    int origin_ok = 0;
    for (int t = 0; t < TRUSTED_ORIGIN_COUNT && !origin_ok; t++) {
        if (_appid && memcmp(trusted[t].hash, _appid, 32) == 0)
            origin_ok = 1;
        else if (memcmp(trusted[t].name, rpid, trusted[t].namelen) == 0)
            origin_ok = 1;
    }
    if (origin_ok && !(wc_policy & OKWC_DISABLE_EXT)) {
        // 2: stored keys allowed, 1: derived keys only.
        return (wc_policy & OKWC_ALLOW_STORED_KEY) ? 2 : 1;
    } else
        return 0;
}

void store_FIDO_response(uint8_t *data, int len, uint8_t encrypt) {
    cancelfadeoffafter20();
    const int framed = (encrypt == 1 || encrypt == 2)
        ? len + OKCRYPTO_TRANSIT_OVERHEAD
        : len;
    if (framed >= (int)LARGE_RESP_BUFFER_SIZE) {
        hidprint("Error response too large to store");
        return;
    }
    if (encrypt == 2 && len < 32) {
        hidprint("Error malformed response");
        return;
    }

    // Seal in large_resp_buffer: the caller's buffer has no room for the
    // counter and tag.
    if (encrypt == 1) {
        /* [counter(4)][ciphertext(len)][tag(16)] */
        memmove(large_resp_buffer + OKCRYPTO_TRANSIT_CTR_LEN, data, len);
        large_resp_buffer_offset = okcrypto_transit_seal(large_resp_buffer, len);
    } else if (encrypt == 2) {
        /* [transit pubkey(32), clear][counter(4)][ciphertext(len-32)][tag(16)]
     *
     * Move the tail first: `data` may point into large_resp_buffer. */
        memmove(large_resp_buffer + 32 + OKCRYPTO_TRANSIT_CTR_LEN, data + 32, len - 32);
        memmove(large_resp_buffer, data, 32);
        large_resp_buffer_offset = 32 + okcrypto_transit_seal(large_resp_buffer + 32, len - 32);
    } else {
        // Unencrypted message, check if it's an error message
        if (strcmp((char *)data, "Error")) {
            // `data` may point into large_resp_buffer; clear only the bytes
            // outside the payload.
            if (data >= large_resp_buffer && data < large_resp_buffer + LARGE_RESP_BUFFER_SIZE) {
                int used = (int)(data - large_resp_buffer) + len;
                if (used > (int)LARGE_RESP_BUFFER_SIZE) used = (int)LARGE_RESP_BUFFER_SIZE;
                memset(large_resp_buffer, 0, (int)(data - large_resp_buffer));
                memset(large_resp_buffer + used, 0, LARGE_RESP_BUFFER_SIZE - used);
            } else {
                memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
            }
            CRYPTO_AUTH = 0;
        }
        memmove(large_resp_buffer, data, len);
        large_resp_buffer_offset = len;
    }

    large_resp_buffer_cursor = 0;
    large_resp_buffer_last_opt3 = 0;

#ifdef DEBUG
    Serial.print("Stored Data for FIDO Response ");
    Serial.println(large_resp_buffer_offset);
#endif
#ifdef DEBUG_BULK_DUMPS
    byteprint(large_resp_buffer, large_resp_buffer_offset);
#endif
    wipedata(); //Data will wait 5 seconds to be retrieved
}

void device_set_status(uint32_t status) {

    __last_update = millis();


    if (status != CTAPHID_STATUS_IDLE && __device_status != status) {
        ctaphid_update_status(status);
    }
    __device_status = status;
}

extern int u2f_button;
int device_is_button_pressed() {
    return IS_BUTTON_PRESSED();
}

void device_reboot() {
    NVIC_SystemReset();
}

void device_init() {
    ctaphid_init();
    ctap_init();
}

int device_is_nfc() {
    //return haveNFC;
    return 0;
}


void usbhid_send(uint8_t *msg) {
#ifdef DEBUG_CTAP_VERBOSE
    printf1(TAG_GREEN, "Sending FIDO response block");
    byteprint(msg, 64);
#endif
    extern uint8_t useinterface;

    if (useinterface == 2) {
        RawHID.send2(msg, 100);
    } else {
        RawHID.send(msg, 100);
    }
}


void device_wink() {
    setcolor(171); //blue
    delay(500);
}

int authenticator_read_state(AuthenticatorState *a) {
    uint8_t buffer[sizeof(AuthenticatorState)];
    int ret;
#ifdef DEBUG_CTAP_VERBOSE
    printf1(TAG_GREEN, "authenticator_read_state");
#endif
    ret = ctap_flash(0, buffer, sizeof(AuthenticatorState), 3);
    memcpy((uint8_t *)a, buffer, sizeof(AuthenticatorState));
#ifdef DEBUG_CTAP_VERBOSE
    byteprint(buffer, sizeof(AuthenticatorState));
#endif
    return ret;
}

void authenticator_read_backup_state(AuthenticatorState *a) {
//This function is unnecessary, using EEPROM
#ifdef DEBUG_CTAP_VERBOSE
    printf1(TAG_GREEN, "authenticator_read_backup_state");
#endif
}

// Return 1 yes backup is init'd, else 0
int authenticator_is_backup_initialized() {
//This function is unnecessary, using EEPROM
#ifdef DEBUG_CTAP_VERBOSE
    printf1(TAG_GREEN, "authenticator_is_backup_initialized");
#endif
    return 0;
}

void authenticator_write_state(AuthenticatorState *a) {

    uint8_t buffer[sizeof(AuthenticatorState)];
    memcpy(buffer, (uint8_t *)a, sizeof(AuthenticatorState));
#ifdef DEBUG_CTAP_VERBOSE
    printf1(TAG_GREEN, "authenticator_write_state");
    printf1(TAG_GREEN, "authenticator_write_state size %d\n", sizeof(AuthenticatorState));
#endif
    ctap_flash(0, buffer, sizeof(AuthenticatorState), 4);
#ifdef DEBUG_CTAP_VERBOSE
    byteprint(buffer, sizeof(AuthenticatorState));
#endif
}

uint32_t ctap_atomic_count(uint32_t amount) {
    uint32_t counter1 = getCounter();

    if (amount == 0) {
        counter1++;
        setCounter(counter1);
        printf1(TAG_RED, "counter1: %d\n", counter1);
        return counter1;
    } else if (amount > 256) {
        setCounter(amount);
    } else {
        setCounter(amount + counter1);
    }
    return getCounter();
}

void device_manage(void) {
    printf1(TAG_GREEN, "device_manage");
#if NON_BLOCK_PRINTING
    int i = 10;
    uint8_t c;
    while (i--) {
        if (fifo_debug_size()) {
            fifo_debug_take(&c);
            while (!LL_USART_IsActiveFlag_TXE(DEBUG_UART));
            LL_USART_TransmitData8(DEBUG_UART, c);
        } else {
            break;
        }
    }
#endif
    //#ifndef IS_BOOTLOADER
    // if(device_is_nfc())
    //	nfc_loop();
    //#endif
}

static bool _up_disabled = false;

void device_disable_up(bool disable) {
    _up_disabled = disable;
}


int ctap_user_presence_test(uint32_t wait) {
#ifdef DEBUG_CTAP_VERBOSE
    printf1(TAG_GREEN, "ctap_user_presence_test");
#endif
    extern Adafruit_NeoPixel pixels;
    int ret = 0;
    uint32_t t1 = millis();
    uint8_t blink = 0;
    extern int Profile_Offset;

    if (_up_disabled) {
        return 2;
    }

    if (wait > 750) {
        fadeon(171);

        do {
            if (t1 + (wait) < millis()) {
                fadeoff(1);
                return 0;
            }
            if (touch_sense_loop()) u2f_button = 1;
            ret = handle_packets();
            if (blink == 0) setcolor(171);
            if (blink == 128) setcolor(0);
            blink++;
            if (ret) return ret;
        } while (!IS_BUTTON_PRESSED());

    } else {
        do {
            if (Profile_Offset == 84) {
                Profile_Offset = 42;
            }
            if (t1 + (wait) < millis()) {
                fadeoff(0);
                break;
            }
            setcolor(170); //blue

            if (touch_sense_loop()) u2f_button = 1;
        } while (!IS_BUTTON_PRESSED());

        if (Profile_Offset == 42) {
            Profile_Offset = 84;
        }
    }

    if (IS_BUTTON_PRESSED()) {
        fadeoff(0);
        u2f_button = 0;
        return 1;
    } else {
        return 0;
    }
}

// 3-digit challenge on the CTAP path: the user must press the three given
// buttons in order within `wait` ms. Returns 1 = entered, 0 = timeout,
// -2 = wrong button, 2 = presence disabled, -1 = cancelled.
int ctap_challenge_test(uint32_t wait, uint8_t b1, uint8_t b2, uint8_t b3) {
    extern int button_selected;
    uint8_t expected[3] = {b1, b2, b3};
    int idx = 0;
    int ret = 0;
    uint8_t blink = 0;
    uint32_t t1 = millis();
    if (_up_disabled) return 2;
    fadeon(171);
    while (1) {
        if (t1 + wait < millis()) {
            fadeoff(1);
            return 0;
        }
        if (touch_sense_loop()) {
            uint8_t pressed = (uint8_t)(button_selected - '0');
            button_selected = 0;
            if (pressed != expected[idx]) {
                fadeoff(1);
                u2f_button = 0;
                return -2;
            }
            if (++idx == 3) {
                fadeoff(0);
                u2f_button = 0;
                return 1;
            }
        }
        ret = handle_packets();
        if (ret) return ret;
        if (blink == 0) setcolor(171);
        if (blink == 128) setcolor(0);
        blink++;
    }
}

int handle_packets() {
    uint8_t hidmsg[64];
    memset(hidmsg, 0, sizeof(hidmsg));
    int n = RawHID.recv(hidmsg, 0);
    if (n) {
        if (ctaphid_handle_packet(hidmsg) == CTAPHID_CANCEL) {
            printf1(TAG_GREEN, "CANCEL!\r\n");
            fadeoff(1);
            return -1;
        } else {
            return 0;
        }
    }
    return 0;
}


int ctap_generate_rng(uint8_t *dst, size_t num) {
    RNG2(dst, num);
    printf1(TAG_GREEN, "ctap_generate_rng");
    return 1;
}

void ctap_reset_rk(void) {
    printf1(TAG_GREEN, "ctap_reset_rk");
    ctap_flash(0, NULL, 0, 5);
}

uint32_t ctap_rk_size(void) {
    printf1(TAG_GREEN, "12 RKs for now");
    return 12; //support 12 RKs for now
}

void ctap_store_rk(int index, CTAP_residentKey *rk) {
    printf1(TAG_GREEN, "store RK %d \r\n", index);
    ctap_flash(index, (uint8_t *)rk, sizeof(CTAP_residentKey), 2);
}

void ctap_load_rk(int index, CTAP_residentKey *rk) {
    printf1(TAG_GREEN, "read RK %d \r\n", index);
    ctap_flash(index, (uint8_t *)rk, sizeof(CTAP_residentKey), 1);
}

void ctap_overwrite_rk(int index, CTAP_residentKey *rk) {

    printf1(TAG_GREEN, "OVWR RK %d \r\n", index);
    ctap_store_rk(index, rk);
}

void ctap_delete_rk(int index) {
    CTAP_residentKey rk;
    memset(&rk, 0xff, sizeof(CTAP_residentKey));
    ctap_overwrite_rk(index, &rk);
}


void ctap_backup_rk(int index, CTAP_residentKey *rk) {
    /*
        unsigned int index = STATE.rk_stored;
        unsigned int i;
        for (i = 0; i < index; i++)
        {
            ctap_load_rk(i, &rk2);
            if (is_matching_rk(&rk, &rk2))
            {
                ctap_overwrite_rk(i, &rk);
                goto done_rk;
            }
        }
         */
}

void _Error_Handler(char *file, int line) {
    printf2(TAG_ERR, "Error: %s: %d\r\n", file, line);
    while (1) {
    }
}

void device_read_aaguid(uint8_t *dst) {
    if (*certified_hw == 1) {
        memmove(dst, CERTIFIED_CTAP_AAGUID, 16);
    } else {
        memmove(dst, CTAP_AAGUID, 16);
    }
    dump_hex1(TAG_GREEN, dst, 16);
}

uint16_t device_attestation_cert_der_get_size() {
    if (*certified_hw == 1) {
        return certified_attestation_cert_der_size;
    } else {
        return attestation_cert_der_size;
    }
}

void device_attestation_read_cert_der(uint8_t *dst) {
    if (*certified_hw == 1) {
        memmove(dst, certified_attestation_cert_der, device_attestation_cert_der_get_size());
    } else {
        memmove(dst, attestation_cert_der, device_attestation_cert_der_get_size());
    }
}


#endif
