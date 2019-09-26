// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _DEVICE_H
#define _DEVICE_H

#include "ctaphid.h"
#include "ctap.h"
#include "storage.h"
#include "uECC.h"
#include "sha256.h"


typedef struct SHA256_HashContext{
    const uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;


#ifdef __cplusplus
extern "C"
{
#endif

extern void fido_msg_timeout();
extern void recv_fido_msg(uint8_t *buffer);
extern void init_SHA256(const uECC_HashContext *base);
extern void update_SHA256(const uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size);
extern void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result);

extern void U2Finit();
extern void store_FIDO_response (uint8_t *data, int len, bool encrypt);
extern int webcryptcheck (uint8_t * _appid);
void device_init();

//uint32_t millis();

//void delay(uint32_t ms);

#define NVIC_SystemReset CPU_RESTART
// Storage of FIDO2 resident keys
#define PAGE_SIZE		2048
#define PAGES			2
//#define RK_NUM_PAGES    1
//#define RK_START_PAGE   (PAGES - 14)
//#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)     // not included
#define DEBUG_LEVEL 0
#define ENABLE_U2F
#define ENABLE_U2F_EXTENSIONS
#define BRIDGE_TO_WALLET
// HID message size in bytes
#define HID_MESSAGE_SIZE        64
#define ONLYKEY_SOLO

//void usbhid_init();

//int usbhid_recv(uint8_t * msg);

//void usbhid_send(uint8_t * msg);

//void usbhid_close();

void main_loop_delay();

//void heartbeat();


void authenticator_read_state(AuthenticatorState * );

void authenticator_read_backup_state(AuthenticatorState * );

// Return 1 yes backup is init'd, else 0
//void authenticator_initialize()
int authenticator_is_backup_initialized();

void authenticator_write_state(AuthenticatorState *, int backup);

// Called each main loop.  Doesn't need to do anything.
void device_manage();

// sets status that's uses for sending status updates ~100ms.
// A timer should be set up to call `ctaphid_update_status`
void device_set_status(uint32_t status);

// Returns if button is currently pressed
int device_is_button_pressed();

// Test for user presence
// Return 1 for user is present, 0 user not present, -1 if cancel is requested.
extern int ctap_user_presence_test(uint32_t delay);

// Generate @num bytes of random numbers to @dest
// return 1 if success, error otherwise
extern int ctap_generate_rng(uint8_t * dst, size_t num);

// Increment atomic counter and return it.
// Must support two counters, @sel selects counter0 or counter1.
uint32_t ctap_atomic_count(int sel);

// Verify the user
// return 1 if user is verified, 0 if not
extern int ctap_user_verification(uint8_t arg);

// Must be implemented by application
// data is HID_MESSAGE_SIZE long in bytes
extern void ctaphid_write_block(uint8_t * data);

extern int handle_packets();


// Resident key
void ctap_reset_rk();
uint32_t ctap_rk_size();
void ctap_store_rk(int index,CTAP_residentKey * rk);
void ctap_load_rk(int index,CTAP_residentKey * rk);
void ctap_overwrite_rk(int index,CTAP_residentKey * rk);

// For Solo hacker
//void boot_solo_bootloader();
//void boot_st_bootloader();

// HID wink command
void device_wink();

//typedef enum {
//    DEVICE_LOW_POWER_IDLE = 0,
//    DEVICE_LOW_POWER_FAST = 1,
//    DEVICE_FAST = 2,
//} DEVICE_CLOCK_RATE;

// Set the clock rate for the device.
// Three modes are targetted for Solo.
// 0: Lowest clock rate for NFC.
// 1: fastest clock rate supported at a low power setting for NFC FIDO.
// 2: fastest clock rate.  Generally for USB interface.
//void device_set_clock_rate(DEVICE_CLOCK_RATE param);

// Returns NFC_IS_NA, NFC_IS_ACTIVE, or NFC_IS_AVAILABLE
#define NFC_IS_NA        0
#define NFC_IS_ACTIVE    1
#define NFC_IS_AVAILABLE 2
int device_is_nfc();

void device_init_button();

#ifdef __cplusplus
}
#endif
#endif
