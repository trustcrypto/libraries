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
extern void store_FIDO_response (uint8_t *data, int len, uint8_t encrypt);
extern int webcryptcheck (uint8_t * _appid, uint8_t * buffer);
void device_init();

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

/** Return a millisecond timestamp.  Does not need to be synchronized to anything.
 *  *Optional* to compile, but will not calculate delays correctly without a correct implementation.
*/
//uint32_t millis();


/** Called by HIDUSB layer to write bytes to the USB HID interface endpoint.
 *  Will write 64 bytes at a time.
 *  
 *  @param msg Pointer to a 64 byte buffer containing a payload to be sent via USB HID. 
 * 
 *  **Required** to compile and work for FIDO application.
*/
extern void usbhid_send(uint8_t * msg);
extern int handle_packets();


/** Reboot / power reset the device.
 *  **Optional** this is not used for FIDO2, and simply won't do anything if not implemented.
*/
//void device_reboot();

extern int authenticator_read_state(AuthenticatorState * s);

/** Store changes in the authenticator state to nonvolatile memory.
 *  @param s pointer to valid Authenticator state to write to NV memory.
 * 
 *  *Optional* this is required to make persistant updates to FIDO2 State (PIN and device master secret).
 *             Without it, changes simply won't be persistant.
 */
extern void authenticator_write_state(AuthenticatorState * s);

// sets status that's uses for sending status updates ~100ms.
// A timer should be set up to call `ctaphid_update_status`

/** Updates status of the status of the FIDO2 layer application, which
 *  can be used for polling updates in the USBHID layer.
 * 
 * @param status is one of the following, which can be used appropriately by USB HID layer.
        #define CTAPHID_STATUS_IDLE         0
        #define CTAPHID_STATUS_PROCESSING   1
        #define CTAPHID_STATUS_UPNEEDED     2
 * 
 * *Optional* to compile and run, but will be required to be used for proper FIDO2 operation with some platforms.
*/
void device_set_status(uint32_t status);

/** Returns true if button is currently pressed.  Debouncing does not need to be handled.  Should not block.
 * @return 1 if button is currently pressed.  
 * 
 * *Optional* to compile and run, but just returns one by default.
*/
int device_is_button_pressed();


/** Test for user presence.
 *  Perform test that user is present.  Returns status on user presence.  This is used by FIDO and U2F layer
 *  to check if an operation should continue, or if the UP flag should be set.
 * 
 * @param delay number of milliseconds to delay waiting for user before timeout.
 * 
 * @return 2 - User presence is disabled.  Operation should continue, but UP flag not set.
 *         1 - User presence confirmed.  Operation should continue, and UP flag is set.
 *         0 - User presence is not confirmed.  Operation should be denied.
 *        -1 - Operation was canceled.  Do not continue, reset transaction state.
 * 
 * *Optional*, the default implementation will return 1, unless a FIDO2 operation calls for no UP, where this will then return 2.
*/
extern int ctap_user_presence_test(uint32_t delay);

/** Disable the next user presence test.  This is called by FIDO2 layer when a transaction
 *  requests UP to be disabled.  The next call to ctap_user_presence_test should return 2,
 *  and then UP should be enabled again.
 * 
 * @param request_active indicate to activate (true) or disable (false) UP.
 * 
 * *Optional*, the default implementation will provide expected behaviour with the default ctap_user_presence_test(...).
*/
extern void device_disable_up(bool request_active);

/** Generate random numbers.  Random numbers should be good enough quality for 
 *  cryptographic use.
 * 
 *  @param dst the buffer to write into.
 *  @param num the number of bytes to generate and write to dst.
 * 
 *  @return 1 if successful, or else the RNG failed.
 * 
 * *Optional*, if not implemented, the random numbers will be from rand() and an error will be logged.
*/
extern int ctap_generate_rng(uint8_t * dst, size_t num);

/** Increment an atomic (non-volatile) counter and return the value.
 * 
 * @param amount a non-zero amount to increment the counter by.
 * 
 * *Optional*, if not implemented, the counter will not be persistant.
*/
extern uint32_t ctap_atomic_count(uint32_t amount);

/** Delete all resident keys.
 * 
 * *Optional*, if not implemented, operates on non-persistant RK's.
*/
extern void ctap_reset_rk();

/** Return the maximum amount of resident keys that can be stored.
 * @return max number of resident keys that can be stored, including already stored RK's.
 * 
 * *Optional*, if not implemented, returns 50.
*/
extern uint32_t ctap_rk_size();

/** Store a resident key into an index between [ 0, ctap_rk_size() ).
 *  Storage should be in non-volatile memory.
 * 
 * @param index between RK index range.
 * @param rk pointer to valid rk structure that should be written to NV memory.
 * 
 * *Optional*, if not implemented, operates on non-persistant RK's.
*/
extern void ctap_store_rk(int index,CTAP_residentKey * rk);

/** Delete a resident key from an index.
 * @param index to delete resident key from.  Has no effect if no RK exists at index.
 * 
 * *Optional*, if not implemented, operates on non-persistant RK's.
*/
extern void ctap_delete_rk(int index);

/** Read a resident key from an index into memory
 * @param index to read resident key from.
 * @param rk pointer to resident key structure to write into with RK.
 * 
 * *Optional*, if not implemented, operates on non-persistant RK's.
*/
extern void ctap_load_rk(int index,CTAP_residentKey * rk);

/** Overwrite the RK located in index with a new RK.
 * @param index to write resident key to.
 * @param rk pointer to valid rk structure that should be written to NV memory, and replace existing RK there.
 * 
 * *Optional*, if not implemented, operates on non-persistant RK's.
*/
extern void ctap_overwrite_rk(int index,CTAP_residentKey * rk);

/** Called by HID layer to indicate that a wink behavior should be performed.
 *  Should not block, and the wink behavior should occur in parallel to FIDO operations.
 * 
 * *Optional*.
*/
void device_wink();

//typedef enum {
//    DEVICE_LOW_POWER_IDLE = 0,
//    DEVICE_LOW_POWER_FAST = 1,
//    DEVICE_FAST = 2,
//} DEVICE_CLOCK_RATE;

/**
 * Set the clock rate for the device.  This gets called only when the device is running in NFC mode.
 * Before Register and authenticate operations, the clock rate will be set to (1), and otherwise back to (0).
 * @param param
    0: Lowest clock rate for NFC.
    1: fastest clock rate supported at a low power setting for NFC FIDO.
    2: fastest clock rate.  Generally for USB interface.
* *Optional*, by default nothing happens.
*/
//void device_set_clock_rate(DEVICE_CLOCK_RATE param);

// Returns NFC_IS_NA, NFC_IS_ACTIVE, or NFC_IS_AVAILABLE
//#define NFC_IS_NA        0
//#define NFC_IS_ACTIVE    1
//#define NFC_IS_AVAILABLE 2

/** Returns NFC status of the device.
 * @return 0 - NFC is not available.
 *         1 - NFC is active, and is powering the chip for a transaction.
 *         2 - NFC is available, but not currently being used.
*/
int device_is_nfc();

/** Return pointer to attestation key.
 * @return pointer to attestation private key, raw encoded.  For P256, this is 32 bytes.
*/
uint8_t * device_get_attestation_key();

/** Read the device's attestation certificate into buffer @dst.
 * @param dst the destination to write the certificate.
 * 
 * The size of the certificate can be retrieved using `device_attestation_cert_der_get_size()`.
*/
void device_attestation_read_cert_der(uint8_t * dst);

/** Returns the size in bytes of attestation_cert_der.
 * @return number of bytes in attestation_cert_der, not including any C string null byte.
*/
uint16_t device_attestation_cert_der_get_size();

/** Read the device's 16 byte AAGUID into a buffer.
 * @param dst buffer to write 16 byte AAGUID into.
 * */
void device_read_aaguid(uint8_t * dst);

#ifdef __cplusplus
}
#endif
#endif

