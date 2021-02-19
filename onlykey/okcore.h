/* 
 * Copyright (c) 2015-2020, CryptoTrust LLC.
 * All rights reserved.
 * 
 * Author : Tim Steiner <t@crp.to>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "CryptoTrust" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" or "CryptoTrust" appear in their names without
 *    specific prior written permission. For written permission, please
 *    contact admin@crp.to.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 7. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for this software and any
 *    accompanying software that uses this software. The source code
 *    must either be included in the distribution or be available for
 *    no more than the cost of distribution plus a nominal fee, and must
 *    be freely redistributable under reasonable conditions. For a
 *    binary file, complete source code means the source code for all
 *    modules it contains.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS
 * ARE GRANTED BY THIS LICENSE. IF SOFTWARE RECIPIENT INSTITUTES PATENT
 * LITIGATION AGAINST ANY ENTITY (INCLUDING A CROSS-CLAIM OR COUNTERCLAIM
 * IN A LAWSUIT) ALLEGING THAT THIS SOFTWARE (INCLUDING COMBINATIONS OF THE
 * SOFTWARE WITH OTHER SOFTWARE OR HARDWARE) INFRINGES SUCH SOFTWARE
 * RECIPIENT'S PATENT(S), THEN SUCH SOFTWARE RECIPIENT'S RIGHTS GRANTED BY
 * THIS LICENSE SHALL TERMINATE AS OF THE DATE SUCH LITIGATION IS FILED. IF
 * ANY PROVISION OF THIS AGREEMENT IS INVALID OR UNENFORCEABLE UNDER
 * APPLICABLE LAW, IT SHALL NOT AFFECT THE VALIDITY OR ENFORCEABILITY OF THE
 * REMAINDER OF THE TERMS OF THIS AGREEMENT, AND WITHOUT FURTHER ACTION
 * BY THE PARTIES HERETO, SUCH PROVISION SHALL BE REFORMED TO THE MINIMUM
 * EXTENT NECESSARY TO MAKE SUCH PROVISION VALID AND ENFORCEABLE. ALL
 * SOFTWARE RECIPIENT'S RIGHTS UNDER THIS AGREEMENT SHALL TERMINATE IF IT
 * FAILS TO COMPLY WITH ANY OF THE MATERIAL TERMS OR CONDITIONS OF THIS
 * AGREEMENT AND DOES NOT CURE SUCH FAILURE IN A REASONABLE PERIOD OF
 * TIME AFTER BECOMING AWARE OF SUCH NONCOMPLIANCE. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR  PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */



#ifndef OKCORE_H
#define OKCORE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <SoftTimer.h>
#include "base64.h"

/*************************************/
//Firmware Memory Locations
/*************************************/
// Factory Values
#define factorysectoradr 0x5800
// Last 512 bytes of factorysectoradr in use
// 0x0000_5E00 - 0x0000_6000
// okcrypto_split_sundae keys
#define banana    (uint8_t *) (factorysectoradr+1536)
#define ice_cream    (uint8_t *) (factorysectoradr+1536+32)
#define chocolate_syrup    (uint8_t *) (factorysectoradr+1536+64)
#define whipped_cream    (uint8_t *) (factorysectoradr+1536+96)
#define cherry_on_top    (uint8_t *) (factorysectoradr+1536+128)
// FIDO attestation key
#define encrypted_attestation_key    (uint8_t *) (factorysectoradr+1536+480)
#define attestation_kek    (uint8_t *) (factorysectoradr+1536+448)
#define attestation_kek_iv    (uint8_t *) (factorysectoradr+1536+436)

// TODO, enable factory config flag when factory keys are supported
#define factory_config_flag 0
// #define factory_config_flag    (uint8_t) (factorysectoradr+1536+435)
// #define attestation_cert_der_stored 0x3DC20
// Start of firmware
// 0x0000_6060 - 0x0003_A05F used for firmware (13 blocks of 16384 = 212992 bytes max size fw)
#define fwstartadr 0x6060
// Start of flash storage
// 0x0003_A800 - 0x0003_FFFF used for data storage 22528 bytes (11 sectors)
// Note: 1st free flash sector get wiped by bootloader on firmware load so can only be used for temp data
#define flashstorestart 0x3A800
// End of flash storage
#define flashend 0x3FFFF
/*************************************/
//Hardware CPU Restart
/*************************************/
#define CPU_RESTART_ADDR (uint32_t *)0xE000ED0C
#define CPU_RESTART_VAL 0x5FA0004
// Restart device
#define CPU_RESTART() (*CPU_RESTART_ADDR = CPU_RESTART_VAL);
/*************************************/
//Global Buffer Sizes
/*************************************/
#define LARGE_RESP_BUFFER_SIZE         1024
#define LARGE_BUFFER_SIZE         1024
#define PACKET_BUFFER_SIZE         768
#define ATTESTATION_DER_BUFFER_SIZE 768
#define KEYBOARD_BUFFER_SIZE         80
/*************************************/
//USB MSG Type assignments
/*************************************/
#define TYPE_INIT               0x80  // Initial frame identifier
#define OKPIN 			(TYPE_INIT | 0x61) 
#define OKPINSD			(TYPE_INIT | 0x62)
#define OKPINSEC 			(TYPE_INIT | 0x63)
#define OKCONNECT 			(TYPE_INIT | 0x64)
#define OKGETLABELS 		(TYPE_INIT | 0x65)
#define OKSETSLOT  			(TYPE_INIT | 0x66)
#define OKWIPESLOT  		(TYPE_INIT | 0x67)
// Removed custom U2F cert feature, msg types available for future new features
// #define OKSETU2FPRIV 		(TYPE_INIT | 0x68)
// #define OKWIPEU2FPRIV 		(TYPE_INIT | 0x69)
// #define OKSETU2FCERT 		(TYPE_INIT | 0x6A)
// #define OKWIPEU2FCERT  		(TYPE_INIT | 0x6B)
#define OKGETPUBKEY          (TYPE_INIT | 0x6C)
#define OKSIGN      (TYPE_INIT | 0x6D)
#define OKWIPEPRIV           (TYPE_INIT | 0x6E)
#define OKSETPRIV           (TYPE_INIT | 0x6F)
#define OKDECRYPT      (TYPE_INIT | 0x70)
#define OKRESTORE            (TYPE_INIT | 0x71)
#define OKGETRESPONSE            (TYPE_INIT | 0x72)
#define OKPING           (TYPE_INIT | 0x73)
#define OKFWUPDATE           (TYPE_INIT | 0x74)
#define OKHMAC           (TYPE_INIT | 0x75)
#define OKWEBAUTHN           (TYPE_INIT | 0x76)
/*************************************/
//ykpers BSD license
/*************************************/
#define	TKTFLAG_TAB_FIRST	0x01	/* Send TAB before first part */
#define	TKTFLAG_APPEND_TAB1	0x02	/* Send TAB after first part */
#define	TKTFLAG_APPEND_TAB2	0x04	/* Send TAB after second part */
#define	TKTFLAG_APPEND_DELAY1	0x08	/* Add 0.5s delay after first part */
#define	TKTFLAG_APPEND_DELAY2	0x10	/* Add 0.5s delay after second part */
#define	TKTFLAG_APPEND_CR	0x20	/* Append CR as final character */
#define TKTFLAG_PROTECT_CFG2	0x80	/* Block update of config 2 unless config 2 is configured and has this bit set */
#define SLOT_CHAL_OTP1		0x20	/* Write 6 byte challenge to slot 1, get Yubico OTP response */
#define SLOT_CHAL_OTP2		0x28	/* Write 6 byte challenge to slot 2, get Yubico OTP response */
#define CFGFLAG_SEND_REF	0x01	/* Send reference string (0..F) before data */
#define CFGFLAG_PACING_10MS	0x04	/* Add 10ms intra-key pacing */
#define CFGFLAG_PACING_20MS	0x08	/* Add 20ms intra-key pacing */
#define CFGFLAG_STATIC_TICKET	0x20	/* Static ticket generation */
#define EXTFLAG_SERIAL_BTN_VISIBLE	0x01	/* Serial number visible at startup (button press) */
#define EXTFLAG_SERIAL_USB_VISIBLE	0x02	/* Serial number visible in USB iSerial field */
#define EXTFLAG_SERIAL_API_VISIBLE	0x04	/* Serial number visible via API call */
/*************************************/
//Types of second profile
/*************************************/
#define STDPROFILE1 0
#define STDPROFILE2 1
#define NONENCRYPTEDPROFILE 2 //International Travel Edition or Plausible Deniability
/*************************************/
//Setup mode
/*************************************/
#define KEYBOARD_MANUAL_PIN_SET 1
#define KEYBOARD_AUTO_PIN_SET 2
#define SETUP_MANUAL 3
#define SETUP_AUTO 4
#define KEYBOARD_ONLYKEY_GO 5
#define KEYBOARD_ONLYKEY_GO_NO_BACKUP 6
/*************************************/
// Output Modes
/*************************************/
#define RAW_USB 0
#define WEBAUTHN 1
#define KEYBOARD_USB 3
#define DISCARD 4
/*************************************/
//Crypto Key Definitions
/*************************************/
#define MAX_RSA_KEY_SIZE 512
#define MAX_ECC_KEY_SIZE 32
#define RESERVED_KEY_DERIVATION 132
#define RESERVED_KEY_DEFAULT_BACKUP 131
#define RESERVED_KEY_HMACSHA1_1 130
#define RESERVED_KEY_HMACSHA1_2 129
#define RESERVED_KEY_WEB_DERIVATION 128
#define KEYTYPE_NACL 1
#define KEYTYPE_ED25519 1
#define KEYTYPE_P256R1 2
#define KEYTYPE_P256K1 3
#define KEYTYPE_CURVE25519 4
#define KEYTYPE_ECDH_P256R   102
#define KEYTYPE_ECDH_P256K   103
#define KEYTYPE_ECDH_CURVE25519  104

/*************************************/
/*************************************/
//Hardware Models
/*************************************/
#define SIM_SDID_PINID                  ((SIM_SDID & 0x000F) >> 0)      // Pincount identification

extern void colorWipe(int color, int wait);
extern int internal_temp ();
extern void recvmsg(int n);
extern void blink(int times);
extern void fadein();
extern void fadeout();
extern void printDigits(int digits);
extern void digitalClockDisplay();
extern void get_slot_labels (uint8_t output);
extern uint8_t get_key_labels (uint8_t output);
extern void okcore_quick_setup(uint8_t step);
extern void set_built_in_pin();
extern void set_time (uint8_t *buffer);
extern void wipe_slot (uint8_t *buffer);
extern void set_slot (uint8_t *buffer);
extern void set_primary_pin (uint8_t *buffer, uint8_t keyboard_mode);
extern void set_secondary_pin (uint8_t *buffer, uint8_t keyboard_mode);
extern void set_sd_pin (uint8_t *buffer, uint8_t keyboard_mode);
extern void set_private (uint8_t *buffer);
extern void wipe_private (uint8_t *buffer);
extern int ctap_flash (int index, uint8_t *buffer, int size, uint8_t mode);
extern void setOtherTimeout();
extern void processPacket(uint8_t *buffer);
extern void setCounter(uint32_t counter);
extern uint32_t getCounter();
extern void sendLargeResponse(uint8_t *request, int len);
extern void respondErrorPDU(uint8_t *buffer, int err);
extern int find_channel_index(int channel_id);
extern void errorResponse(uint8_t *buffer, int code);
extern int initResponse(uint8_t *buffer);
extern int allocate_channel(int channel_id);
extern int allocate_new_channel();
extern void cleanup_timeout();
extern int touch_sense_loop ();
extern uint32_t Wheel(uint8_t WheelPos);
extern void rngloop();
extern void printHex(const uint8_t *data, unsigned len);
extern void hidprint(char const * chars);
extern void keytype(char const * chars);
extern void byteprint(uint8_t* bytes, int size);
extern void factorydefault();
extern void wipeEEPROM();
extern void wipeflashdata();
extern bool unlocked;
extern bool initialized;
extern bool configmode;
extern bool PDmode;
extern int pin_set;
extern int u2f_button;
extern int large_buffer_offset;

extern void okcore_flashset_2ndpinhashpublic (uint8_t *ptr);
extern int okcore_flashget_2ndpinhashpublic (uint8_t *ptr);
extern void okcore_flashset_selfdestructhash (uint8_t *ptr);
extern int okcore_flashget_selfdestructhash (uint8_t *ptr);
extern void okcore_flashset_pinhashpublic (uint8_t *ptr);
extern int okcore_flashget_pinhashpublic (uint8_t *ptr, int size);
extern void okcore_flashset_noncehash (uint8_t *ptr);
extern int okcore_flashget_noncehash (uint8_t *ptr, int size);
extern int okcore_flashget_profilekey (uint8_t *ptr);
extern void okcore_flashset_profilekey (uint8_t *secret);
extern void okcore_flashset_common (uint8_t *ptr, unsigned long *adr, int len);
extern void okcore_flashget_common (uint8_t *ptr, unsigned long *adr, int len);
extern void okcore_flashsector(uint8_t *ptr, unsigned long *adr, int len);
extern int okcore_flashget_2fa_key (uint8_t *ptr, int slot);
extern void okcore_flashset_2fa_key (uint8_t *ptr, int size, int slot);
extern void okcore_flashset_yubiotp(uint8_t *ptr, uint8_t slot);
extern void okcore_flashget_yubiotp(uint8_t *ptr, uint8_t slot);
extern int okcore_flashget_username (uint8_t *ptr, int slot);
extern void okcore_flashset_username (uint8_t *ptr, int size, int slot);
extern int okcore_flashget_url (uint8_t *ptr, int slot);
extern void okcore_flashset_url (uint8_t *ptr, int size, int slot);
extern void okcore_flashget_label (uint8_t *ptr, uint8_t slot);
extern void okcore_flashset_label (uint8_t *ptr, uint8_t slot);
extern int okcore_flashget_ECC (uint8_t slot);
extern int okcore_flashget_RSA (uint8_t slot);
void okcore_aes_gcm_encrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len);
void okcore_aes_gcm_decrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len);
void okcore_aes_cbc_decrypt (uint8_t * state, const uint8_t * key, int len);
void okcore_aes_cbc_encrypt (uint8_t * state, const uint8_t * key, int len);
void okcore_pin_login ();

extern void yubikeyinit(uint8_t slot);
extern int yubikeysim(char *ptr, uint8_t slot);
extern void yubikey_incr_time();
extern void increment(Task* me);
extern void decrement(Task* me);
extern bool wipebuffersafter5sec(Task* me);
extern bool fadeoffafter20sec(Task* me);
extern bool fadeendafter2sec(Task* me);
extern void typeoutbackup(Task* me);
extern void wipedata();
extern void wipetasks();
extern void fadeoffafter20();
extern void cancelfadeoffafter20();
extern void fadeoff(uint8_t color);
extern void fadeon(uint8_t color);
extern void rainbowCycle();
extern void initColor();
extern void setcolor (uint8_t Color);
extern void backup();
extern void rsa_priv_flash (uint8_t *buffer, bool wipe);
extern void ecc_priv_flash (uint8_t *buffer);
extern void flash_modify (int index, uint8_t *sector, uint8_t *data, int size, bool wipe);
extern void RESTORE (uint8_t *buffer);
extern void process_packets (uint8_t *buffer, int len, uint8_t *blocknum);
extern void done_process_packets ();
extern void done_process_single ();
extern void send_transport_response (uint8_t* data, int len, uint8_t encrypt, uint8_t store);
extern void apdu_data(uint8_t *data, int len);
extern int store_keyboard_response();
extern void changeoutputmode(uint8_t mode);
extern int RNG2(uint8_t *dest, unsigned size);
extern int calibratecaptouch (uint16_t j);
extern void process_setreport ();
extern void generate_random_pin (uint8_t *buffer);
extern void generate_random_passphrase (uint8_t *buffer);
extern int check_crc(uint8_t* buffer);
extern char * HW_MODEL(char const * in);
extern void ByteToChar2(uint8_t *bytes, char *chars, unsigned int count, unsigned int index);
extern void fw_version_changes();

#ifdef __cplusplus
}
#endif
#endif
