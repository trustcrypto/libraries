/* Tim Steiner
 * Copyright (c) 2015-2018, CryptoTrust LLC.
 * All rights reserved.
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
 *    the OnlyKey Project (http://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "OnlyKey Project" must not be used to
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
 *    the OnlyKey Project (http://www.crp.to/ok)"
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

// Start of firmware
#define fwstartadr 0x6060
// Start of flash storage
#define flashstorestart 0x3B000
// End of flash storage
#define flashend 0x3FFFF
#define CPU_RESTART_ADDR (uint32_t *)0xE000ED0C
#define CPU_RESTART_VAL 0x5FA0004
// Restart device
#define CPU_RESTART() (*CPU_RESTART_ADDR = CPU_RESTART_VAL);

#define LARGE_RESP_BUFFER_SIZE         1024
#define LARGE_BUFFER_SIZE         1024
#define PACKET_BUFFER_SIZE         768
#define KEYBOARD_BUFFER_SIZE         80

#define TYPE_INIT               0x80  // Initial frame identifier
/*************************************/
//Vendor Defined OnlyKey MSG Type assignments
/*************************************/
#define OKSETPIN 			(TYPE_INIT | 0x61)  // First vendor defined command
#define OKSETSDPIN 			(TYPE_INIT | 0x62)
#define OKSETPDPIN 			(TYPE_INIT | 0x63)
#define OKSETTIME 			(TYPE_INIT | 0x64)
#define OKGETLABELS 		(TYPE_INIT | 0x65)
#define OKSETSLOT  			(TYPE_INIT | 0x66)
#define OKWIPESLOT  		(TYPE_INIT | 0x67)
#define OKSETU2FPRIV 		(TYPE_INIT | 0x68)
#define OKWIPEU2FPRIV 		(TYPE_INIT | 0x69)
#define OKSETU2FCERT 		(TYPE_INIT | 0x6A)
#define OKWIPEU2FCERT  		(TYPE_INIT | 0x6B)
#define OKGETPUBKEY          (TYPE_INIT | 0x6C)
#define OKSIGN      (TYPE_INIT | 0x6D)
#define OKWIPEPRIV           (TYPE_INIT | 0x6E)
#define OKSETPRIV           (TYPE_INIT | 0x6F)
#define OKDECRYPT      (TYPE_INIT | 0x70)//
#define OKRESTORE            (TYPE_INIT | 0x71)
#define OKGETRESPONSE            (TYPE_INIT | 0x72)
#define OKPING           (TYPE_INIT | 0x73)
#define OKFWUPDATE           (TYPE_INIT | 0x74)

/*************************************/
//Types of second profile
/*************************************/
#define STDPROFILE1 0
#define STDPROFILE2 1
#define NONENCRYPTEDPROFILE 2 //International Travel Edition or Plausible Deniability

/*************************************/
//Keyboard setup mode
/*************************************/
#define MANUAL_PIN_SET 1
#define AUTO_PIN_SET 2

// Last vendor defined command

extern void ByteToChar(uint8_t* bytes, char* chars, unsigned int count);
extern void CharToByte(char* chars, uint8_t* bytes, unsigned int count);
extern void ByteToChar2(uint8_t* bytes, char* chars, unsigned int count, unsigned int index);
extern void CharToByte2(char* chars, uint8_t* bytes, unsigned int count, unsigned int index);
extern void recvmsg(int n);
extern void blink(int times);
extern void fadein();
extern void fadeout();
extern void printDigits(int digits);
extern void digitalClockDisplay();
extern void get_slot_labels (uint8_t output);
extern uint8_t get_key_labels (uint8_t output);
extern void keyboard_mode_config(uint8_t step);
extern void set_time (uint8_t *buffer);
extern void wipe_u2f_cert (uint8_t *buffer);
extern void set_u2f_cert (uint8_t *buffer);
extern void wipe_u2f_priv (uint8_t *buffer);
extern void set_u2f_priv (uint8_t *buffer);
extern void wipe_slot (uint8_t *buffer);
extern void set_slot (uint8_t *buffer);
extern void set_primary_pin (uint8_t *buffer, uint8_t keyboard_mode);
extern void set_secondary_pin (uint8_t *buffer, uint8_t keyboard_mode);
extern void set_sd_pin (uint8_t *buffer, uint8_t keyboard_mode);
extern void set_private (uint8_t *buffer);
extern void wipe_private (uint8_t *buffer);
extern void ctap_flash (int index, uint8_t *buffer, int size, uint8_t mode);
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

extern void aes_gcm_encrypt (uint8_t * state, uint8_t slot, uint8_t value, const uint8_t * key, int len);
extern void aes_gcm_decrypt (uint8_t * state, uint8_t slot, uint8_t value, const uint8_t * key, int len);
extern void aes_gcm_encrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);
extern void aes_gcm_decrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);
extern void aes_cbc_encrypt (uint8_t * state, const uint8_t * key, int len);
extern void aes_cbc_decrypt (uint8_t * state, const uint8_t * key, int len);
extern void onlykey_flashset_2ndpinhashpublic (uint8_t *ptr);
extern int onlykey_flashget_2ndpinhashpublic (uint8_t *ptr);
extern void onlykey_flashset_selfdestructhash (uint8_t *ptr);
extern int onlykey_flashget_selfdestructhash (uint8_t *ptr);
extern void onlykey_flashset_pinhashpublic (uint8_t *ptr);
extern int onlykey_flashget_pinhashpublic (uint8_t *ptr, int size);
extern void onlykey_flashset_noncehash (uint8_t *ptr);
extern int onlykey_flashget_noncehash (uint8_t *ptr, int size);
extern void onlykey_flashset_common (uint8_t *ptr, uintptr_t adr, int len);
extern void onlykey_flashget_common (uint8_t *ptr, uintptr_t adr, int len);
extern int onlykey_flashget_totpkey (uint8_t *ptr, int slot);
extern void onlykey_flashset_totpkey (uint8_t *ptr, int size, int slot);
extern int onlykey_flashget_username (uint8_t *ptr, int slot);
extern void onlykey_flashset_username (uint8_t *ptr, int size, int slot);
extern int onlykey_flashget_url (uint8_t *ptr, int slot);
extern void onlykey_flashset_url (uint8_t *ptr, int size, int slot);
extern void onlykey_flashget_label (uint8_t *ptr, int slot);
extern void onlykey_flashset_label (uint8_t *ptr, int slot);
extern void onlykey_flashget_U2F ();
extern int onlykey_flashget_ECC (uint8_t slot);
extern int onlykey_flashget_RSA (uint8_t slot);
extern void yubikeyinit();
extern void yubikeysim(char *ptr);
extern void yubikey_incr_time();
extern void increment(Task* me);
extern void decrement(Task* me);
extern bool wipebuffersafter5sec(Task* me);
extern bool fadeoffafter20sec(Task* me);
extern bool fadeendafter2sec(Task* me);
extern void typeoutbackup(Task* me);
extern void wipedata();
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
extern void apdu_data(uint8_t *data, int len, bool first);
extern void temp_voltage ();
extern int RNG2(uint8_t *dest, unsigned size);
extern int calibratecaptouch (uint16_t j);
extern void process_setreport ();
extern void generate_random_pin (uint8_t *buffer);
extern void generate_random_passphrase (uint8_t *buffer);

#ifdef __cplusplus
}
#endif
#endif
