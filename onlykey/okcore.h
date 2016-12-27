/* okcore.h
*/

/* Tim Steiner
 * Copyright (c) 2016 , CryptoTrust LLC.
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
 *    "This product includes software developed by the OnlyKey Project
 *    (http://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "OnlyKey Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" appear in their names without prior written
 *    permission of the OnlyKey Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OnlyKey Project
 *    (http://www.crp.to/ok)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OnlyKey PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OnlyKey PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 

#ifndef OKCORE_H
#define OKCORE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <SoftTimer.h>

#define TYPE_INIT               0x80  // Initial frame identifier
/*************************************/
//Vendor Defined OnlyKey MSG Type assignments
/*************************************/
#define OKSETPIN 			(TYPE_INIT | 0x61)  // First vendor defined command
#define OKSETSDPIN 			(TYPE_INIT | 0x62)  // 
#define OKSETPDPIN 			(TYPE_INIT | 0x63)  // 
#define OKSETTIME 			(TYPE_INIT | 0x64)  // 
#define OKGETLABELS 		(TYPE_INIT | 0x65)  //
#define OKSETSLOT  			(TYPE_INIT | 0x66)  // 
#define OKWIPESLOT  		(TYPE_INIT | 0x67)  // 
#define OKSETU2FPRIV 		(TYPE_INIT | 0x68)  // 
#define OKWIPEU2FPRIV 		(TYPE_INIT | 0x69)  // 
#define OKSETU2FCERT 		(TYPE_INIT | 0x6A)  // 
#define OKWIPEU2FCERT  		(TYPE_INIT | 0x6B)  //
#define OKGETECCPUBKEY          (TYPE_INIT | 0x6C)//
#define OKSIGNECCCHALLENGE      (TYPE_INIT | 0x6D)//
#define OKWIPEECCPRIV           (TYPE_INIT | 0x6E)//
#define OKSETECCPRIV            (TYPE_INIT | 0x6F)// 
#define OKGETRSAPUBKEY          (TYPE_INIT | 0x70)//
#define OKSIGNRSACHALLENGE      (TYPE_INIT | 0x71)//
#define OKWIPERSAPRIV           (TYPE_INIT | 0x72)//
#define OKSETRSAPRIV            (TYPE_INIT | 0x73)// Last vendor defined command


extern int getCounter();
extern void setCounter(int counter);
extern void ByteToChar(uint8_t* bytes, char* chars, unsigned int count);
extern void CharToByte(char* chars, uint8_t* bytes, unsigned int count);
extern void ByteToChar2(uint8_t* bytes, char* chars, unsigned int count, unsigned int index);
extern void CharToByte2(char* chars, uint8_t* bytes, unsigned int count, unsigned int index);
extern void recvmsg();
extern void blink(int times);
extern void fadein();
extern void fadeout();
extern void printDigits(int digits);
extern void digitalClockDisplay();
extern void GETLABELS (uint8_t *buffer);
extern void SETTIME (uint8_t *buffer);
extern void WIPEU2FCERT (uint8_t *buffer);
extern void SETU2FCERT (uint8_t *buffer);
extern void WIPEU2FPRIV (uint8_t *buffer);
extern void SETU2FPRIV (uint8_t *buffer);
extern void WIPESLOT (uint8_t *buffer);
extern void SETSLOT (uint8_t *buffer);
extern void SETPIN (uint8_t *buffer);
extern void SETPDPIN (uint8_t *buffer);
extern void SETSDPIN (uint8_t *buffer);
extern void setOtherTimeout();
extern void processPacket(uint8_t *buffer);
extern void setCounter(int counter);
extern int getCounter();
extern void sendLargeResponse(uint8_t *request, int len);
extern void respondErrorPDU(uint8_t *buffer, int err);
extern int find_channel_index(int channel_id);
extern void errorResponse(uint8_t *buffer, int code);
extern int initResponse(uint8_t *buffer);
extern int allocate_channel(int channel_id);
extern int allocate_new_channel();
extern void cleanup_timeout();
extern void rngloop();
extern int RNG2(uint8_t *dest, unsigned size);
extern void printHex(const uint8_t *data, unsigned len);
extern void hidprint(char const * chars);
extern void factorydefault();
extern void wipeEEPROM();
extern void wipeflash();
extern bool unlocked;
extern bool initialized;
extern bool PDmode;
extern int PINSET;
extern int u2f_button;
extern void aes_gcm_encrypt (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);
extern void aes_gcm_decrypt (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);
extern void aes_gcm_encrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);
extern void aes_gcm_decrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);
extern int onlykey_eeget_noncehash (uint8_t *ptr, int size);
extern void onlykey_eeset_noncehash (uint8_t *ptr);
extern int onlykey_eeget_pinhash (uint8_t *ptr, int size);
extern void onlykey_eeset_pinhash (uint8_t *ptr); 
extern int onlykey_eeget_selfdestructhash (uint8_t *ptr);
extern void onlykey_eeset_selfdestructhash (uint8_t *ptr);
extern int onlykey_eeget_plausdenyhash (uint8_t *ptr);
extern void onlykey_eeset_plausdenyhash (uint8_t *ptr);
extern void onlykey_flashset_plausdenyhash (uint8_t *ptr);
extern int onlykey_flashget_plausdenyhash (uint8_t *ptr);
extern void onlykey_flashset_selfdestructhash (uint8_t *ptr);
extern int onlykey_flashget_selfdestructhash (uint8_t *ptr);
extern void onlykey_flashset_pinhash (uint8_t *ptr);
extern int onlykey_flashget_pinhash (uint8_t *ptr, int size);
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
extern int onlykey_flashget_ECC (int slot);
extern int onlykey_flashget_RSA (int slot);
extern void yubikeyinit();
extern void yubikeysim(char *ptr);
extern void yubikey_incr_time();
extern void increment(Task* me);
extern void decrement(Task* me);
extern void typeoutbackup(Task* me);
extern void fadeoff();
extern void backupslots();
extern void backupkeys();

#ifdef __cplusplus
}
#endif
#endif
