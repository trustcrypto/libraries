/* onlykey.h
*/

/*
 * Modifications by Tim Steiner
 * Copyright (c) 2016 , CryptoTrust LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *Original 
 *Copyright (c) 2015, Yohanes Nugroho
 *All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 *Redistributions in binary form must reproduce the above copyright notice,
 *this list of conditions and the following disclaimer in the documentation
 *and/or other materials provided with the distribution.
 *
 *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 

#ifndef ONLYKEY_H
#define ONLYKEY_H

#ifdef __cplusplus
extern "C"
{
#endif

#define DEBUG
#define CID_BROADCAST           0xffffffff  // Broadcast channel id
#define TYPE_MASK               0x80  // Frame type mask
#define TYPE_INIT               0x80  // Initial frame identifier
#define TYPE_CONT               0x00  // Continuation frame identifier

#define U2FHID_PING         (TYPE_INIT | 0x01)  // Echo data through local processor only
#define U2FHID_MSG          (TYPE_INIT | 0x03)  // Send U2F message frame
#define U2FHID_LOCK         (TYPE_INIT | 0x04)  // Send lock channel command
#define U2FHID_INIT         (TYPE_INIT | 0x06)  // Channel initialization
#define U2FHID_WINK         (TYPE_INIT | 0x08)  // Send device identification wink
#define U2FHID_ERROR        (TYPE_INIT | 0x3f)  // Error response

#define OKSETPIN 			(TYPE_INIT | 0x61)  // First vendor defined command
#define OKSETSDPIN 			(TYPE_INIT | 0x62)  // First vendor defined command
#define OKSETPDPIN 			(TYPE_INIT | 0x63)  // First vendor defined command
#define OKSETTIME 			(TYPE_INIT | 0x64)  // 
#define OKGETLABELS 		(TYPE_INIT | 0x65)  //
#define OKSETSLOT  			(TYPE_INIT | 0x66)  // 
#define OKWIPESLOT  		(TYPE_INIT | 0x67)  // 
#define OKSETU2FPRIV 		(TYPE_INIT | 0x68)  // 
#define OKWIPEU2FPRIV 		(TYPE_INIT | 0x69)  // 
#define OKSETU2FCERT 		(TYPE_INIT | 0x6A)  // 
#define OKWIPEU2FCERT  		(TYPE_INIT | 0x6B)  // Last vendor defined command

// Errors
#define ERR_NONE  0
#define ERR_INVALID_CMD  1
#define ERR_INVALID_PAR  2
#define ERR_INVALID_LEN  3
#define ERR_INVALID_SEQ  4
#define ERR_MSG_TIMEOUT  5
#define ERR_CHANNEL_BUSY  6
#define ERR_LOCK_REQUIRED  10
#define ERR_INVALID_CID  11
#define ERR_OTHER  127

#define U2F_INS_REGISTER  0x01
#define U2F_INS_AUTHENTICATE  0x02
#define U2F_INS_VERSION  0x03

#define STATE_CHANNEL_AVAILABLE 0
#define STATE_CHANNEL_WAIT_PACKET 1
#define STATE_CHANNEL_WAIT_CONT 2
#define STATE_CHANNEL_TIMEOUT 3
#define STATE_LARGE_PACKET 4

#define MAX_TOTAL_PACKET 7609
#define MAX_INITIAL_PACKET 57
#define MAX_CONTINUATION_PACKET 59
#define SET_MSG_LEN(b, v) do { (b)[5] = ((v) >> 8) & 0xff;  (b)[6] = (v) & 0xff; } while(0)

#define CERTMAXLENGTH       1024  // Make sure size of certificate is limited so that the whole flash is not overwritten

#define U2FHID_IF_VERSION       2  // Current interface implementation version
#define MAX_CHANNEL 4
#define TIMEOUT_VALUE 1000

#define IS_CONTINUATION_PACKET(x) ( (x) < 0x80)
#define IS_NOT_CONTINUATION_PACKET(x) ( (x) >= 0x80)

#define SW_NO_ERROR                       0x9000
#define SW_CONDITIONS_NOT_SATISFIED       0x6985
#define SW_WRONG_DATA                     0x6A80
#define SW_WRONG_LENGTH                     0x6700
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00

#define APPEND_SW(x, v1, v2) do { (*x++)=v1; (*x++)=v2;} while (0)
#define APPEND_SW_NO_ERROR(x) do { (*x++)=0x90; (*x++)=0x00;} while (0)
	
#define TIMEOUT_VALUE 1000

extern void recvmsg();
extern void blink(int times);
extern int RNG2(uint8_t *dest, unsigned size);
extern void printDigits(int digits);
extern void digitalClockDisplay();
extern void GETLABELS (byte *buffer);
extern void SETTIME (byte *buffer);
extern void WIPEU2FCERT (byte *buffer);
extern void SETU2FCERT (byte *buffer);
extern void WIPEU2FPRIV (byte *buffer);
extern void SETU2FPRIV (byte *buffer);
extern void WIPESLOT (byte *buffer);
extern void SETSLOT (byte *buffer);
extern void SETPIN (byte *buffer);
extern void SETPDPIN (byte *buffer);
extern void SETSDPIN (byte *buffer);
extern void setOtherTimeout();
extern void processPacket(byte *buffer);
extern void setCounter(int counter);
extern int getCounter();
extern void sendLargeResponse(byte *request, int len);
extern void respondErrorPDU(byte *buffer, int err);
extern int find_channel_index(int channel_id);
extern void errorResponse(byte *buffer, int code);
extern int initResponse(byte *buffer);
extern int allocate_channel(int channel_id);
extern int allocate_new_channel();
extern void cleanup_timeout();
extern void getrng(uint8_t *ptr, unsigned size);
extern void printHex(const byte *data, unsigned len);
extern void ByteToChar(byte* bytes, char* chars, unsigned int count);
extern void CharToByte(char* chars, byte* bytes, unsigned int count);
extern void ByteToChar2(byte* bytes, char* chars, unsigned int count, unsigned int index);
extern void CharToByte2(char* chars, byte* bytes, unsigned int count, unsigned int index);
extern void hidprint(char* chars);
extern void factorydefault();
extern bool unlocked;
extern bool initialized;
extern bool PDmode;
extern int PINSET;
extern int u2f_button;
extern void aes_gcm_encrypt (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);
extern int aes_gcm_decrypt (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len);

#ifdef __cplusplus
}
#endif
#endif
