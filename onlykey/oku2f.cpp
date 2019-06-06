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

#include "oku2f.h"
#include <SoftTimer.h>
#include <okcore.h>
#include "Time.h"

#ifdef US_VERSION

/*************************************/
//FIDO2 assignments
/*************************************/
extern uint16_t attestation_cert_der_size;
extern uint8_t attestation_key[33];
extern uint16_t attestation_key_size;
extern uint8_t attestation_cert_der[768];

/*************************************/
//U2F Assignments
/*************************************/

extern uint8_t expected_next_packet;
extern int large_buffer_offset;
extern uint8_t* large_resp_buffer;
int large_resp_buffer_offset;
extern int packet_buffer_offset;
extern uint8_t*  packet_buffer;
extern uint8_t recv_buffer[64];
extern uint8_t resp_buffer[64];
uint8_t handle[64];
extern char attestation_pub[66];
extern char attestation_priv[33];
extern char attestation_der[768];
extern uint8_t nonce[32];
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE*2)+1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
extern uint8_t type;
uint8_t times = 0;
int msgcount = 0;
bool isFirefox;
extern uint8_t NEO_Color;

// OLD U2F, FIDO2 uses different appid
//const char stored_appid[] = "\x23\xCD\xF4\x07\xFD\x90\x4F\xEE\x8B\x96\x40\x08\xB0\x49\xC5\x5E\xA8\x81\x13\x36\xA3\xA5\x17\x1B\x58\xD6\x6A\xEC\xF3\x79\xE7\x4A";

const char stored_appid[] = "\xEB\xAE\xE3\x29\x09\x0A\x5B\x51\x92\xE0\xBD\x13\x2D\x5C\x22\xC6\xD1\x8A\x4D\x23\xFC\x8E\xFD\x4A\x21\xAF\xA8\xE4\xC8\xFD\x93\x54";
uint8_t handlekey[32] = {0};
uint8_t apphandlekey[32] = {0};

extern uint8_t profilemode;

int u2f_button = 0;

void U2Finit()
{
  uint8_t length[2];
  device_init();
  onlykey_eeget_U2Fcertlen(length);
  int length2 = length[0] << 8 | length[1];
  if (length2 != 0) {
  extern uint16_t attestation_cert_der_size;
  attestation_cert_der_size=length2;
  onlykey_flashget_U2F();
  } else {
  byteprint((uint8_t*)attestation_key,sizeof(attestation_key));
  byteprint((uint8_t*)attestation_cert_der,sizeof(attestation_cert_der));
  }
  DERIVEKEY(0 , (uint8_t*)attestation_key); //Derive key from default key in slot 32
  memcpy(handlekey, ecc_private_key, 32); // Copy derived key to handlekey
  SHA256_CTX APPKEY;
  sha256_init(&APPKEY);
  sha256_update(&APPKEY, (uint8_t*)attestation_cert_der+(profilemode*32), 32); //Separate U2F key for profile 1 and 2
  sha256_update(&APPKEY, (uint8_t*)attestation_key, 32);
  sha256_update(&APPKEY, handlekey, 32);
  sha256_final(&APPKEY, apphandlekey); // Derivation key for app IDs
#ifdef DEBUG
  Serial.println("HANDLE KEY =");
  byteprint(handlekey, 32);
#endif
}

void fido_msg_timeout(uint8_t *buffer) {
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
void update_SHA256(const uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, message_size);
}
void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}

void store_FIDO_response (uint8_t *data, int len, bool encrypt) {
	if (strcmp((char*)data, "Error")) CRYPTO_AUTH = 0;
	cancelfadeoffafter20();
  if (len >= (int)LARGE_RESP_BUFFER_SIZE) return; //Double check buf overflow
	large_resp_buffer_offset = len;
	if (encrypt) {
	//	aes_crypto_box (data, len, false);
	}
	if (len < 64) {
		uint8_t tempdata[64];
		memmove( tempdata, data, len);
		data = tempdata+len;
		RNG2(data, 64-len); //Store a random number in key handle empty space
		data = tempdata;
		len = 64;
	}
  memmove(large_resp_buffer, data, len);
#ifdef DEBUG
      Serial.print ("Stored Data for FIDO Response");
	  byteprint(large_resp_buffer, large_resp_buffer_offset);
#endif
	 wipedata(); //Data will wait 5 seconds to be retrieved
}


#endif
