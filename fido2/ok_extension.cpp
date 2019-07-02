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
#include "wallet.h"
//#include APP_CONFIG
#include "ctap.h"
#include "ctap_errors.h"
#include "crypto.h"
#include "u2f.h"
#include "log.h"
#include "util.h"
#include "storage.h"
#include "device.h"
#include "extensions.h"
#include "ok_extension.h"
#include "oku2f.h"

extern uint8_t* large_resp_buffer;
extern int large_resp_buffer_offset;
extern uint8_t profilemode;
extern uint8_t isfade;
extern uint8_t NEO_Color;
extern uint8_t type;
extern int outputmode;
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE*2)+1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
extern uint8_t recv_buffer[64];
extern uint8_t pending_operation;
extern int packet_buffer_offset;

const char stored_appid[] = "\xEB\xAE\xE3\x29\x09\x0A\x5B\x51\x92\xE0\xBD\x13\x2D\x5C\x22\xC6\xD1\x8A\x4D\x23\xFC\x8E\xFD\x4A\x21\xAF\xA8\xE4\xC8\xFD\x93\x54";

int16_t bridge_to_onlykey(uint8_t * _appid, uint8_t * keyh, int handle_len, uint8_t * output)
{
    int appid_match;
    int8_t ret = 0;
	uint8_t *client_handle = keyh+10;
	handle_len-=10;
	uint8_t cmd = keyh[0];
	uint8_t opt1 = keyh[1];
	uint8_t opt2 = keyh[2];
	uint8_t opt3 = keyh[3];

    appid_match = memcmp (stored_appid, _appid, 32);
    Serial.println("App ID:");
    byteprint(_appid, 32);
    Serial.println("Stored App ID:");
    byteprint((uint8_t*)stored_appid, 32);
    Serial.println("Keyhandle:");
    byteprint(client_handle, handle_len);

    if (appid_match == 0) { // Only allow crp.to and localhost
      outputmode=DISCARD; // Discard output 
      //Todo add localhost support
		if (cmd == OKSETTIME && !CRYPTO_AUTH) {
			if(profilemode!=NONENCRYPTEDPROFILE) {
			#ifdef STD_VERSION
			large_buffer_offset = 0;
			set_time(client_handle);
			memset(ecc_public_key, 0, sizeof(ecc_public_key));
			crypto_box_keypair(ecc_public_key+sizeof(UNLOCKED), ecc_private_key); //Generate keys
			#ifdef DEBUG
			Serial.println("OnlyKey public = ");
			byteprint(ecc_public_key+sizeof(UNLOCKED), 32);
			#endif
			memcpy(ecc_public_key, UNLOCKED, sizeof(UNLOCKED));
			outputmode=WEBAUTHN;
			send_transport_response (ecc_public_key, 32+sizeof(UNLOCKED), false, false); //Don't encrypt and send right away
			memcpy(ecc_public_key, client_handle+9, 32); //Get app public key
			#ifdef DEBUG
			Serial.println("App public = ");
			byteprint(ecc_public_key, 32);
			#endif
			uint8_t shared[32];
			type = 1;
			if (shared_secret (ecc_public_key, shared)) {
			ret = CTAP2_ERR_OPERATION_DENIED;
			printf2(TAG_ERR,"Error with ECC Shared Secret\n");
			return ret;
			}
			#ifdef DEBUG
			Serial.println("Shared Secret = ");
			byteprint(shared, 32);
			#endif
			SHA256_CTX context;
			sha256_init(&context);
			sha256_update(&context, shared, 32);
			sha256_final(&context, ecc_private_key);
			#ifdef DEBUG
			Serial.println("AES Key = ");
			byteprint(ecc_private_key, 32);
			#endif
			#endif
			}
		} else {
			//aes_crypto_box (client_handle, 64, true);
			#ifdef DEBUG
			Serial.println("Decrypted client handle");
			byteprint(client_handle, handle_len);
			Serial.println("Received FIDO2 request to send data to OnlyKey");
			#endif

			if(profilemode!=NONENCRYPTEDPROFILE) {
			#ifdef STD_VERSION
			if (cmd == OKPING) { //Ping
				outputmode=WEBAUTHN;
				if(!CRYPTO_AUTH && !large_resp_buffer_offset) {
					Serial.println("Error incorrect challenge was entered");
					hidprint("Error incorrect challenge was entered");
				} else {
					Serial.println("Sending stored data from ping request");
				}
			}
			// Break the FIDO message into packets
			else if (!CRYPTO_AUTH) {
				int i=0;
				while(handle_len>0) { // Max size packet minus header
					memset(recv_buffer, 0, sizeof(recv_buffer));
					if (handle_len>=57) memmove(recv_buffer+7, client_handle+(i*57), 57);
					else memmove(recv_buffer+7, client_handle+(i*57), handle_len);
					memset(recv_buffer, 0xFF, 4);
					recv_buffer[4] = cmd;
					recv_buffer[5] = opt1; //slot
					recv_buffer[6] = 0xFF;
					if (opt2 && handle_len<=57) recv_buffer[6] = handle_len;
					if (cmd == OKDECRYPT) {
						NEO_Color = 128; //Turquoise
						large_buffer_offset = 0;
						outputmode=WEBAUTHN;
						Serial.println("OKDECRYPT Chunk");
						byteprint(recv_buffer, 64);
						DECRYPT(recv_buffer);
					} else if (cmd == OKSIGN) {
						NEO_Color = 213; //Purple
						large_buffer_offset = 0;
						outputmode=WEBAUTHN;
						Serial.println("OKSIGN Chunk");
						byteprint(recv_buffer, 64);
						SIGN(recv_buffer);
					}
					handle_len-=57;
					i++;
				}
				ret = 0;
				}
			#endif
			}
		}
		ret = send_stored_response(output);
		return ret;
			
		//if (!isfade) fadeon(NEO_Color);
	} 

    ret = CTAP2_ERR_EXTENSION_NOT_SUPPORTED; //APPID doesn't match
    wipedata();
    return ret;
}

int16_t send_stored_response(uint8_t * output) {
  int16_t ret = 0;
	if(profilemode!=NONENCRYPTEDPROFILE) {
		#ifdef DEBUG
		Serial.println("Sending data on OnlyKey via Webauthn");
		byteprint(large_resp_buffer, large_resp_buffer_offset);
		Serial.println(large_resp_buffer_offset);
		#endif
    // Check if large response is ready
		if (pending_operation==CTAP2_ERR_OPERATION_PENDING) {
			#ifdef DEBUG
			Serial.print("CTAP2_ERR_OPERATION_PENDING");
			#endif
			ret = CTAP2_ERR_OPERATION_PENDING;
		} else if (large_resp_buffer_offset) {
			#ifdef STD_VERSION
			extension_writeback_init(output, large_resp_buffer_offset);
			extension_writeback(large_resp_buffer, large_resp_buffer_offset);
			memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
			#endif
		} else if (CRYPTO_AUTH || packet_buffer_offset) {
			Serial.println("Ping success");
			memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
			ret = CTAP2_ERR_USER_ACTION_PENDING;
		} else if (!CRYPTO_AUTH) {
			#ifdef DEBUG
			Serial.print("Error no data ready to be retrieved");
			#endif
			//custom_error(6);
      		ret = CTAP2_ERR_NO_OPERATION_PENDING;
			fadeoff(1);
		}
		return ret; 
	}
}
