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

#include "device.h"
#include "onlykey.h"
#ifdef STD_VERSION
#include "log.h"
#include "wallet.h"
//#include APP_CONFIG
#include "util.h"
#include "storage.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "crypto.h"
#include "u2f.h"
#include "extensions.h"
#include "ok_extension.h"




extern uint8_t* large_resp_buffer;
extern int large_resp_buffer_offset;
extern uint8_t profilemode;
extern uint8_t isfade;
extern uint8_t NEO_Color;
extern uint8_t type;
extern uint8_t CRYPTO_AUTH;
extern int outputmode;
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE*2)+1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
extern uint8_t recv_buffer[64];
extern uint8_t pending_operation;
extern int packet_buffer_offset;

const char stored_appid[] = "\xEB\xAE\xE3\x29\x09\x0A\x5B\x51\x92\xE0\xBD\x13\x2D\x5C\x22\xC6\xD1\x8A\x4D\x23\xFC\x8E\xFD\x4A\x21\xAF\xA8\xE4\xC8\xFD\x93\x54";
//const char stored_appid_u2f[] = "\x23\xCD\xF4\x07\xFD\x90\x4F\xEE\x8B\x96\x40\x08\xB0\x49\xC5\x5E\xA8\x81\x13\x36\xA3\xA5\x17\x1B\x58\xD6\x6A\xEC\xF3\x79\xE7\x4A";
//const char stored_clientDataHash[] = "\x57\x81\xAF\x14\xB9\x71\x6D\x87\x24\x61\x8E\x8A\x6F\xD6\x50\xEB\x6B\x02\x6B\xEC\x6B\xAD\xB3\xB1\xA3\x01\xAA\x0D\x75\xF6\x0C\x14";
//const char stored_clientDataHash_u2f[] = "\x78\x4E\x39\xF2\xDA\xF8\xE6\xA4\xBB\xD7\x15\x0D\x39\x34\xCC\x81\x5F\x6E\xE7\x6F\x57\xBC\x02\x6A\x0E\x49\x33\x13\xF4\x36\x63\x47"; 
const char stored_apprpid[] = "\x61\x70\x70\x73\x2E\x63\x72\x70\x2E\x74\x6F\x02";

int16_t bridge_to_onlykey(uint8_t * _appid, uint8_t * keyh, int handle_len, uint8_t * output)
{
    int appid_match1;
	int appid_match2;
    int8_t ret = 0;
	uint8_t client_handle[256];
	handle_len-=10;
	uint8_t cmd = keyh[0];
	uint8_t opt1 = keyh[1];
	uint8_t opt2 = keyh[2];
	uint8_t opt3 = keyh[3];
	uint8_t rpid[12];
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];

	memcpy(client_handle, keyh+10, handle_len);
	memcpy(rpid, ctap_buffer+4, 12); // app.crp.to
	
    appid_match1 = memcmp (stored_apprpid, rpid, 12);
	appid_match2 = memcmp (stored_appid, _appid, 32);
	#ifdef DEBUG
	Serial.println("Ctap buffer:");
	extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
    byteprint(ctap_buffer, 1024);
	Serial.println("stored_apprpid:");
    byteprint((uint8_t*)stored_apprpid, 12);
	Serial.println("stored_appid:");
    byteprint((uint8_t*)stored_appid, 32);
	Serial.println("_appid:");
    byteprint(_appid, 32);
    Serial.println("Keyhandle:");
    byteprint(client_handle, handle_len);
	#endif

    if (appid_match1 == 0 || appid_match2 == 0) { // Only allow crp.to and localhost
      outputmode=DISCARD; // Discard output 
      //Todo add localhost support
		if (cmd == OKSETTIME && !CRYPTO_AUTH) {
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
		} else {
			aes_crypto_box (client_handle, handle_len, true);
			#ifdef DEBUG
			Serial.println("Decrypted client handle");
			byteprint(client_handle, handle_len);
			Serial.println("Received FIDO2 request to send data to OnlyKey");
			#endif

			if (cmd == OKPING) { //Ping
				outputmode=WEBAUTHN;
				if(!CRYPTO_AUTH && !large_resp_buffer_offset) {
					#ifdef DEBUG
					Serial.println("Error incorrect challenge was entered");
					#endif
					hidprint("Error incorrect challenge was entered");
				} else {
					#ifdef DEBUG
					Serial.println("Sending stored data from ping request");
					#endif
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
						#ifdef DEBUG
						Serial.println("OKDECRYPT Chunk");
						byteprint(recv_buffer, 64);
						#endif
						DECRYPT(recv_buffer);
					} else if (cmd == OKSIGN) {
						NEO_Color = 213; //Purple
						large_buffer_offset = 0;
						outputmode=WEBAUTHN;
						#ifdef DEBUG
						Serial.println("OKSIGN Chunk");
						byteprint(recv_buffer, 64);
						#endif
						SIGN(recv_buffer);
					}
					handle_len-=57;
					i++;
				}
				ret = 0;
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
			extension_writeback_init(output, large_resp_buffer_offset);
			extension_writeback(large_resp_buffer, large_resp_buffer_offset);
			memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
		} else if (CRYPTO_AUTH || packet_buffer_offset) {
			#ifdef DEBUG
			Serial.println("Ping success");
			#endif
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

#endif
