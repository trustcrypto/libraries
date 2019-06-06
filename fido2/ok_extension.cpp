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

const char stored_appid[] = "\xEB\xAE\xE3\x29\x09\x0A\x5B\x51\x92\xE0\xBD\x13\x2D\x5C\x22\xC6\xD1\x8A\x4D\x23\xFC\x8E\xFD\x4A\x21\xAF\xA8\xE4\xC8\xFD\x93\x54";

int16_t bridge_to_onlykey(uint8_t * _appid, uint8_t * client_handle, int handle_len)
{
    /*
    int reqlen = klen;
    int i;
    int8_t ret = 0;

    uint8_t sig[200];

    uint8_t * args[5] = {NULL,NULL,NULL,NULL,NULL};
    uint8_t lens[5];

    uint8_t key[256];
    uint8_t shasum[32];
    uint8_t chksum[4];

    int keysize = sizeof(key);

    memset(lens,0,sizeof(lens));

    wallet_request * req = (wallet_request *) msg_buf;
    uint8_t * payload = req->payload;

    memmove(msg_buf, keyh, klen);


    //printf1(TAG_WALLET, "u2f2wallet [%d]: ",reqlen); dump_hex1(TAG_WALLET, msg_buf,reqlen);

    int offset = 0;
    for (i = 0; i < MIN(5,req->numArgs); i++)
    {
        if (offset > MAX_PAYLOAD_SIZE)
        {
            ret = CTAP1_ERR_INVALID_LENGTH;
            goto cleanup;
        }
        lens[i] = *(payload + offset);
        offset++;
        args[i] = payload + offset;
        offset += lens[i];
    }
    if (offset > MAX_PAYLOAD_SIZE)
    {
        ret = CTAP1_ERR_INVALID_LENGTH;
        printf2(TAG_ERR,"Wallet operation lengths too big\n");
        goto cleanup;
    }
    */
    int appid_match;
    int8_t ret = 0;
    appid_match = memcmp (stored_appid, _appid, 32);
    Serial.println("App ID:");
    byteprint(_appid, 32);
    Serial.println("Stored App ID:");
    byteprint((uint8_t*)stored_appid, 32);
    Serial.println("Keyhandle:");
    byteprint(client_handle, handle_len);

    if (appid_match == 0) { // Only allow crp.to and localhost
      outputmode=4; //Webauthn
      //Todo add U2F support outputmode=1
      //Todo add localhost support
    	   if (client_handle[0] == 0xFF && client_handle[1] == 0xFF && client_handle[2] == 0xFF && client_handle[3] == 0xFF) {
    			if (client_handle[4] == OKSETTIME && !CRYPTO_AUTH) {
    				if(profilemode!=NONENCRYPTEDPROFILE) {
    				#ifdef US_VERSION
    				large_buffer_offset = 0;
    				set_time(client_handle);
    				memset(ecc_public_key, 0, sizeof(ecc_public_key));
    				crypto_box_keypair(ecc_public_key+sizeof(UNLOCKED), ecc_private_key); //Generate keys
    				#ifdef DEBUG
    				Serial.println("OnlyKey public = ");
    				byteprint(ecc_public_key+sizeof(UNLOCKED), 32);
    				#endif
    				memcpy(ecc_public_key, UNLOCKED, sizeof(UNLOCKED));
            send_transport_response (ecc_public_key, 32+sizeof(UNLOCKED), false, false); //Don't encrypt and send right away
    				memcpy(ecc_public_key, client_handle+9, 32); //Get app public key
    				#ifdef DEBUG
    				Serial.println("App public = ");
    				byteprint(ecc_public_key, 32);
    				#endif

    				//send_U2F_response(buffer); //Send response with our public key
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
    				return ret;
    				#endif
    				}
    			}
    		large_buffer_offset = 0;
    		return ret;
    	   } else {
    		   //aes_crypto_box (client_handle, 64, true);
    			#ifdef DEBUG
    			Serial.println("Decrypted client handle");
    			byteprint(client_handle, 64);
    			#endif
    		   if (client_handle[0] == 0xFF && client_handle[1] == 0xFF && client_handle[2] == 0xFF && client_handle[3] == 0xFF) {
    			#ifdef DEBUG
    					Serial.println("Received U2F request to send data to OnlyKey");
    			#endif
    			if (client_handle[4] == OKDECRYPT && !CRYPTO_AUTH) {
    				if(profilemode!=NONENCRYPTEDPROFILE) {
    				#ifdef US_VERSION
    				NEO_Color = 128; //Turquoise
    				large_buffer_offset = 0;
    				DECRYPT(client_handle);
            ret = 0;
    				#endif
    				}
    			} else if (client_handle[4] == OKSIGN && !CRYPTO_AUTH) {
    				if(profilemode!=NONENCRYPTEDPROFILE) {
    				#ifdef US_VERSION
    				NEO_Color = 213; //Purple
    				large_buffer_offset = 0;
    				SIGN(client_handle);
            ret = 0;
    				#endif
    				}
    			} else if (client_handle[4] == OKPING) { //Ping
    				if(profilemode!=NONENCRYPTEDPROFILE) {
    				#ifdef US_VERSION
    				large_buffer_offset = 0;
    				if  (CRYPTO_AUTH) {
    					//custom_error(0); //ACK
              ret = CTAP2_ERR_USER_ACTION_PENDING;
    				}
    				//else if (large_resp_buffer[0] != 0x01 && large_resp_buffer[large_resp_buffer_offset-2] != 0x90) {
              else if (large_resp_buffer_offset) { //Need to check if PIN correct
              #ifdef DEBUG
                  Serial.println("Check large_resp_buffer to see if challenge code worked or not");
                  byteprint(large_resp_buffer, 64);
              #endif
              ret = CTAP2_ERR_PIN_INVALID;
              //custom_error(1); //incorrect challenge code entered
    				} else if (!CRYPTO_AUTH) {
    					large_buffer_offset = 0;
    					ret = send_stored_response();
    					fadeoff(0);
    				}
    				return ret;
    				#endif
    				}
    			}
          if (!isfade) fadeon(NEO_Color);
    			large_buffer_offset = 0;
    			return ret;
    		  } else {
            //invalid message or decrypt failed, IV out of sync
              ret = CTAP2_ERR_KEEPALIVE_CANCEL;
              if (isfade) fadeoff(1);
    			    return ret;
    		  }
    	  }
      }
    ret = CTAP2_ERR_EXTENSION_NOT_SUPPORTED; //APPID doesn't match
    wipedata();
    return ret;
}

int16_t send_stored_response() {
  int16_t ret = 0;
	if(profilemode!=NONENCRYPTEDPROFILE) {
		#ifdef DEBUG
		Serial.print("Sending data on OnlyKey via U2F");
		#endif
    // Check if large response is ready
		if (large_resp_buffer_offset) {
			#ifdef US_VERSION
      extension_writeback(large_resp_buffer, large_resp_buffer_offset);
			//sendLargeResponse(buffer, large_resp_buffer_offset);
			//memset(large_resp_buffer, 0, large_resp_buffer_offset);
			memset(large_resp_buffer, 0, large_resp_buffer_offset);
			#endif
			return 0;
		} else {
			#ifdef DEBUG
			Serial.print("Error no data ready to be retrieved");
			#endif
			//custom_error(6);
      ret = CTAP2_ERR_NO_OPERATION_PENDING;
			if (!CRYPTO_AUTH) fadeoff(1);
			return ret;
		}
	}
}
