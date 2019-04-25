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
extern int large_data_len;
extern int large_data_offset;
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
extern int outputU2F;
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE*2)+1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
extern uint8_t type;
uint8_t times = 0;
int msgcount = 0;
bool isFirefox;
extern uint8_t NEO_Color;

const char stored_appid[] = "\x23\xCD\xF4\x07\xFD\x90\x4F\xEE\x8B\x96\x40\x08\xB0\x49\xC5\x5E\xA8\x81\x13\x36\xA3\xA5\x17\x1B\x58\xD6\x6A\xEC\xF3\x79\xE7\x4A";
    
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

void errorResponse(uint8_t *buffer, int code)
{
        u2f_button = 0;
		memset(resp_buffer, 0, 64);
		memcpy(resp_buffer, buffer, 4);
        resp_buffer[4] = U2FHID_ERROR;
        SET_MSG_LEN(resp_buffer, 1);
        resp_buffer[7] = code & 0xff;
#ifdef DEBUG
	Serial.print("SENT RESPONSE error:");
	Serial.println(code);
	byteprint(resp_buffer,64);
#endif
	RawHID.send(resp_buffer, 100);
}

void respondErrorPDU(uint8_t *buffer, int err)
{
	u2f_button = 0;
	SET_MSG_LEN(buffer, 2); //len("") + 2 byte SW
	uint8_t *datapart = buffer + 7;
	APPEND_SW(datapart, (err >> 8) & 0xff, err & 0xff);
	memset(buffer+9, 0, 55);
	RawHID.send(buffer, 100);
}


int recv_custom_msg(uint8_t *datapart, uint8_t *buffer) {
  int appid_match;
  uint8_t *application_parameter = datapart+32;
  uint8_t handle_len = datapart[64];
  uint8_t *client_handle = datapart+65;
  appid_match = memcmp (stored_appid, application_parameter, 32);
  Serial.println("CID");
  byteprint(buffer, 4);
  Serial.println("App ID:");
  byteprint(application_parameter, 32);
  Serial.println("Stored App ID:");
  byteprint((uint8_t*)stored_appid, 32);
  Serial.println("Keyhandle:");
  byteprint(client_handle, handle_len);
  if (appid_match == 0) {
	   if (client_handle[0] == 0xFF && client_handle[1] == 0xFF && client_handle[2] == 0xFF && client_handle[3] == 0xFF) {
			handle_firefox_u2f (client_handle+4);
			if (client_handle[4] == OKSETTIME && !CRYPTO_AUTH) {
				if(profilemode!=NONENCRYPTEDPROFILE) {
				#ifdef US_VERSION
				msgcount = 0;
				outputU2F = 1;
				large_data_offset = 0;
				set_time(client_handle);
				memset(ecc_public_key, 0, sizeof(ecc_public_key));
				crypto_box_keypair(ecc_public_key+sizeof(UNLOCKED), ecc_private_key); //Generate keys
				#ifdef DEBUG
				Serial.println("OnlyKey public = ");
				byteprint(ecc_public_key+sizeof(UNLOCKED), 32);
				#endif
				memcpy(ecc_public_key, UNLOCKED, sizeof(UNLOCKED));
				store_U2F_response(ecc_public_key, (32+sizeof(UNLOCKED)), false);
				memcpy(ecc_public_key, client_handle+9, 32); //Get app public key
				#ifdef DEBUG
				Serial.println("App public = ");
				byteprint(ecc_public_key, 32);
				#endif
				send_U2F_response(buffer); //Send response with our public key
				uint8_t shared[32];
				type = 1;
				if (shared_secret (ecc_public_key, shared)) {
					hidprint("Error with ECC Shared Secret");
					return 1;
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
				return 1;
				#endif
				}
			}
		large_data_offset = 0;
		return 1;
	   } else {
		   aes_crypto_box (client_handle, 64, true);
		   handle_firefox_u2f (client_handle+4);
			#ifdef DEBUG
			Serial.println("Decrypted client handle");
			byteprint(client_handle, 64);
			#endif  
		   if (client_handle[0] == 0xFF && client_handle[1] == 0xFF && client_handle[2] == 0xFF && client_handle[3] == 0xFF) {
			#ifdef DEBUG
					Serial.println("Received U2F request to send data to OnlyKey");
					Serial.println(times);
			#endif 		
			if (client_handle[4] == OKDECRYPT && !CRYPTO_AUTH) {
				if(profilemode!=NONENCRYPTEDPROFILE) {
				#ifdef US_VERSION
				NEO_Color = 128; //Turquoise
				outputU2F = 1;
				large_data_offset = 0;
				DECRYPT(client_handle);
				#endif
				}	
			} else if (client_handle[4] == OKSIGN && !CRYPTO_AUTH) {
				if(profilemode!=NONENCRYPTEDPROFILE) {
				#ifdef US_VERSION
				NEO_Color = 213; //Purple
				outputU2F = 1;
				large_data_offset = 0;
				SIGN(client_handle);
				#endif
				}
			} else if (client_handle[4] == OKGETPUBKEY && !CRYPTO_AUTH) {
				if(profilemode!=NONENCRYPTEDPROFILE) {
				#ifdef US_VERSION
				outputU2F = 1;
				large_data_offset = 0;
				GETPUBKEY(client_handle);
				send_U2F_response(buffer);
				return 1;
				#endif
				}
			} else if (client_handle[4] == OKPING) { //Ping
				if(profilemode!=NONENCRYPTEDPROFILE) {
				#ifdef US_VERSION
				large_data_offset = 0;
				if  (CRYPTO_AUTH) {
					custom_error(0); //ACK
				}
				else if (large_resp_buffer[0] != 0x01 && large_resp_buffer[large_resp_buffer_offset-2] != 0x90) {
					custom_error(1); //incorrect challenge code entered
				} else if (!CRYPTO_AUTH) {
					large_data_offset = 0;
					send_U2F_response(buffer);
					fadeoff(0);
				}					
				return 1;
				#endif
				}
			} 
			large_data_offset = 0;
			return 1;
		  } else {
			msgcount--; 
			return 1;				
		  }
	  }
  }
  wipedata();
  return 0;
}
	  
void fido_msg_timeout(uint8_t *buffer) {
	ctaphid_check_timeouts();
}

void recv_fido_msg(uint8_t *buffer) {
	ctaphid_handle_packet(buffer);
    memset(recv_buffer, 0, sizeof(buffer));
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

void store_U2F_response (uint8_t *data, int len, bool encrypt) {
	if (strcmp((char*)data, "Error")) CRYPTO_AUTH = 0;
	cancelfadeoffafter20();
	int len2 = 0;
	large_resp_buffer[1] = 0x00;
	large_resp_buffer[2] = 0x00;
	large_resp_buffer[3] = 0x00;
	large_resp_buffer[4] = 0x00;
	if (encrypt) {
		aes_crypto_box (data, len, false);
		large_resp_buffer[4] = 0x01;
	} 
	if ((len+13) >= (int)LARGE_RESP_BUFFER_SIZE) return; //Double check buf overflow
	if (len < 64) {
		uint8_t tempdata[64];
		memmove( tempdata, data, len);
		data = tempdata+len;
		RNG2(data, 64-len); //Store a random number in key handle empty space
		data = tempdata;
		len = 64;
	}
	large_resp_buffer[0] = 0x01; // user_presence
	len2 = 5;
	large_resp_buffer[len2++] = 0x30; //header: compound structure
	large_resp_buffer[len2++] = len+4; //total length 
    large_resp_buffer[len2++] = 0x02;  //header: integer
	#ifdef DEBUG
      Serial.print ("Len1 ");
      Serial.print (len/2);
#endif
	large_resp_buffer[len2++] = len/2; 
	memmove(large_resp_buffer+len2, data, len/2); //R value
	len2 += len/2;
	large_resp_buffer[len2++] = 0x02;  //header: integer 
	large_resp_buffer[len2++] = len/2; 
	memmove(large_resp_buffer+len2, data+(len/2), len/2); //S value
	len2 += len/2;
	uint8_t *last = large_resp_buffer+len2;
	APPEND_SW_NO_ERROR(last);
	len2 += 2;
	large_resp_buffer_offset = len2;
#ifdef DEBUG
      Serial.print ("Stored U2F Response");
	  byteprint(large_resp_buffer, large_resp_buffer_offset);
#endif
	 wipedata(); //Data will wait 5 seconds to be retrieved
}

void send_U2F_response(uint8_t *buffer) {
	if(profilemode!=NONENCRYPTEDPROFILE) {
		#ifdef DEBUG
		Serial.print("Sending data on OnlyKey via U2F");
		#endif  
		if (large_resp_buffer[large_resp_buffer_offset-1] == 0 && large_resp_buffer[large_resp_buffer_offset-2] == 0x90) {
			#ifdef US_VERSION
			sendLargeResponse(buffer, large_resp_buffer_offset);
			memset(large_resp_buffer, 0, large_resp_buffer_offset);
			memset(large_resp_buffer, 0, large_resp_buffer_offset);
			outputU2F = 0;
			#endif
			return;
		} else {
			#ifdef DEBUG
			Serial.print("Error no data ready to be retrieved");
			#endif 
			custom_error(6); 
			outputU2F = 0;
			if (!CRYPTO_AUTH) fadeoff(1);
			return;
		}
	}
}

void custom_error (uint8_t code) {
	char response[64] = "Error";
	if (isFirefox) {
		response[6] = code;
		store_U2F_response((uint8_t*)response, 64, true);
		send_U2F_response(recv_buffer);
		outputU2F = 1;
	} else {
		msgcount++;
		errorResponse(recv_buffer, 127+code); 
	}
}

void handle_firefox_u2f (uint8_t *msgid) {
	if (*msgid < 128) { //Firefox
		if (times < 1) {
			respondErrorPDU(recv_buffer, SW_CONDITIONS_NOT_SATISFIED);
			times++;
			msgcount--;
			return;
		} else {
		times = 0;
		}
		*msgid+=128;
		isFirefox = true;
#ifdef DEBUG
      Serial.print ("Browser is Firefox");
#endif
	} else { //Chrome
		isFirefox = false;				
	}
}

void sendLargeResponse(uint8_t *request, int len)
{
#ifdef DEBUG	
	Serial.print("Sending large response ");
	Serial.println(len);
	byteprint(large_resp_buffer, len);
	Serial.println("\n--\n");
#endif	
	memcpy(resp_buffer, request, 4); //copy cid
	resp_buffer[4] = U2FHID_MSG;
	int r = len;
	if (r>MAX_INITIAL_PACKET) {
		r = MAX_INITIAL_PACKET;
	}

	SET_MSG_LEN(resp_buffer, len);
	memcpy(resp_buffer + 7, large_resp_buffer, r);

	RawHID.send(resp_buffer, 100);
	len -= r;
	uint8_t p = 0;
	int offset = MAX_INITIAL_PACKET;
	while (len > 0) {
		//memcpy(resp_buffer, request, 4); //copy cid, doesn't need to recopy
		resp_buffer[4] = p++;
		memcpy(resp_buffer + 5, large_resp_buffer + offset, MAX_CONTINUATION_PACKET);
		RawHID.send(resp_buffer, 100);
		len-= MAX_CONTINUATION_PACKET;
		offset += MAX_CONTINUATION_PACKET;
		delayMicroseconds(2500);
	}
}


#endif