/* oku2f.c
*/

/* Modifications by Tim Steiner
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
 *
 *Original U2F Portion
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

#include "oku2f.h"

struct ch_state {
  int cid;
  uint8_t state;
  int last_millis;
};

/*************************************/
//U2F Assignments
/*************************************/
uint8_t expected_next_packet;
int large_data_len;
int large_data_offset;
uint8_t large_buffer[1024];
uint8_t large_resp_buffer[1024];
uint8_t recv_buffer[64];
uint8_t resp_buffer[64];
uint8_t handle[64];
uint8_t sha256_hash[32];
extern uint8_t nonce[32];

const char stored_pub[] = "\x04\xC3\xC9\x1F\x25\x2E\x20\x10\x7B\x5E\x8D\xEA\xB1\x90\x20\x98\xF7\x28\x70\x71\xE4\x54\x18\xB8\x98\xCE\x5F\xF1\x7C\xA7\x25\xAE\x78\xC3\x3C\xC7\x01\xC0\x74\x60\x11\xCB\xBB\xB5\x8B\x08\xB6\x1D\x20\xC0\x5E\x75\xD5\x01\xA3\xF8\xF7\xA1\x67\x3F\xBE\x32\x63\xAE\xBE";

const char stored_priv[] = "\xD3\x0C\x9C\xAC\x7D\xA2\xB4\xA7\xD7\x1B\x00\x2A\x40\xA3\xB5\x9A\x96\xCA\x50\x8B\xA9\xC7\xDC\x61\x7D\x98\x2C\x4B\x11\xD9\x52\xE6";

const char stored_der[] = "\x30\x82\x01\xB4\x30\x82\x01\x58\xA0\x03\x02\x01\x02\x02\x01\x01\x30\x0C\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02\x05\x00\x30\x61\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x44\x45\x31\x26\x30\x24\x06\x03\x55\x04\x0A\x0C\x1D\x55\x6E\x74\x72\x75\x73\x74\x77\x6F\x72\x74\x68\x79\x20\x43\x41\x20\x4F\x72\x67\x61\x6E\x69\x73\x61\x74\x69\x6F\x6E\x31\x0F\x30\x0D\x06\x03\x55\x04\x08\x0C\x06\x42\x65\x72\x6C\x69\x6E\x31\x19\x30\x17\x06\x03\x55\x04\x03\x0C\x10\x55\x6E\x74\x72\x75\x73\x74\x77\x6F\x72\x74\x68\x79\x20\x43\x41\x30\x22\x18\x0F\x32\x30\x31\x34\x30\x39\x32\x34\x31\x32\x30\x30\x30\x30\x5A\x18\x0F\x32\x31\x31\x34\x30\x39\x32\x34\x31\x32\x30\x30\x30\x30\x5A\x30\x5E\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x44\x45\x31\x21\x30\x1F\x06\x03\x55\x04\x0A\x0C\x18\x76\x69\x72\x74\x75\x61\x6C\x2D\x75\x32\x66\x2D\x6D\x61\x6E\x75\x66\x61\x63\x74\x75\x72\x65\x72\x31\x0F\x30\x0D\x06\x03\x55\x04\x08\x0C\x06\x42\x65\x72\x6C\x69\x6E\x31\x1B\x30\x19\x06\x03\x55\x04\x03\x0C\x12\x76\x69\x72\x74\x75\x61\x6C\x2D\x75\x32\x66\x2D\x76\x30\x2E\x30\x2E\x31\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00\x04\xC3\xC9\x1F\x25\x2E\x20\x10\x7B\x5E\x8D\xEA\xB1\x90\x20\x98\xF7\x28\x70\x71\xE4\x54\x18\xB8\x98\xCE\x5F\xF1\x7C\xA7\x25\xAE\x78\xC3\x3C\xC7\x01\xC0\x74\x60\x11\xCB\xBB\xB5\x8B\x08\xB6\x1D\x20\xC0\x5E\x75\xD5\x01\xA3\xF8\xF7\xA1\x67\x3F\xBE\x32\x63\xAE\xBE\x30\x0C\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02\x05\x00\x03\x48\x00\x30\x45\x02\x21\x00\x8E\xB9\x20\x57\xA1\xF3\x41\x4F\x1B\x79\x1A\x58\xE6\x07\xAB\xA4\x66\x1C\x93\x61\xFB\xC4\xBA\x89\x65\x5C\x8A\x3B\xEC\x10\x68\xDA\x02\x20\x15\x90\xA8\x76\xF0\x80\x47\xDF\x60\x8E\x23\xB2\x2A\xA0\xAA\xD2\x4B\x0D\x49\xC9\x75\x33\x00\xAF\x32\xB6\x90\x73\xF0\xA1\xA4\xDB";

char attestation_pub[66];
char attestation_priv[33];
char attestation_der[768];
  
char handlekey[34] = {NULL};
#ifdef US_VERSION
const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256
#endif
uint8_t private_k[36]; //32
uint8_t public_k[68]; //64
uint8_t public_temp[64]; //64

ch_state channel_states[MAX_CHANNEL];

void U2Finit()
{
  SHA256_CTX hkey;
  sha256_init(&hkey);
  sha256_update(&hkey, nonce, 32); //Add nonce to hkey 
  sha256_update(&hkey, (uint8_t*)ID, 36); //Add ID to hkey 
  sha256_final(&hkey, (uint8_t*)handlekey); //Create hash and store in handlekey
#ifdef DEBUG
  Serial.println("HANDLE KEY =");
  Serial.println(handlekey); 
#endif
  uint8_t length[2];
  onlykey_eeget_U2Fcertlen(length);
  int length2 = length[0] << 8 | length[1];
  if (length2 != 0) {
  onlykey_flashget_U2F();
  } else {
  memcpy(attestation_pub, stored_pub, 66);
  memcpy(attestation_priv, stored_priv, 33);
#ifdef DEBUG
  for (int i = 0; i< sizeof(stored_priv); i++) {
    Serial.print(attestation_priv[i],HEX);
    }
#endif
  memcpy(attestation_der, stored_der, sizeof(stored_der));
#ifdef DEBUG
  for (int i = 0; i< sizeof(stored_der); i++) {
    Serial.print(attestation_der[i],HEX);
    }
#endif
  }
}


void cleanup_timeout()
{
	int i;
	for (i = 0;  i < MAX_CHANNEL; i++) {
		//free channel that is inactive
		ch_state &c = channel_states[i];
		int m = millis();
		if (c.state != STATE_CHANNEL_AVAILABLE) {
			if ((m - c.last_millis) > TIMEOUT_VALUE) {
				c.state = STATE_CHANNEL_AVAILABLE;
			}
		}
	}
}

int allocate_new_channel()
{
	int i;
	//alloace new channel_id
	int channel_id = 1;

	do {
		bool found = false;
		for (i = 0;  i < MAX_CHANNEL; i++) {
			if (channel_states[i].state != STATE_CHANNEL_AVAILABLE) {
				if (channel_states[i].cid == channel_id) {
					found = true;
					channel_id++;
					break;
				}
			}
		}
		if (!found)
			break;
	} while (true);
	return channel_id;
}

int allocate_channel(int channel_id)
{
	int i;
	if (channel_id==0) {
		channel_id =  allocate_new_channel();
	}

	bool has_free_slots = false;
	for (i = 0;  i < MAX_CHANNEL; i++) {
		if (channel_states[i].state == STATE_CHANNEL_AVAILABLE) {
			has_free_slots = true;
			break;
		}
	}
	if (!has_free_slots)
		cleanup_timeout();

	for (i = 0;  i < MAX_CHANNEL; i++) {
		ch_state &c = channel_states[i];
		if (c.state == STATE_CHANNEL_AVAILABLE) {
			c.cid = channel_id;
			c.state = STATE_CHANNEL_WAIT_PACKET;
			c.last_millis = millis();
			return channel_id;
		}
	}
	return 0;
}

int initResponse(uint8_t *buffer)
{
#ifdef DEBUG
	Serial.print("INIT RESPONSE");
#endif
	int cid = *(int*)buffer;
#ifdef DEBUG
	Serial.println(cid, HEX);
#endif
	int len = buffer[5] << 8 | buffer[6];
	int i;
	memcpy(resp_buffer, buffer, 5);
	SET_MSG_LEN(resp_buffer, 17);
	memcpy(resp_buffer + 7, buffer + 7, len); //nonce
	i = 7 + len;
	if (cid==-1) {
		cid = allocate_channel(0);
	} else {
#ifdef DEBUG
		Serial.println("using existing CID");
#endif
		allocate_channel(cid);
	}
	memcpy(resp_buffer + i, &cid, 4);
	i += 4;
	resp_buffer[i++] = U2FHID_IF_VERSION;
	resp_buffer[i++] = 1; //major
	resp_buffer[i++] = 0;
	resp_buffer[i++] = 1; //build
	//resp_buffer[i++] = CAPABILITY_WINK; //capabilities
	resp_buffer[i++] = 0; //capabilities
#ifdef DEBUG
	Serial.println("SENT RESPONSE 1");
#endif	
	RawHID.send(resp_buffer, 100);
#ifdef DEBUG
	Serial.println(cid, HEX);
#endif	
	return cid;
}


void errorResponse(uint8_t *buffer, int code)
{
        memcpy(resp_buffer, buffer, 4);
        resp_buffer[4] = U2FHID_ERROR;
        SET_MSG_LEN(resp_buffer, 1);
        resp_buffer[7] = code & 0xff;
#ifdef DEBUG
	Serial.print("SENT RESPONSE error:");
	Serial.println(code);
#endif
	RawHID.send(resp_buffer, 100);
}


//find channel index and update last access
int find_channel_index(int channel_id)
{
	int i;

	for (i = 0;  i < MAX_CHANNEL; i++) {
		if (channel_states[i].cid==channel_id) {
			channel_states[i].last_millis = millis();
			return i;
		}
	}

	return -1;
}





void respondErrorPDU(uint8_t *buffer, int err)
{
	SET_MSG_LEN(buffer, 2); //len("") + 2 byte SW
	uint8_t *datapart = buffer + 7;
	APPEND_SW(datapart, (err >> 8) & 0xff, err & 0xff);
	RawHID.send(buffer, 100);
}

void sendLargeResponse(uint8_t *request, int len)
{
#ifdef DEBUG	
	Serial.print("Sending large response ");
	Serial.println(len);
	for (int i = 0; i < len; i++) {
		Serial.print(large_resp_buffer[i], HEX);
		Serial.print(" ");
	}
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


int u2f_button = 0;


void processMessage(uint8_t *buffer)
{
  int len = buffer[5] << 8 | buffer[6];
#ifdef DEBUG  
  Serial.println(F("Got message"));
  Serial.println(len);
  Serial.println(F("Data:"));
#endif  
  uint8_t *message = buffer + 7;
#ifdef DEBUG
  for (int i = 7; i < 7+len; i++) {
    Serial.print(buffer[i], HEX);
  }
  Serial.println(F(""));
#endif  
  //todo: check CLA = 0
  uint8_t CLA = message[0];

  if (CLA!=0) {
#ifdef DEBUG 
    Serial.println("U2F Error SW_CLA_NOT_SUPPORTED 366");
#endif 
    respondErrorPDU(buffer, SW_CLA_NOT_SUPPORTED);
    return;
  }

  uint8_t INS = message[1];
  uint8_t P1 = message[2];
  uint8_t P2 = message[3];
  int reqlength = (message[4] << 16) | (message[5] << 8) | message[6];

  switch (INS) {
  case U2F_INS_REGISTER:
    {
      if (reqlength!=64) {
#ifdef DEBUG 
		Serial.println("U2F Error SW_WRONG_LENGTH 382");
#endif 
        respondErrorPDU(buffer, SW_WRONG_LENGTH);
        return;
      }

   
      if (!u2f_button) {
#ifdef DEBUG 
		Serial.println("U2F Error SW_CONDITIONS_NOT_SATISFIED 391");
#endif 
        respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
		return;
        }
      else {
#ifdef DEBUG
          Serial.println("U2F button pressed for register");
#endif
      }
    

      uint8_t *datapart = message + 7;
      uint8_t *challenge_parameter = datapart;
      uint8_t *application_parameter = datapart+32;

      memset(public_k, 0, sizeof(public_k));
      memset(private_k, 0, sizeof(private_k));
      #ifdef US_VERSION
      uECC_make_key(public_k + 1, private_k, curve); //so we ca insert 0x04
      #endif
      public_k[0] = 0x04;
#ifdef DEBUG
      Serial.println(F("Public K"));
      for (int i =0; i < sizeof(public_k); i++) {
        Serial.print(public_k[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
      Serial.println(F("Private K"));
      for (int i =0; i < sizeof(private_k); i++) {
        Serial.print(private_k[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif      
      //construct hash

      memcpy(handle, application_parameter, 32);
      memcpy(handle+32, private_k, 32);
#ifdef DEBUG
      Serial.println("Unencrypted handle");
      for (int i =0; i<sizeof(handle); i++) {
      Serial.print(handle[i],HEX);
      }
#endif
      SHA256_CTX IV;
      sha256_init(&IV);
      sha256_update(&IV, application_parameter, 32);
      sha256_final(&IV, sha256_hash);
      #ifdef US_VERSION
      aes_gcm_encrypt2(handle, (uint8_t*)sha256_hash, (uint8_t*)handlekey, 64);
      #endif 
#ifdef DEBUG
      Serial.println();
      Serial.println("Encrypted handle");
      for (int i =0; i<sizeof(handle); i++) {
      Serial.print(handle[i],HEX);
      }
#endif
      SHA256_CTX ctx;
      sha256_init(&ctx);
      large_resp_buffer[0] = 0x00;
      sha256_update(&ctx, large_resp_buffer, 1);
#ifdef DEBUG      
      Serial.println(F("App Parameter:"));
      for (int i =0; i < 32; i++) {
        Serial.print(application_parameter[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif
      sha256_update(&ctx, application_parameter, 32);
#ifdef DEBUG
      Serial.println(F("Chal Parameter:"));
      for (int i =0; i < 32; i++) {
        Serial.print(challenge_parameter[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif
      sha256_update(&ctx, challenge_parameter, 32);
      sha256_update(&ctx, handle, 64);
      sha256_update(&ctx, public_k, 65);
      sha256_final(&ctx, sha256_hash);
#ifdef DEBUG
      Serial.println(F("Hash:"));
      for (int i =0; i < 32; i++) {
        Serial.print(sha256_hash[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif

      uint8_t *signature = resp_buffer; //temporary
#ifdef US_VERSION
	  uint8_t tmp[32 + 32 + 64];
	  SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
	  if (!uECC_sign_deterministic((uint8_t *)attestation_priv,
						sha256_hash,
						32,
						&ectx.uECC,
						signature,
						curve)) {
#endif         
#ifdef DEBUG
      Serial.println("ECC Signature Failed Register");
	  //respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
      //return;
#endif
      }
      //if (!uECC_verify((uint8_t *)attestation_pub+1, sha256_hash, 32, signature, curve)) {
#ifdef DEBUG
      //Serial.println("ECC Verify Signature Failed Register");
      //respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
      //return;

#endif
      //}

      int len = 0;
      large_resp_buffer[len++] = 0x05;
      memcpy(large_resp_buffer + len, public_k, 65);
      len+=65;
      large_resp_buffer[len++] = 64; //length of handle
      memcpy(large_resp_buffer+len, handle, 64);
      len += 64;
#ifdef DEBUG
      Serial.println("len = ");
      Serial.println(len);
#endif
      uint8_t length[2];
      onlykey_eeget_U2Fcertlen(length);
      int length2 = length[0] << 8 | length[1];
      if (length2 == 0) length2 = sizeof(stored_der) - 1;
#ifdef DEBUG
      Serial.println("copy attestation_der to buffer, length = ");
      Serial.println(length2);
#endif
      memcpy(large_resp_buffer+len, attestation_der, length2);
      len += length2;
      //convert signature format
      //http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
      large_resp_buffer[len++] = 0x30; //header: compound structure
	  uint8_t *total_len = &large_resp_buffer[len];
      large_resp_buffer[len++] = 0x44; //total length (32 + 32 + 2 + 2)
      large_resp_buffer[len++] = 0x02;  //header: integer

			if (signature[0]>0x7f) {
			   	large_resp_buffer[len++] = 33;  //33 byte
				large_resp_buffer[len++] = 0;
				(*total_len)++; //update total length
			}  else {
				large_resp_buffer[len++] = 32;  //32 byte      
		    }
	  memcpy(large_resp_buffer+len, signature, 32); //R value
      len +=32;
      large_resp_buffer[len++] = 0x02;  //header: integer

			if (signature[32]>0x7f) {
				large_resp_buffer[len++] = 33;  //32 byte
				large_resp_buffer[len++] = 0;
				(*total_len)++;	//update total length
			} else {
				large_resp_buffer[len++] = 32;  //32 byte
			}
      memcpy(large_resp_buffer+len, signature+32, 32); //R value
      len +=32;

      uint8_t *last = large_resp_buffer+len;
      APPEND_SW_NO_ERROR(last);
      len += 2;
     
      u2f_button = 0;
      sendLargeResponse(buffer, len);
      large_data_offset = 0;
    }

    break;
  case U2F_INS_AUTHENTICATE:
    {

      //minimum is 64 + 1 + 64
      if (reqlength!=(64+1+64)) {
#ifdef DEBUG
		Serial.print("Error SW wrong length");
#endif
        respondErrorPDU(buffer, SW_WRONG_LENGTH);
        return;
      }

      uint8_t *datapart = message + 7;
      uint8_t *challenge_parameter = datapart;
      uint8_t *application_parameter = datapart+32;
      uint8_t handle_len = datapart[64];
      uint8_t *client_handle = datapart+65;

      if (handle_len!=64) {
        //not from this device
#ifdef DEBUG
		Serial.print("Error not from this device");
#endif
        respondErrorPDU(buffer, SW_WRONG_DATA);
        return;
      }
     
      if (!u2f_button) {
#ifdef DEBUG
		Serial.print("Error U2F Button Not Pressed");
#endif
        respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
		return;
        }
      else { 
#ifdef DEBUG
        Serial.println("U2F button pressed for authenticate");
#endif
      }

      memcpy(handle, client_handle, 64);
      SHA256_CTX IV2;
      sha256_init(&IV2);
      sha256_update(&IV2, application_parameter, 32);
      sha256_final(&IV2, sha256_hash);
#ifdef DEBUG
      Serial.println("Encrypted handle");
      for (int i =0; i<sizeof(handle); i++) {
      Serial.print(handle[i]);
      }
#endif
#ifdef US_VERSION
      aes_gcm_decrypt2(handle, (uint8_t*)sha256_hash, (uint8_t*)handlekey, 64);
#endif 
#ifdef DEBUG
      Serial.println();
      Serial.println("Unencrypted handle");
      for (int i =0; i<sizeof(handle); i++) {
      Serial.print(handle[i]);
      }
#endif
      uint8_t *key = handle + 32;

      if (memcmp(handle, application_parameter, 32)!=0) {
        //this handle is not from us
#ifdef DEBUG
		Serial.println("U2F Error SW_WRONG_DATA");
#endif
        respondErrorPDU(buffer, SW_WRONG_DATA);
        return;
      }

      if (P1==0x07) { //check-only
#ifdef DEBUG
		Serial.println("U2F Error SW_CONDITIONS_NOT_SATISFIED");
#endif
        respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
      } else if (P1==0x03) { //enforce-user-presence-and-sign
        int counter = getCounter();
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, application_parameter, 32);
        large_resp_buffer[0] = 0x01; // user_presence

        int ctr = ((counter>>24)&0xff) | // move byte 3 to byte 0
          ((counter<<8)&0xff0000) | // move byte 1 to byte 2
          ((counter>>8)&0xff00) | // move byte 2 to byte 1
          ((counter<<24)&0xff000000); // byte 0 to byte 3

        memcpy(large_resp_buffer + 1, &ctr, 4);

        sha256_update(&ctx, large_resp_buffer, 5); //user presence + ctr

        sha256_update(&ctx, challenge_parameter, 32);
        sha256_final(&ctx, sha256_hash);

        uint8_t *signature = resp_buffer; //temporary
        
        #ifdef US_VERSION
        uint8_t tmp[32 + 32 + 64];
		SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
        if (!uECC_sign_deterministic((uint8_t *)key,
							sha256_hash,
							32,
							&ectx.uECC,
							signature,
							curve)) {
#ifdef DEBUG
      	Serial.println("ECC Signature Failed Authenticate");
		//respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
      	//return;
#endif
      	}
		
      	//if (!uECC_verify((uint8_t *)attestation_pub+1, sha256_hash, 32, signature, curve)) {
#ifdef DEBUG
      	//Serial.println("ECC Verify Signature Failed Authenticate");
#endif
      	//respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
      	//return;
      	//}
	#endif	

        int len = 5;

        //convert signature format
        //http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
        large_resp_buffer[len++] = 0x30; //header: compound structure
        uint8_t *total_len = &large_resp_buffer[len];				
				large_resp_buffer[len++] = 0x44; //total length (32 + 32 + 2 + 2)
				large_resp_buffer[len++] = 0x02;  //header: integer

				if (signature[0]>0x7f) {
			   	   large_resp_buffer[len++] = 33;  //33 byte
				   large_resp_buffer[len++] = 0;
				   (*total_len)++; //update total length
				} else {
				   large_resp_buffer[len++] = 32;  //32 byte
				}
        memcpy(large_resp_buffer+len, signature, 32); //R value
        len +=32;
        large_resp_buffer[len++] = 0x02;  //header: integer

				if (signature[32]>0x7f) {
				    large_resp_buffer[len++] = 33;  //32 byte
				    large_resp_buffer[len++] = 0;
				    (*total_len)++;	//update total length
				} else {
				    large_resp_buffer[len++] = 32;  //32 byte
				}
        memcpy(large_resp_buffer+len, signature+32, 32); //R value
        len +=32;
        uint8_t *last = large_resp_buffer+len;
        APPEND_SW_NO_ERROR(last);
        len += 2;
#ifdef DEBUG
        Serial.print("Len to send ");
        Serial.println(len);
#endif
        u2f_button = 0;
        sendLargeResponse(buffer, len);
        setCounter(counter+1);
      } else {
#ifdef DEBUG
        Serial.println("return error");
#endif
      }
    }
    break;
  case U2F_INS_VERSION:
    {
      if (reqlength!=0) {
#ifdef DEBUG
		Serial.println("U2F Error SW_WRONG_LENGTH 636");
#endif
        respondErrorPDU(buffer, SW_WRONG_LENGTH);
        return;
      }
      //reuse input buffer for sending
      SET_MSG_LEN(buffer, 8); //len("U2F_V2") + 2 byte SW
      uint8_t *datapart = buffer + 7;
      memcpy(datapart, "U2F_V2", 6);
      datapart += 6;
      APPEND_SW_NO_ERROR(datapart);
      RawHID.send(buffer, 100);
    }
    break;
  default:
    {
#ifdef DEBUG
	  Serial.println("U2F Error SW_INS_NOT_SUPPORTED 651");
#endif
      respondErrorPDU(buffer, SW_INS_NOT_SUPPORTED);
    }
    ;
  }

}

void processPacket(uint8_t *buffer)
{
#ifdef DEBUG  
  Serial.print("Process CMD ");
#endif
  char cmd = buffer[4]; //cmd or continuation
#ifdef DEBUG
  Serial.println((int)cmd, HEX);
#endif

  int len = buffer[5] << 8 | buffer[6];
  if (cmd > U2FHID_INIT || cmd==U2FHID_LOCK) {
#ifdef DEBUG
	Serial.println("U2F Error ERR_INVALID_CMD 671");
#endif
    errorResponse(recv_buffer, ERR_INVALID_CMD);
    return;
  }
  if (cmd==U2FHID_PING) {
    if (len <= MAX_INITIAL_PACKET) {
#ifdef DEBUG      
      Serial.println("Sending ping response");
#endif      
      RawHID.send(buffer, 100);
    } else {
      //large packet
      //send first one
#ifdef DEBUG      
      Serial.println("SENT RESPONSE 3");
#endif      
      RawHID.send(buffer, 100);
      len -= MAX_INITIAL_PACKET;
      uint8_t p = 0;
      int offset = 7 + MAX_INITIAL_PACKET;
      while (len > 0) {
        memcpy(resp_buffer, buffer, 4); //copy cid
        resp_buffer[4] = p++;
        memcpy(resp_buffer + 5, buffer + offset, MAX_CONTINUATION_PACKET);
        RawHID.send(resp_buffer, 100);
        len-= MAX_CONTINUATION_PACKET;
        offset += MAX_CONTINUATION_PACKET;
        delayMicroseconds(2500);
      }
#ifdef DEBUG      
      Serial.println("Sending large ping response");
#endif      
    }
  }
  if (cmd==U2FHID_MSG) {
    processMessage(buffer);
  }

}

void setOtherTimeout()
{
  //we can process the data
  //but if we find another channel is waiting for continuation, we set it as timeout
  for (int i = 0; i < MAX_CHANNEL; i++) {
    if (channel_states[i].state==STATE_CHANNEL_WAIT_CONT) {
#ifdef DEBUG      
      Serial.println("Set other timeout");
#endif      
      channel_states[i].state= STATE_CHANNEL_TIMEOUT;
    }
  }

}

int cont_start = 0;

void recvu2fmsg(uint8_t *buffer) {

    //int cid = *(int*)recv_buffer;
	int cid; //handle strict-aliasing warning
	memcpy(&cid, buffer, sizeof(cid));	
#ifdef DEBUG    
    Serial.println(cid, HEX);
#endif    
    if (cid==0) { 
#ifdef DEBUG
	  Serial.println("U2F Error ERR_INVALID_CID 753");
#endif
      errorResponse(buffer, ERR_INVALID_CID);
      return;
    }
	   //Support for additional vendor defined commands
	unsigned char cmd_or_cont = buffer[4]; //cmd or continuation
    int len = (buffer[5]) << 8 | buffer[6];
	

#ifdef DEBUG
    if (IS_NOT_CONTINUATION_PACKET(cmd_or_cont)) {
      Serial.print(F("LEN "));
      Serial.println((int)len);
    }
#endif
 
    //don't care about cid
    if (cmd_or_cont==U2FHID_INIT) {
      setOtherTimeout();
      cid = initResponse(buffer);
      int cidx = find_channel_index(cid);
      channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
      return;
    }

    if (cid==-1) {
#ifdef DEBUG
	  Serial.println("U2F Error ERR_INVALID_CID 907");
#endif
      errorResponse(buffer, ERR_INVALID_CID);
      return;
    }

    int cidx = find_channel_index(cid);

    if (cidx==-1) {
#ifdef DEBUG      
      Serial.println("allocating new CID");
#endif      
      allocate_channel(cid);
      cidx = find_channel_index(cid);
      if (cidx==-1) {
#ifdef DEBUG
		Serial.println("U2F Error ERR_INVALID_CID 921");
#endif
        errorResponse(buffer, ERR_INVALID_CID);
        return;
      }

    }

    if (IS_NOT_CONTINUATION_PACKET(cmd_or_cont)) {

      if (len > MAX_TOTAL_PACKET) {
#ifdef DEBUG
	    Serial.println("U2F Error ERR_INVALID_LEN 931");
#endif
        errorResponse(buffer, ERR_INVALID_LEN); //invalid length
        return;
      }

      if (len > MAX_INITIAL_PACKET) {
        //if another channel is waiting for continuation, we respond with busy
        for (int i = 0; i < MAX_CHANNEL; i++) {
          if (channel_states[i].state==STATE_CHANNEL_WAIT_CONT) {
            if (i==cidx) {
              #ifdef DEBUG 
              Serial.println("U2F Error ERR_INVALID_SEQ 942");
              #endif 
              errorResponse(buffer, ERR_INVALID_SEQ); //invalid sequence
              channel_states[i].state= STATE_CHANNEL_WAIT_PACKET;
            } else {
              #ifdef DEBUG 
              Serial.println("U2F Error ERR_CHANNEL_BUSY 948");
              #endif 
              errorResponse(buffer, ERR_CHANNEL_BUSY);
              return;
            }

            return;
          }
        }
        //no other channel is waiting
        channel_states[cidx].state=STATE_CHANNEL_WAIT_CONT;
        cont_start = millis();
        memcpy(large_buffer, buffer, 64);
        large_data_len = len;
        large_data_offset = MAX_INITIAL_PACKET;
        expected_next_packet = 0;
        return;
      }

      setOtherTimeout();
      processPacket(buffer);
      channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
    } else {

      if (channel_states[cidx].state!=STATE_CHANNEL_WAIT_CONT) {
#ifdef DEBUG        
        Serial.println("ignoring stray packet");
        Serial.println(cid, HEX);
#endif        
        return;
      }

      //this is a continuation
      if (cmd_or_cont != expected_next_packet) {
#ifdef DEBUG 
        Serial.println("U2F Error ERR_INVALID_SEQ 984");
#endif 
        errorResponse(buffer, ERR_INVALID_SEQ); //invalid sequence
        channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
        return;
      } else {

        memcpy(large_buffer + large_data_offset + 7, buffer + 5, MAX_CONTINUATION_PACKET);
        large_data_offset += MAX_CONTINUATION_PACKET;

        if (large_data_offset < large_data_len) {
          expected_next_packet++;
#ifdef DEBUG          
          Serial.println("Expecting next cont");
#endif          
          return;
        }
#ifdef DEBUG        
        Serial.println("Completed");
#endif        
        channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
        processPacket(large_buffer);
        return;
      }
    }
}


void u2fmsgtimeout(uint8_t *buffer) {
	  
    for (int i = 0; i < MAX_CHANNEL; i++) {
      if (channel_states[i].state==STATE_CHANNEL_TIMEOUT) {
#ifdef DEBUG        
        Serial.println("send timeout");
        Serial.println(channel_states[i].cid, HEX);
#endif        
        memcpy(buffer, &channel_states[i].cid, 4);
#ifdef DEBUG
		Serial.println("U2F Error ERR_MSG_TIMEOUT 1017");
#endif
        errorResponse(buffer, ERR_MSG_TIMEOUT);
        channel_states[i].state= STATE_CHANNEL_WAIT_PACKET;

      }
      if (channel_states[i].state==STATE_CHANNEL_WAIT_CONT) {

        int now = millis();
        if ((now - channel_states[i].last_millis)>500) {
#ifdef DEBUG          
          Serial.println("SET timeout");
#endif          
          channel_states[i].state=STATE_CHANNEL_TIMEOUT;
        }
      }
    }	  
}

void init_SHA256(uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}
void update_SHA256(uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, message_size);
}
void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}
