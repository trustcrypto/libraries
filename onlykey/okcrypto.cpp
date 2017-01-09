
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
 * 
 */

#include "okcrypto.h"
#include <SoftTimer.h>
#include <cstring>
#include "Arduino.h"
#include "onlykey.h"
#include "rsa.h"
#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "memory_buffer_alloc.h"
#endif

#ifdef US_VERSION

/*************************************/
//RSA assignments
/*************************************/
uint8_t rsa_signature[256];
uint8_t rsa_public_key[256];
uint8_t rsa_private_key[256];
//Temp assignments for RSA testing
//const unsigned char rsa_1024_test_private_key[] = "\x92\x92\x75\x84\x53\x06\x3D\x80\x3D\xD6\x03\xD5\xE7\x77\xD7\x88\x8E\xD1\xD5\xBF\x35\x78\x61\x90\xFA\x2F\x23\xEB\xC0\x84\x8A\xEA\xDD\xA9\x2C\xA6\xC3\xD8\x0B\x32\xC4\xD1\x09\xBE\x0F\x36\xD6\xAE\x71\x30\xB9\xCE\xD7\xAC\xDF\x54\xCF\xC7\x55\x5A\xC1\x4E\xEB\xAB\x93\xA8\x98\x13\xFB\xF3\xC4\xF8\x06\x6D\x2D\x80\x0F\x7C\x38\xA8\x1A\xE3\x19\x42\x91\x74\x03\xFF\x49\x46\xB0\xA8\x3D\x3D\x3E\x05\xEE\x57\xC6\xF5\xF5\x60\x6F\xB5\xD4\xBC\x6C\xD3\x4E\xE0\x80\x1A\x5E\x94\xBB\x77\xB0\x75\x07\x23\x3A\x0B\xC7\xBA\xC8\xF9\x0F\x79";
//const unsigned char rsa_test_PT[] = "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD";
//unsigned char rsa_plaintext[24];
//unsigned char rsa_decrypted[24];
//unsigned char rsa_ciphertext[128];
/*************************************/
/*************************************/
//ECC Authentication assignments
/*************************************/
const char ecc_stored_private_key[] = "\xF4\x2C\x74\xF8\x03\x50\xD0\x05\xEA\x82\x80\x1C\x95\xD2\x82\xCB\xB8\x1E\x6E\xF3\x63\xF7\x67\x59\xE8\x14\x0F\xBF\x31\x4D\x68\xA0";
uint8_t ecc_signature[64];
uint8_t ecc_public_key[32];
uint8_t ecc_private_key[32];
/*************************************/
uint8_t Challenge_button1 = 0;
uint8_t Challenge_button2 = 0;
uint8_t Challenge_button3 = 0;
uint8_t CRYPTO_AUTH = 0;
uint8_t type;
extern int large_data_offset;
extern uint8_t large_buffer[BUFFER_SIZE];

void SIGN (uint8_t *buffer) {
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
	type = onlykey_flashget_RSA (buffer[5]);
	SIGNRSA(buffer);
	} else {
	type = onlykey_flashget_ECC (buffer[5]);
	SIGNECC(buffer);
	}
}

void GETPUBKEY (uint8_t *buffer) {
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
	type = onlykey_flashget_RSA (buffer[5]);
	GETRSAPUBKEY(buffer);
	} else {
	type = onlykey_flashget_ECC (buffer[5]);	
	GETECCPUBKEY(buffer);
	}
}

void DECRYPT (uint8_t *buffer){
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
	type = onlykey_flashget_RSA (buffer[5]);
	DECRYPTRSA(buffer);
	} else {
	type = onlykey_flashget_ECC (buffer[5]);	
	DECRYPTECC(buffer);
	}
}

void GETRSAPUBKEY (uint8_t *buffer)
{
            #ifdef DEBUG
    	    Serial.println("OKGETRSAPUBKEY MESSAGE RECEIVED"); 
	    for (int i = 0; i< 32; i++) {
    	    Serial.print(rsa_public_key[i],HEX);
     	    }
	    #endif
            RawHID.send(rsa_public_key, 32);
			mbedtls_memory_buffer_alloc_init( large_buffer, sizeof(large_buffer) );
			int mbedtls_rsa_self_test( 1 );
            blink(3);
}

void SIGNRSA (uint8_t *buffer)
{
#ifdef DEBUG
    Serial.println();
    Serial.println("OKSIGNRSACHALLENGE MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) {
    // XXX(tsileo): on my system the challenge always seems to be 147 bytes, but I keep it dynamic
    // // since it may change.
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
    if (buffer[6]==0xFF) //Not last packet
    {
        if (large_data_offset <= (sizeof(large_buffer) - 57)) {
            memcpy(large_buffer+large_data_offset, buffer+7, 57);
            large_data_offset = large_data_offset + 57;
			return;
        } else {
              hidprint("Error RSA challenge too large");
			  return;
        }
        return;
    } else {
        if (large_data_offset <= (sizeof(large_buffer) - 57) && buffer[6] <= 57) {
            memcpy(large_buffer+large_data_offset, buffer+7, buffer[6]);
            large_data_offset = large_data_offset + buffer[6];
			CRYPTO_AUTH = 1;
			SHA256_CTX CRYPTO;
			sha256_init(&CRYPTO);
			sha256_update(&CRYPTO, large_buffer, large_data_offset); //add data to sign
			sha256_final(&CRYPTO, rsa_signature); //Temporarily store hash
			if (rsa_signature[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
			else {
				Challenge_button1 = rsa_signature[0] % 5; //Get the base 5 remainder (0-5)
				Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (rsa_signature[15] < 6) Challenge_button2 = '1'; //Convert last byte of hash
			else {
				Challenge_button2 = rsa_signature[15] % 5; //Get the base 5 remainder (0-5)
				Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (rsa_signature[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
			else {
				Challenge_button3 = rsa_signature[31] % 5; //Get the base 5 remainder (0-5)
				Challenge_button3 = Challenge_button3 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
#ifdef DEBUG
    Serial.println();
    Serial.printf("Enter challenge code %c%c%c", Challenge_button1,Challenge_button2,Challenge_button3); 
#endif
        } else {
            hidprint("Error RSA challenge too large");
			return;
        }
    }
	} else if (CRYPTO_AUTH == 4) {

#ifdef DEBUG
    Serial.println();
    Serial.printf("RSA challenge blob size=%d", large_data_offset);
#endif

	// Sign the blob stored in the buffer
	
	//int rsa_sign (const uint8_t *raw_message, uint8_t *output, int msg_len,struct key_data *kd, int pubkey_len){
	//TODO create struct key_data *kd from rsa_private_key[256]
	//rsa_sign(large_buffer, rsa_signature, large_data_offset, large_buffer, large_data_offset);

    // Reset the large buffer offset
    large_data_offset = 0;
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
    // Stop the fade in
    fadeoff();

    // Send the signature

#ifdef DEBUG
	    for (int i = 0; i< 256; i++) {
    	    Serial.print(rsa_signature[i],HEX);
     	    }
#endif
    RawHID.send(rsa_signature, 256);
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
	memset(rsa_signature, 0, 256); //wipe buffer
	memset(rsa_public_key, 0, 256); //wipe buffer
	memset(rsa_private_key, 0, 256); //wipe buffer
    return;
	} else {
#ifdef DEBUG
    Serial.println("Waiting for challenge buttons to be pressed");
#endif
	}
}

void DECRYPTRSA (uint8_t *buffer)
{
#ifdef DEBUG
    Serial.println();
    Serial.println("OKDECRYPTRSA MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) {
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
    if (buffer[6]==0xFF) //Not last packet
    {
        if (large_data_offset <= (sizeof(large_buffer) - 57)) {
            memcpy(large_buffer+large_data_offset, buffer+7, 57);
            large_data_offset = large_data_offset + 57;
			return;
        } else {
              hidprint("Error RSA challenge too large");
			  return;
        }
        return;
    } else {
        if (large_data_offset <= (sizeof(large_buffer) - 57) && buffer[6] <= 57) {
            memcpy(large_buffer+large_data_offset, buffer+7, buffer[6]);
            large_data_offset = large_data_offset + buffer[6];
			CRYPTO_AUTH = 1;
			SHA256_CTX CRYPTO;
			sha256_init(&CRYPTO);
			sha256_update(&CRYPTO, large_buffer, large_data_offset); //add data to sign
			sha256_final(&CRYPTO, rsa_signature); //Temporarily store hash
			if (rsa_signature[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
			else {
				Challenge_button1 = rsa_signature[0] % 5; //Get the base 5 remainder (0-5)
				Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (rsa_signature[15] < 6) Challenge_button2 = '1'; //Convert last byte of hash
			else {
				Challenge_button2 = rsa_signature[15] % 5; //Get the base 5 remainder (0-5)
				Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (rsa_signature[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
			else {
				Challenge_button3 = rsa_signature[31] % 5; //Get the base 5 remainder (0-5)
				Challenge_button3 = Challenge_button3 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
#ifdef DEBUG
    Serial.println();
    Serial.printf("Enter challenge code %c%c%c", Challenge_button1,Challenge_button2,Challenge_button3); 
#endif
        } else {
            hidprint("Error RSA challenge too large");
			return;
        }
    }
	} else if (CRYPTO_AUTH == 4) {

#ifdef DEBUG
    Serial.println();
    Serial.printf("RSA challenge blob size=%d", large_data_offset);
#endif


	// decrypt ciphertext to large_buffer
    
    // Stop the fade in
    fadeoff();

    // Send the plaintext

#ifdef DEBUG
	    for (int i = 0; i< sizeof(large_buffer); i++) {
    	    Serial.print(large_buffer[i],HEX);
     	    }
#endif
    RawHID.send(large_buffer, sizeof(large_buffer));
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
    // Reset the large buffer offset
    large_data_offset = 0;
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
    return;
	} else {
#ifdef DEBUG
    Serial.println("Waiting for challenge buttons to be pressed");
#endif
	}
}

void GETECCPUBKEY (uint8_t *buffer)
{
		onlykey_flashget_ECC (buffer[5]);        
			#ifdef DEBUG
    	    Serial.println("OKGETECCPUBKEY MESSAGE RECEIVED"); 
	    for (int i = 0; i< 32; i++) {
    	    Serial.print(ecc_public_key[i],HEX);
     	    }
	    #endif
            RawHID.send(ecc_public_key, 32);
			memset(ecc_public_key, 0, 32); //wipe buffer
			memset(ecc_private_key, 0, 32); //wipe buffer
            blink(3);
}

void SIGNECC(uint8_t *buffer)
{
#ifdef DEBUG
    Serial.println();
    Serial.println("OKSIGNECCCHALLENGE MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) {
    // XXX(tsileo): on my system the challenge always seems to be 147 bytes, but I keep it dynamic
    // // since it may change.
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
    if (buffer[6]==0xFF) //Not last packet
    {
        if (large_data_offset <= (sizeof(large_buffer) - 57)) {
            memcpy(large_buffer+large_data_offset, buffer+7, 57);
            large_data_offset = large_data_offset + 57;
			return;
        } else {
              hidprint("Error ECC challenge too large");
			  return;
        }
        return;
    } else {
        if (large_data_offset <= (sizeof(large_buffer) - 57) && buffer[6] <= 57) {
            memcpy(large_buffer+large_data_offset, buffer+7, buffer[6]);
            large_data_offset = large_data_offset + buffer[6];
			CRYPTO_AUTH = 1;
			SHA256_CTX CRYPTO;
			sha256_init(&CRYPTO);
			sha256_update(&CRYPTO, large_buffer, large_data_offset); //add data to sign
			sha256_final(&CRYPTO, ecc_signature); //Temporarily store hash
			if (ecc_signature[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
			else {
				Challenge_button1 = ecc_signature[0] % 5; //Get the base 5 remainder (0-5)
				Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (ecc_signature[15] < 6) Challenge_button2 = '1'; //Convert last byte of hash
			else {
				Challenge_button2 = ecc_signature[15] % 5; //Get the base 5 remainder (0-5)
				Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (ecc_signature[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
			else {
				Challenge_button3 = ecc_signature[31] % 5; //Get the base 5 remainder (0-5)
				Challenge_button3 = Challenge_button3 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
#ifdef DEBUG
    Serial.println();
    Serial.printf("Enter challenge code %c%c%c",Challenge_button1,Challenge_button2,Challenge_button3); 
#endif
        } else {
            hidprint("Error ECC challenge too large");
			return;
        }
    }
	} else if (CRYPTO_AUTH == 4) {

#ifdef DEBUG
    Serial.println();
    Serial.printf("ECC challenge blob size=%d", large_data_offset);
#endif

	const struct uECC_Curve_t * curves[2];
    int num_curves = 0;
    curves[num_curves++] = uECC_secp256r1();
    curves[num_curves++] = uECC_secp256k1();
	// Sign the blob stored in the buffer
	if (type==0x01) Ed25519::sign(ecc_signature, ecc_private_key, ecc_public_key, large_buffer, large_data_offset);
	else if (type==0x02) {
		uECC_sign(ecc_private_key, large_buffer, large_data_offset, ecc_signature, curves[1]);
	}
	else if (type==0x03) {
		uECC_sign(ecc_private_key, large_buffer, large_data_offset, ecc_signature, curves[2]);
	}
    
    // Reset the large buffer offset
    large_data_offset = 0;
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
    // Stop the fade in
    fadeoff();

    // Send the signature
    /* hidprint((const char*)ecc_signature); */
#ifdef DEBUG
	    for (int i = 0; i< 64; i++) {
    	    Serial.print(ecc_signature[i],HEX);
     	    }
#endif
    RawHID.send(ecc_signature, 64);
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
	memset(ecc_signature, 0, 64); //wipe buffer
	memset(ecc_public_key, 0, 32); //wipe buffer
	memset(ecc_private_key, 0, 32); //wipe buffer
    return;
	} else {
#ifdef DEBUG
    Serial.println("Waiting for challenge buttons to be pressed");
#endif
	}
}


void DECRYPTECC(uint8_t *buffer)
{
#ifdef DEBUG
    Serial.println();
    Serial.println("OKDECRYPTECC MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) {
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	uint8_t secret[32];
	uint8_t key[32];
    if (buffer[6]==0xFF) //Not last packet
    {
        if (large_data_offset <= (sizeof(large_buffer) - 57)) {
            memcpy(large_buffer+large_data_offset, buffer+7, 57);
            large_data_offset = large_data_offset + 57;
			return;
        } else {
              hidprint("Error ECC challenge too large");
			  return;
        }
        return;
    } else {
        if (large_data_offset <= (sizeof(large_buffer) - 57) && buffer[6] <= 57) {
            memcpy(large_buffer+large_data_offset, buffer+7, buffer[6]);
            large_data_offset = large_data_offset + buffer[6];
			CRYPTO_AUTH = 1;
			SHA256_CTX CRYPTO;
			sha256_init(&CRYPTO);
			sha256_update(&CRYPTO, large_buffer, large_data_offset); //add data to sign
			sha256_final(&CRYPTO, ecc_signature); //Temporarily store hash
			if (ecc_signature[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
			else {
				Challenge_button1 = ecc_signature[0] % 5; //Get the base 5 remainder (0-5)
				Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (ecc_signature[15] < 6) Challenge_button2 = '1'; //Convert middle byte of hash
			else {
				Challenge_button2 = ecc_signature[15] % 5; //Get the base 5 remainder (0-5)
				Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (ecc_signature[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
			else {
				Challenge_button3 = ecc_signature[31] % 5; //Get the base 5 remainder (0-5)
				Challenge_button3 = Challenge_button3 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
#ifdef DEBUG
    Serial.println();
    Serial.printf("Enter challenge code %c%c%c", Challenge_button1,Challenge_button2,Challenge_button3); 
#endif
        } else {
            hidprint("Error ECC challenge too large");
			return;
        }
    }
	} else if (CRYPTO_AUTH == 4) {

#ifdef DEBUG
    Serial.println();
    Serial.printf("ECC blob to decrypt size=%d", large_data_offset);
#endif

	const struct uECC_Curve_t * curves[2];
    int num_curves = 0;
    curves[num_curves++] = uECC_secp256r1();
    curves[num_curves++] = uECC_secp256k1();
	// Step 1. Determine the symmetric message encryption key algorithm
	// From RFC4880, for example, for AES -128 use 7, AES-256 use 9
	//following AES-256 session key, in which 32 octets are denoted from k0 to k31, is composed to form the following 40 octet sequence:
	// 09 k0 k1 ... k31 c0 c1 05 05 05 05 05
	//The octets c0 and c1 above denote the checksum
	
	
	
	
	//if (type==0x01) Ed25519::sign(ecc_signature, ecc_private_key, ecc_public_key, large_buffer, large_data_offset);
	//else if (type==0x02) {
	//	uECC_sign(ecc_private_key, large_buffer, large_data_offset, ecc_signature, curves[1]);
	//}
	//else if (type==0x03) {
	//	uECC_sign(ecc_private_key, large_buffer, large_data_offset, ecc_signature, curves[2]);
	//}
    

    // Stop the fade in
    fadeoff();

    // Send the plaintext

#ifdef DEBUG
	    for (int i = 0; i< sizeof(large_buffer); i++) {
    	    Serial.print(large_buffer[i],HEX);
     	    }
#endif
    RawHID.send(large_buffer, sizeof(large_buffer));
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
    // Reset the large buffer offset
    large_data_offset = 0;
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
    return;
	} else {
#ifdef DEBUG
    Serial.println("Waiting for challenge buttons to be pressed");
#endif
	}
}
#endif