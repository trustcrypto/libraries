
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
#include "oku2f.h"
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
uint8_t rsa_public_key[MAX_RSA_KEY_SIZE];
uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
/*************************************/
/*************************************/
//ECC Authentication assignments
/*************************************/
uint8_t ecc_public_key[MAX_ECC_KEY_SIZE];
uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
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
	if (!is_bit_set(type, 6)) {
		hidprint("Error key not set as signature key");
		return;
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
	if (!is_bit_set(type, 5)) {
		hidprint("Error key not set as decryption key");
		return;
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
            RawHID.send(rsa_public_key, (type*128));
            blink(3);
}

void SIGNRSA (uint8_t *buffer)
{
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	uint8_t temp[32];
	uint8_t rsa_signature[(type*128)];
#ifdef DEBUG
    Serial.println();
    Serial.println("OKSIGNRSACHALLENGE MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) {
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
			sha256_final(&CRYPTO, temp); //Temporarily store hash
			if (temp[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
			else {
				Challenge_button1 = temp[0] % 5; //Get the base 5 remainder (0-5)
				Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (temp[15] < 6) Challenge_button2 = '1'; //Convert last byte of hash
			else {
				Challenge_button2 = temp[15] % 5; //Get the base 5 remainder (0-5)
				Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (temp[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
			else {
				Challenge_button3 = temp[31] % 5; //Get the base 5 remainder (0-5)
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
	// sign data in large_buffer 
    if (rsa_sign (large_data_offset, large_buffer, rsa_signature) != 0)
	{
#ifdef DEBUG
		Serial.print("Signature = ");
	    for (int i = 0; i< sizeof(rsa_signature); i++) {
    	    Serial.print(rsa_signature[i],HEX);
     	    }
		Serial.println();
#endif
    RawHID.send(rsa_signature, sizeof(rsa_signature));
	} else {
		hidprint("Error with RSA signing");
	}
	fadeoff();
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

void DECRYPTRSA (uint8_t *buffer)
{
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	uint8_t temp[32];
	size_t plaintext_len;
#ifdef DEBUG
    Serial.println();
    Serial.println("OKDECRYPTRSA MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) {
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
			sha256_final(&CRYPTO, temp); //Temporarily store hash
			if (temp[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
			else {
				Challenge_button1 = temp[0] % 5; //Get the base 5 remainder (0-5)
				Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (temp[15] < 6) Challenge_button2 = '1'; //Convert last byte of hash
			else {
				Challenge_button2 = temp[15] % 5; //Get the base 5 remainder (0-5)
				Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (temp[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
			else {
				Challenge_button3 = temp[31] % 5; //Get the base 5 remainder (0-5)
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
	// decrypt ciphertext in large_buffer to large_buffer
    if (rsa_decrypt (large_data_offset, plaintext_len, large_buffer, large_buffer) != 0)
	{
#ifdef DEBUG
		Serial.print("Plaintext = ");
	    for (int i = 0; i< plaintext_len; i++) {
    	    Serial.print(large_buffer[i],HEX);
     	    }
		Serial.println();
#endif
    RawHID.send(large_buffer, plaintext_len);
	} else {
		hidprint("Error with RSA decryption");
	}
	fadeoff();
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
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	uint8_t ecc_signature[MAX_ECC_KEY_SIZE*2];
#ifdef DEBUG
    Serial.println();
    Serial.println("OKSIGNECCCHALLENGE MESSAGE RECEIVED"); 
#endif

    if(!CRYPTO_AUTH) {
    // XXX(tsileo): on my system the challenge always seems to be 147 bytes, but I keep it dynamic
    // // since it may change.
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
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
	// Sign the blob stored in the buffer
	if (type==0x01) Ed25519::sign(ecc_signature, ecc_private_key, ecc_public_key, large_buffer, large_data_offset);
	else if (type==0x02) {
		    const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256
			uECC_sign_deterministic(ecc_private_key,
						large_buffer,
						large_data_offset,
						&ectx.uECC,
						ecc_signature,
						curve);
	}
	else if (type==0x03) {
			const struct uECC_Curve_t * curve = uECC_secp256k1(); 
			uECC_sign_deterministic(ecc_private_key,
						large_buffer,
						large_data_offset,
						&ectx.uECC,
						ecc_signature,
						curve);
	}
#ifdef DEBUG
	    for (int i = 0; i< sizeof(ecc_signature); i++) {
    	    Serial.print(ecc_signature[i],HEX);
     	    }
#endif
    RawHID.send(ecc_signature, 64);
	// Reset the large buffer offset
    large_data_offset = 0;
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
    // Stop the fade in
    fadeoff();
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
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
	extern int large_data_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	uint8_t secret[32];
	uint8_t temp[32];
#ifdef DEBUG
    Serial.println();
    Serial.println("OKDECRYPTECC MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) {
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
			sha256_final(&CRYPTO, temp); //Temporarily store hash
			if (temp[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
			else {
				Challenge_button1 = temp[0] % 5; //Get the base 5 remainder (0-5)
				Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (temp[15] < 6) Challenge_button2 = '1'; //Convert middle byte of hash
			else {
				Challenge_button2 = temp[15] % 5; //Get the base 5 remainder (0-5)
				Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
			}
			if (temp[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
			else {
				Challenge_button3 = temp[31] % 5; //Get the base 5 remainder (0-5)
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
    Serial.printf("ECC blob to ECDH decrypt size=%d", large_data_offset);
#endif

	const struct uECC_Curve_t * curves[2];
    int num_curves = 0;
    curves[num_curves++] = uECC_secp256r1();
    curves[num_curves++] = uECC_secp256k1();
	
	//We need senders public key
    //use first 32 bytes of large_buffer
	if (type==0x01) {
		//mbedtls_ecdh_compute_shared
	}		
	else if (type==0x02) {
		uECC_shared_secret(large_buffer, ecc_private_key, secret, curves[1]);
	}
	else if (type==0x03) {
		uECC_shared_secret(large_buffer, ecc_private_key, secret, curves[2]);
	}
	// From https://github.com/kmackay/micro-ecc/blob/14222e062d77f45321676e813d9525f32a88e8fa/uECC.h
	// Note: It is recommended that you hash the result of uECC_shared_secret() before using it for
	// symmetric encryption or HMAC.
	// assuming SHA-256
	//SHA256_CTX CRYPTO;
	//sha256_init(&CRYPTO);
	//sha256_update(&CRYPTO, secret, sizeof(secret)); //add data to sign
	//sha256_final(&CRYPTO, secret); //store hash as secret
	
    // Send the secret for now - TODO, implement how GPG does this

#ifdef DEBUG
	for (int i = 0; i< sizeof(secret); i++) {
		Serial.print(secret[i],HEX);
		}
#endif
    RawHID.send(secret, sizeof(secret));
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
    // Reset the large buffer offset
    large_data_offset = 0;
	// Stop the fade in
    fadeoff();
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
	memset(secret, 0, sizeof(secret)); //wipe buffer
	memset(ecc_public_key, 0, sizeof(ecc_public_key)); //wipe buffer
	memset(ecc_private_key, 0, sizeof(ecc_private_key)); //wipe buffer
    return;
	} else {
#ifdef DEBUG
    Serial.println("Waiting for challenge buttons to be pressed");
#endif
	}
}

int rsa_sign (int mlen, uint8_t *msg, uint8_t *out)
{
	int ret = 0;
	static mbedtls_rsa_context rsa;
    uint8_t rsa_temp[(type*128)];
	mbedtls_mpi P1, Q1, H;
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
	
	mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);
	
	rsa.len = (type*128);
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], (type*128) / 2) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[(type*128) / 2], (type*128) / 2) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );
	cleanup:
	mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);
  if (ret == 0)
    {
      Serial.print("RSA sign");
      ret = mbedtls_rsa_rsassa_pkcs1_v15_sign (&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE, mlen, msg, rsa_temp);
      memcpy (out, rsa_temp, (type*128));
    }

  if (ret == 0)
    {
    Serial.println("completed successfully");
	mbedtls_rsa_free (&rsa);
    return 0;
    }
  else
    {
	Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
    Serial.println(ret);
	mbedtls_rsa_free (&rsa);
    return -1; 
    }
}

int rsa_decrypt (int mlen, size_t olen, const uint8_t *in, uint8_t *out)
{
  mbedtls_mpi P1, Q1, H;
  int ret;
  static mbedtls_rsa_context rsa;
  Serial.print ("RSA decrypt:");
  Serial.println ((uint32_t)&ret);

  mbedtls_rsa_init (&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);

  rsa.len = mlen;
  Serial.println (mlen);

  MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], mlen / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[mlen / 2], mlen / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );
  cleanup:
  mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);
  if (ret == 0)
    {
      Serial.print ("RSA decrypt ");
      ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt (&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, &olen, in, out, BUFFER_SIZE);
    }
  if (ret == 0)
    {
      Serial.print ("completed successfully");
      mbedtls_rsa_free (&rsa);
      return 0;
    }
  else
    {
      Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
	  mbedtls_rsa_free (&rsa);
      Serial.println (ret);
      return -1;
    }
}

bool is_bit_set(unsigned char byte, int index) {
  return (byte >> index) & 1;
}

#endif