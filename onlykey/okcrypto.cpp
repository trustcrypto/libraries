
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
#include <SoftTimer.h>


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
uint8_t rsa_publicN[MAX_RSA_KEY_SIZE];
uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
/*************************************/
/*************************************/
//ECC Authentication assignments
/*************************************/
uint8_t ecc_public_key[MAX_ECC_KEY_SIZE*2];
uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
/*************************************/
extern uint8_t Challenge_button1;
extern uint8_t Challenge_button2;
extern uint8_t Challenge_button3;
extern uint8_t CRYPTO_AUTH;
extern int outputU2F;
uint8_t type;
extern uint8_t resp_buffer[64];

extern int packet_buffer_offset;
extern uint8_t large_buffer[BUFFER_SIZE];

void SIGN (uint8_t *buffer) {
	uECC_set_rng(&RNG2); 
	#ifdef DEBUG
	Serial.println();
	Serial.println("OKSIGN MESSAGE RECEIVED"); 
	#endif
	bool signingkey;
	uint8_t features;
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
	features = onlykey_flashget_RSA ((int)buffer[5]);
	#ifdef DEBUG
	Serial.print(features, BIN);
	#endif
	signingkey = is_bit_set(features, 6);
	if (!signingkey) {
		#ifdef DEBUG
		Serial.print("Error key not set as signature key");
		#endif
		hidprint("Error key not set as signature key");
		return;
	}
	RSASIGN(buffer);
	} else {
	features = onlykey_flashget_ECC ((int)buffer[5]);
	#ifdef DEBUG
	Serial.print(features, BIN);
	#endif
	signingkey = is_bit_set(features, 6);
	#ifdef DEBUG
	Serial.print("before is bit set");
	#endif
	if (!signingkey) {
		#ifdef DEBUG
		Serial.print("Error key not set as signature key");
		#endif
		hidprint("Error key not set as signature key");
		return;
	}
	#ifdef DEBUG
	Serial.print("after is bit set");
	#endif
	ECDSA_EDDSA(buffer);
	#ifdef DEBUG
	Serial.print("after ECDSA_EDDSA");
	#endif
	}
}

void GETPUBKEY (uint8_t *buffer) {
	#ifdef DEBUG
	Serial.println();
	Serial.println("OKGETPUBKEY MESSAGE RECEIVED"); 
	#endif
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
	onlykey_flashget_RSA ((int)buffer[5]);
	GETRSAPUBKEY(buffer);
	} else {
	onlykey_flashget_ECC ((int)buffer[5]);	
	GETECCPUBKEY(buffer);
	}
}

void DECRYPT (uint8_t *buffer){
	uECC_set_rng(&RNG2); 
	#ifdef DEBUG
	Serial.println();
	Serial.println("OKDECRYPT MESSAGE RECEIVED"); 
	#endif
	if (buffer[5] < 101) { //Slot 101-132 are for ECC, 1-4 are for RSA
	uint8_t features = onlykey_flashget_RSA (buffer[5]);
	if (!is_bit_set(features, 5)) {
		hidprint("Error key not set as decryption key");
		return;
	}
	RSADECRYPT(buffer);
	} else {
	uint8_t features = onlykey_flashget_ECC (buffer[5]);	
	if (!is_bit_set(features, 5)) {
		hidprint("Error key not set as decryption key");
		return;
	}
	ECDH(buffer);
	}
}

void GETRSAPUBKEY (uint8_t *buffer)
{
#ifdef DEBUG
	byteprint(rsa_publicN, (type*128));
#endif
    if (!outputU2F){
	memcpy(resp_buffer, rsa_publicN, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	memcpy(resp_buffer, rsa_publicN+64, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	}
	if (type>=2 && !outputU2F) {
	memcpy(resp_buffer, rsa_publicN+128, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	memcpy(resp_buffer, rsa_publicN+192, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	} if (type>=3 && !outputU2F) {
	memcpy(resp_buffer, rsa_publicN+256, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	memcpy(resp_buffer, rsa_publicN+320, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	} if (type==4 && !outputU2F) {
	memcpy(resp_buffer, rsa_publicN+384, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	memcpy(resp_buffer, rsa_publicN+448, 64);
    RawHID.send(resp_buffer, 0);
	delay(100);
	} else if (outputU2F) {
	memcpy(large_buffer, rsa_publicN, (type*128));
	uint8_t *ptr = large_buffer+(type*128);
	APPEND_SW_NO_ERROR(ptr);
	sendLargeResponse(large_buffer, ((type*128)+2));	
	memset(large_buffer, 0, 514);
	outputU2F = 0;
	}
	blink(3);
}

void RSASIGN (uint8_t *buffer)
{
	extern int packet_buffer_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	uint8_t rsa_signature[(type*128)];

    if(!CRYPTO_AUTH) process_packets (buffer);
	else if (packet_buffer_offset != 28 || packet_buffer_offset != 32 || packet_buffer_offset != 48 || packet_buffer_offset != 64) {
	hidprint("Error with RSA data to sign invalid size");
	CRYPTO_AUTH=0;
	fadeoff();
	return;
	} else if (CRYPTO_AUTH == 4) {

#ifdef DEBUG
    Serial.println();
    Serial.printf("RSA data to sign size=%d", packet_buffer_offset);
	Serial.println();
	byteprint(large_buffer, packet_buffer_offset);
#endif
	// sign data in large_buffer 
    if (rsa_sign (packet_buffer_offset, large_buffer, rsa_signature) == 0)
	{
#ifdef DEBUG
		Serial.print("Signature = ");
	    byteprint(rsa_signature, sizeof(rsa_signature));
		Serial.println();
#endif
	if (!outputU2F){
	memcpy(resp_buffer, rsa_signature, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	memcpy(resp_buffer, rsa_signature+64, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	}
	if (type>=2 && !outputU2F) {
	memcpy(resp_buffer, rsa_signature+128, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	memcpy(resp_buffer, rsa_signature+192, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (type>=3 && !outputU2F) {
	memcpy(resp_buffer, rsa_signature+256, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	memcpy(resp_buffer, rsa_signature+320, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (type==4 && !outputU2F) {
	memcpy(resp_buffer, rsa_signature+384, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	memcpy(resp_buffer, rsa_signature+448, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} else if (outputU2F) {
	memcpy(large_buffer, rsa_signature, (type*128));
	uint8_t *ptr = large_buffer+(type*128);
	APPEND_SW_NO_ERROR(ptr);
    sendLargeResponse(large_buffer, ((type*128)+2));
	memset(large_buffer, 0, 514);
	outputU2F = 0;
	}
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
    packet_buffer_offset = 0;
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
    return;
	} else {
#ifdef DEBUG
    Serial.println("Waiting for challenge buttons to be pressed");
#endif
	}
}

void RSADECRYPT (uint8_t *buffer)
{
	extern int packet_buffer_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	size_t plaintext_len = 0;

    if(!CRYPTO_AUTH) process_packets (buffer);
	if (packet_buffer_offset != (type*128)) {
	hidprint("Error with RSA data to decrypt invalid size");
	CRYPTO_AUTH=0;
	fadeoff();
	return;
	}
	else if (CRYPTO_AUTH == 4) {
#ifdef DEBUG
    Serial.println();
    Serial.printf("RSA ciphertext blob size=%d", packet_buffer_offset);
	Serial.println();
	byteprint(large_buffer, packet_buffer_offset);
#endif
	// decrypt ciphertext in large_buffer to large_buffer
    if (rsa_decrypt (plaintext_len, large_buffer, large_buffer) == 0)
	{
#ifdef DEBUG
		Serial.println();
		Serial.print("Plaintext len = ");
		Serial.println(plaintext_len);
		Serial.print("Plaintext = ");
		byteprint(large_buffer, ((type*128)-11));
		Serial.println();
#endif
    if (!outputU2F){
	memcpy(resp_buffer, large_buffer, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	}
	if (plaintext_len > 64 && !outputU2F) {
	memcpy(resp_buffer, large_buffer+64, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (plaintext_len > 128 && !outputU2F) {
	memcpy(resp_buffer, large_buffer+128, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (plaintext_len > 192 && !outputU2F) {
	memcpy(resp_buffer, large_buffer+192, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (plaintext_len > 256 && !outputU2F) {
	memcpy(resp_buffer, large_buffer+256, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (plaintext_len > 320 && !outputU2F) {
	memcpy(resp_buffer, large_buffer+320, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (plaintext_len > 384 && !outputU2F) {
	memcpy(resp_buffer, large_buffer+384, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} if (plaintext_len > 448 && !outputU2F) {
	memcpy(resp_buffer, large_buffer+448, 64);
    RawHID.send(resp_buffer, 0);
	delay(10);
	} else if (outputU2F) {
	memcpy(large_buffer, ecc_public_key, 64);
	uint8_t *ptr = large_buffer+64;
	APPEND_SW_NO_ERROR(ptr);
    sendLargeResponse(large_buffer, (plaintext_len+2));
	outputU2F = 0;
	}
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
    packet_buffer_offset = 0;
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
			byteprint(ecc_public_key, MAX_ECC_KEY_SIZE*2);
	    #endif
            if (outputU2F) {
			memcpy(large_buffer, ecc_public_key, 64);
			uint8_t *ptr = large_buffer+64;
			APPEND_SW_NO_ERROR(ptr);
			sendLargeResponse(large_buffer, 64+2);
			memset(large_buffer, 0, 64+2); //wipe buffer
			outputU2F = 0;
			} else {
			RawHID.send(ecc_public_key, 0);
			}
			memset(ecc_public_key, 0, MAX_ECC_KEY_SIZE*2); //wipe buffer
			memset(ecc_private_key, 0, MAX_ECC_KEY_SIZE); //wipe buffer
            blink(3);
}

void ECDSA_EDDSA(uint8_t *buffer)
{
	extern int packet_buffer_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
	uint8_t ecc_signature[64];
#ifdef DEBUG
    Serial.println();
    Serial.println("OKECDSA_EDDSACHALLENGE MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) process_packets (buffer);
	else if (CRYPTO_AUTH == 4) {

#ifdef DEBUG
    Serial.println();
    Serial.printf("ECC challenge blob size=%d", packet_buffer_offset);
#endif
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
	// Sign the blob stored in the buffer
	if (type==0x01) Ed25519::sign(ecc_signature, ecc_private_key, ecc_public_key, large_buffer, packet_buffer_offset);
	else if (type==0x02) {
		    const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256
			uECC_sign_deterministic(ecc_private_key,
						large_buffer,
						packet_buffer_offset,
						&ectx.uECC,
						ecc_signature,
						curve);
	}
	else if (type==0x03) {
			const struct uECC_Curve_t * curve = uECC_secp256k1(); 
			uECC_sign_deterministic(ecc_private_key,
						large_buffer,
						packet_buffer_offset,
						&ectx.uECC,
						ecc_signature,
						curve);
	}
#ifdef DEBUG
	    for (uint8_t i = 0; i< sizeof(ecc_signature); i++) {
    	    Serial.print(ecc_signature[i],HEX);
     	    }
#endif
	if (outputU2F) {
	memcpy(large_buffer, ecc_signature, 64);
	uint8_t *ptr = large_buffer+64;
	APPEND_SW_NO_ERROR(ptr);
	sendLargeResponse(large_buffer, 64+2);
	memset(large_buffer, 0, 64+2);
	outputU2F = 0;
	} else{
	RawHID.send(ecc_signature, 0);
	}
	// Reset the large buffer offset
    packet_buffer_offset = 0;
	memset(large_buffer, 0, sizeof(large_buffer)); //wipe buffer
    // Stop the fade in
    fadeoff();
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
	memset(ecc_public_key, 0, sizeof(ecc_public_key)); //wipe buffer
	memset(ecc_private_key, 0, sizeof(ecc_private_key)); //wipe buffer
    return;
	} else {
#ifdef DEBUG
    Serial.println("Waiting for challenge buttons to be pressed");
#endif
	}
}


void ECDH(uint8_t *buffer)
{
	extern int packet_buffer_offset;
	extern uint8_t large_buffer[sizeof(large_buffer)];
    uint8_t ephemeral_pub[MAX_ECC_KEY_SIZE*2];
	uint8_t secret[MAX_ECC_KEY_SIZE];
#ifdef DEBUG
    Serial.println();
    Serial.println("OKECDH MESSAGE RECEIVED"); 
#endif
    if(!CRYPTO_AUTH) process_packets (buffer);
	else if (CRYPTO_AUTH == 4) {
	memcpy (ephemeral_pub, large_buffer, MAX_ECC_KEY_SIZE*2);
    if (shared_secret(ephemeral_pub, secret)) {
		hidprint("Error with ECC Shared Secret");
		return;
	}
#ifdef DEBUG
    Serial.println();
    Serial.print("Public key to generate shared secret for"); 
	for (int i = 0; i<= MAX_ECC_KEY_SIZE*2; i++) {
		Serial.print(ephemeral_pub[i],HEX);
		}
    Serial.println();
    Serial.print("ECDH Secret is "); 
	for (uint8_t i = 0; i< sizeof(secret); i++) {
		Serial.print(secret[i],HEX);
		}
#endif
	if (outputU2F) {
	memcpy(large_buffer, secret, 32);
	uint8_t *ptr = large_buffer+32;
	APPEND_SW_NO_ERROR(ptr);
	sendLargeResponse(large_buffer, 32+2);
	memset(large_buffer, 0, 32+2);
	outputU2F = 0;
	} else{
	RawHID.send(secret, 0);
	}
	//delay(100);
    // Reference - https://www.ietf.org/mail-archive/web/openpgp/current/msg00637.html
	// https://fossies.org/linux/misc/gnupg-2.1.17.tar.gz/gnupg-2.1.17/g10/ecdh.c
	// gcry_md_write(h, "\x00\x00\x00\x01", 4);      /* counter = 1 */
    // gcry_md_write(h, secret_x, secret_x_size);    /* x of the point X */
    // gcry_md_write(h, message, message_size);      /* KDF parameters */
	// This is a limitation as we have to be able to fit the entire message to decrypt
	// In this way RSA seems to have an advantage?
	// /* Build kdf_params.  */
    //{
    //IOBUF obuf;
    //
    //obuf = iobuf_temp();
    ///* variable-length field 1, curve name OID */
    //err = gpg_mpi_write_nohdr (obuf, pkey[0]);
    ///* fixed-length field 2 */
    //iobuf_put (obuf, PUBKEY_ALGO_ECDH);
    ///* variable-length field 3, KDF params */
    //err = (err ? err : gpg_mpi_write_nohdr (obuf, pkey[2]));
    ///* fixed-length field 4 */
    //iobuf_write (obuf, "Anonymous Sender    ", 20);
    ///* fixed-length field 5, recipient fp */
    //iobuf_write (obuf, pk_fp, 20);
    //
    //message_size = iobuf_temp_to_buffer (obuf, message, sizeof message);
	/*

	uint8_t hash_alg = large_buffer[0];
	uint8_t *pub_key = large_buffer+1;
	uint8_t *msg = large_buffer+1+32;
	uint8_t counter[] = "\x00\x00\x00\x01";
	uint8_t hash[64];
    mbedtls_sha512_context sha512;
	switch (hash_alg) {
		case 2: //sha256
		SHA256_CTX context;
		sha256_init(&context);
		sha256_update(&context, counter, 4); //add counter
		sha256_update(&context, secret, sizeof(secret)); //add secret
		sha256_update(&context, msg, (packet_buffer_offset-1-type)); //add message
		sha256_final(&context, hash); 
		break;
		case 3: //sha384
		mbedtls_sha512_init (&sha512);
		mbedtls_sha512_starts (&sha512, 1); //is 384
		mbedtls_sha512_update (&sha512, counter, 4); //add counter
		mbedtls_sha512_update (&sha512, secret, sizeof(secret)); //add secret
		mbedtls_sha512_update (&sha512, msg, (packet_buffer_offset-1-type)); //add message
		mbedtls_sha512_finish (&sha512, hash); 
		mbedtls_sha512_free (&sha512);
		break;
		case 5: //sha512
		mbedtls_sha512_init (&sha512);
		mbedtls_sha512_starts (&sha512, 0); //is not 384
		mbedtls_sha512_update (&sha512, counter, 4); //add counter
		mbedtls_sha512_update (&sha512, secret, sizeof(secret)); //add secret
		mbedtls_sha512_update (&sha512, msg, (packet_buffer_offset-1-sizeof(secret))); //add message
		mbedtls_sha512_finish (&sha512, hash); 
		mbedtls_sha512_free (&sha512);
		break;
		default:
		hidprint("Error hash algorithm incorrect");
		return;
	}
	//Send the KEK, client app should know the symmetric encryption alg
	//Depending on the alg the client will drop the uneeded tail of the the key
    
#ifdef DEBUG
    Serial.println();
    Serial.print("ECDH KEK is "); 
	for (int i = 0; i< sizeof(hash); i++) {
		Serial.print(hash[i],HEX);
		}
#endif
    RawHID.send(hash, 0);
	*/
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
    blink(3);
    // Reset the large buffer offset
    packet_buffer_offset = 0;
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

int shared_secret (uint8_t *ephemeral_pub, uint8_t *secret) {
	const struct uECC_Curve_t * curve;
	#ifdef DEBUG 
	Serial.printf("Shared Secret for type %X ",type);
	#endif
	switch (type) {
	case 1:
		if (Curve25519::dh2(ephemeral_pub, ecc_private_key)) {
		memcpy (secret, ephemeral_pub, 32);
		return 0;
		}
		else return 1;			
	case 2:
		curve = uECC_secp256r1(); 
		if (uECC_shared_secret(ephemeral_pub, ecc_private_key, secret, curve)) return 0;
		else return 1;	
	case 3:
		curve = uECC_secp256k1(); 
		if (uECC_shared_secret(ephemeral_pub, ecc_private_key, secret, curve)) return 0;
		else return 1;	
	default:
		hidprint("Error ECC type incorrect");
		return 1;
	}
}

int rsa_sign (int mlen, const uint8_t *msg, uint8_t *out)
{
	mbedtls_rsa_self_test(1);
	int ret = 0;
	static mbedtls_rsa_context rsa;
    uint8_t rsa_ciphertext[(type*128)];
	mbedtls_mpi P1, Q1, H;
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
	
	mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);
	rsa.len = (type*128);
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );
	
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa.N, &rsa.P, &rsa.Q) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );
	
	#ifdef DEBUG
	Serial.printf( "\nRSA len = " );
	Serial.println(rsa.len);
	#endif
	ret = mbedtls_rsa_check_privkey( &rsa );
	cleanup:
	mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);
	
   if( ret != 0 )
    {
		#ifdef DEBUG
	        Serial.printf("Error with key check =%d", ret);
	        #endif
		return -1;
	}
  if (ret == 0)
    {
      #ifdef DEBUG
      Serial.print("RSA sign messege length = ");
	  Serial.println(mlen);
	  #endif
	  if (mlen > ((type*128)-11)) mlen = ((type*128)-11);
      ret = mbedtls_rsa_rsassa_pkcs1_v15_sign (&rsa, mbedtls_rand, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE, mlen, msg, rsa_ciphertext);
      memcpy (out, rsa_ciphertext, (type*128));
	  int ret2 = mbedtls_rsa_rsassa_pkcs1_v15_verify ( &rsa, mbedtls_rand, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, mlen, msg, rsa_ciphertext );
	  if( ret2 != 0 ) {
		  #ifdef DEBUG
		  Serial.print("Signature Verification Failed ");
		  Serial.println(ret2);
		  #endif
		  return -1;
	  }
    }
  mbedtls_rsa_free (&rsa);
  if (ret == 0)
    {
    #ifdef DEBUG
    Serial.println("completed successfully");
	#endif
    return 0;
    }
  else
    {
	#ifdef DEBUG
	Serial.print("MBEDTLS_ERR_RSA_XXX error code ");
    Serial.println(ret);
	#endif
    return -1; 
    }
}

int rsa_decrypt (size_t olen, const uint8_t *in, uint8_t *out)
{
  mbedtls_mpi P1, Q1, H;
  int ret = 0;
  static mbedtls_rsa_context rsa;
  #ifdef DEBUG
  Serial.printf ("\nRSA decrypt:");
  Serial.println ((uint32_t)&ret);
  #endif

  mbedtls_rsa_init (&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);
  rsa.len = (type*128);
  MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], ((type*128) / 2) ));
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa.N, &rsa.P, &rsa.Q) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );
  #ifdef DEBUG
  Serial.println (rsa.len);
  #endif
  cleanup:
  mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);
  
	#ifdef DEBUG
	Serial.printf( "\nRSA len = " );
	Serial.println(rsa.len);
	#endif
  ret = mbedtls_rsa_check_privkey( &rsa ); 
	if (ret != 0) {
	  #ifdef DEBUG
      Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
	  Serial.println (ret);
	  #endif
	}
  if (ret == 0)
    {
	  #ifdef DEBUG
      Serial.print ("RSA decrypt ");
	  #endif
      ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt (&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, &olen, in, out, BUFFER_SIZE);
    }
  mbedtls_rsa_free (&rsa);
  if (ret == 0)
    {
	  #ifdef DEBUG
      Serial.print ("completed successfully");
	  #endif
      return 0;
    }
  else
    {
	  #ifdef DEBUG
      Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
	  Serial.println (ret);
	  #endif
      return -1;
    }
}


void rsa_getpub (uint8_t type)
{
  mbedtls_mpi P, Q, N;
  int ret = 0;
  #ifdef DEBUG
  Serial.print ("RSA generate public N:");
  #endif
  
  mbedtls_mpi_init (&P);  mbedtls_mpi_init (&Q);  mbedtls_mpi_init (&N);

  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&P, &rsa_private_key[0], ((type*128) / 2) ));
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&N, &P, &Q) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary (&N, &rsa_publicN[0], (type*128) ));
  cleanup:
  mbedtls_mpi_free (&P);  mbedtls_mpi_free (&Q);  mbedtls_mpi_free (&N);
  
  if (ret == 0)
    {
	  #ifdef DEBUG
      Serial.print ("Storing RSA public ");
	  byteprint(rsa_publicN, (type*128));
	  #endif
    } else {
	  hidprint("Error generating RSA public N");
	  #ifdef DEBUG
      Serial.print ("Error generating RSA public");
	  byteprint(rsa_publicN, (type*128));
	  #endif
	}
}

int rsa_encrypt (int len, const uint8_t *in, uint8_t *out)
{
	mbedtls_mpi P1, Q1, H;
	int ret = 0;
	static mbedtls_rsa_context rsa;
	#ifdef DEBUG
	Serial.printf ("\nRSA encrypt:");
	Serial.println ((uint32_t)&ret);
	#endif

	mbedtls_rsa_init (&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);
	rsa.len = (type*128);
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa.E, 0x10001) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.P, &rsa_private_key[0], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa.Q, &rsa_private_key[((type*128) / 2)], ((type*128) / 2) ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa.N, &rsa.P, &rsa.Q) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa.P, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa.Q, 1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.D , &rsa.E, &H) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DP, &rsa.D, &P1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa.DQ, &rsa.D, &Q1) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa.QP, &rsa.Q, &rsa.P) );
	#ifdef DEBUG
	Serial.println (rsa.len);
	#endif
	cleanup:
	mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);
  
	#ifdef DEBUG
	Serial.printf( "\nRSA len = " );
	Serial.println(rsa.len);
	#endif
  ret = mbedtls_rsa_check_pubkey( &rsa ); 
	if (ret != 0) {
	  #ifdef DEBUG
      Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
	  Serial.println (ret);
	  #endif
	  return ret;
	}
  if (ret == 0)
    {

	  ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt	( &rsa, mbedtls_rand, NULL, MBEDTLS_RSA_PUBLIC, len,
                           in, out );
    }
  mbedtls_rsa_free (&rsa);
  if (ret == 0)
    {
	  #ifdef DEBUG
      Serial.print ("completed successfully");
	  #endif
      return 0;
    }
  else
    {
	  #ifdef DEBUG
      Serial.print ("MBEDTLS_ERR_RSA_XXX error code ");
	  Serial.println (ret);
	  #endif
      return ret;
    }
}


bool is_bit_set(unsigned char byte, int index) {
  return (byte >> index) & 1;
}

int mbedtls_rand( void *rng_state, unsigned char *output, size_t len )
{
	if( rng_state != NULL )
        rng_state = NULL;
    RNG2( output, len );
    return( 0 );
}


#endif
