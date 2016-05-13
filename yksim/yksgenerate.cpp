/* yksgenerate.c --- adaption of libyubikey for Teensy 3.X
**
**  msd, 13-sep-2012:	based on code from https://github.com/Yubico/yubico-c
**  
*/

#include <Arduino.h>
#include "yksim.h"

/* ykgenerate.c --- Example command line interface for generating OTPs.
 *
 * Written by Olov Danielson <olov@yubico.com>.
 * Copyright (c) 2006-2012 Yubico AB
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
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/*********************************/

void yubikey_init1(
	yubikey_ctx_t	ctx,
	uint8_t		*aeskey,
	char		*yk_pubid1,
	char		*yk_prvid1,
	uint16_t	yk_counter,
	uint32_t	yk_time1,
	uint32_t	seed1)
{
    // store AES key
    memcpy ((char *) ctx->key, aeskey, YUBIKEY_KEY_SIZE);

    /* Fill up ctx with values */
    yubikey_hex_decode ((char *) ctx->prv, yk_prvid1, YUBIKEY_UID_SIZE);

    ctx->publen = strlen(yk_pubid1)/2;
    if (ctx->publen > YUBIKEY_PUB_SIZE) ctx->publen = YUBIKEY_PUB_SIZE;
    if (ctx->publen > 0) yubikey_hex_decode ((char *) ctx->pub, yk_pubid1, ctx->publen);

    ctx->usage = 0;
    ctx->counter = yk_counter;
    ctx->timestamp = yk_time1;

    /* Initiate pseudo-random generator */
    
    randomSeed (seed1);
}

/*********************************/

void yubikey_simulate1(
	char		*otp,
	yubikey_ctx_t	ctx)
{
    yubikey_token_st tok1;
    char pubid1[YUBIKEY_OTP_SIZE];
    char block1[YUBIKEY_OTP_SIZE];

    /* Fill up tok with values */
    memcpy ((char *) &tok1.uid, ctx->prv, YUBIKEY_UID_SIZE);

    tok1.use = ctx->usage;
    tok1.ctr = ctx->counter;

    // time stamp
    tok1.tstpl = (uint16_t) ctx->timestamp & 0xffff;
    tok1.tstph = (uint8_t) (ctx->timestamp >> 16) & 0xff;

    tok1.rnd = random (0x10000);
    tok1.crc = ~yubikey_crc16 ((const uint8_t *) &tok1, sizeof (tok1) - sizeof (tok1.crc));

    if (ctx->publen > 0) {
	yubikey_modhex_encode (pubid1, (const char *) ctx->pub, ctx->publen);
	memcpy ((char *) otp, pubid1, 2*ctx->publen+1);
	otp += 2*ctx->publen;
    }

    yubikey_generate (&tok1, ctx->key, block1);
    memcpy ((char *) otp, block1, 2*YUBIKEY_BLOCK_SIZE+1);
}

/*********************************/


void yubikey_incr_timestamp(
	yubikey_ctx_t	ctx)
{
    ctx->timestamp += 1;
}

void yubikey_disable_eeprom()
{
    uint8_t length = 0;
    yubikey_eeset_keylen (&length);
    yubikey_eeset_ctrlen (&length);
    yubikey_eeset_prvlen (&length);
    yubikey_eeset_publen (&length);
    onlykey_eeset_passwordlen1 (&length);
    onlykey_eeset_passwordlen2 (&length);
    onlykey_eeset_passwordlen3 (&length);
    onlykey_eeset_passwordlen4 (&length);
    onlykey_eeset_passwordlen5 (&length);
    onlykey_eeset_passwordlen6 (&length);
    onlykey_eeset_passwordlen7 (&length);
    onlykey_eeset_passwordlen8 (&length);
    onlykey_eeset_passwordlen9 (&length);
    onlykey_eeset_passwordlen10 (&length);
    onlykey_eeset_passwordlen11 (&length);
    onlykey_eeset_passwordlen12 (&length);
	
}

int yubikey_incr_counter(
	yubikey_ctx_t	ctx)
{
    if (ctx->counter >= MAX_counter) {
	// End-Of-Life for YubiKey 
	yubikey_disable_eeprom();
	// Reset needed!
	return EXIT_FAILURE;
    } else {
	ctx->counter += 1;
	yubikey_eeset_counter ((uint8_t *) &(ctx->counter));
	return EXIT_SUCCESS;
    }
}

int yubikey_incr_usage(
	yubikey_ctx_t	ctx)
{
    if (ctx->usage == 0xff) {
	ctx->usage = 0;
	return yubikey_incr_counter (ctx);
    } else {
	ctx->usage += 1;
	return EXIT_SUCCESS;
    }
}


/*********************************/

