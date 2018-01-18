
/* Tim Steiner
 * Copyright (c) 2018 , CryptoTrust LLC.
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
 
#include <Arduino.h>
#include "yksim.h"

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
    uint8_t length [2] = {0};
	yubikey_eeset_counter(length);
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

