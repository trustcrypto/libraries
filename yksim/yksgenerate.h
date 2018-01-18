
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

#ifndef YKS_GENERATE_H
#define YKS_GENERATE_H

#include <ykcore.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define	YUBIKEY_PUB_SIZE	16
#define YUBIKEY_OTP_MAXSIZE	((YUBIKEY_BLOCK_SIZE + YUBIKEY_PUB_SIZE) * 2 + 1)

typedef struct {
	uint8_t		key[YUBIKEY_KEY_SIZE];
	uint8_t		prv[YUBIKEY_UID_SIZE];
	uint8_t		pub[YUBIKEY_PUB_SIZE];
	uint8_t		publen;
	uint8_t		usage;
	uint16_t	counter;
	uint32_t	timestamp;
} yubikey_ctx_st;




typedef yubikey_ctx_st *yubikey_ctx_t;


#define EXIT_FAILURE	1
#define EXIT_SUCCESS	0

extern void yubikey_init1(
	yubikey_ctx_t	ctx,
	uint8_t		*aeskey,
	char		*yk_pubid1,
	char		*yk_prvid1,
	uint16_t	yk_counter,
	uint32_t	yk_time1,
	uint32_t	seed1);
	


extern void yubikey_simulate1(
        char		*otp,
	yubikey_ctx_t	ctx);
	


#define MAX_counter	0xffff
extern void yubikey_incr_timestamp (yubikey_ctx_t ctx);

extern int  yubikey_incr_counter   (yubikey_ctx_t ctx);

extern int  yubikey_incr_usage     (yubikey_ctx_t ctx);


#ifdef __cplusplus
}
#endif
#endif

