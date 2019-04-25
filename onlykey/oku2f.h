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


#include "uECC.h"
#include "sha256.h"
#include "T3MacLib.h"
#include "onlykey.h"
#include <newhope.h>
#include "tweetnacl.h"

#ifdef US_VERSION

#ifdef OKSOLO
#include "ctap.h"
#include "ctaphid.h"
#include "cbor.h"
#include "device.h"
#include "storage.h"
#include "extensions/wallet.h"
#include "extensions/extensions.h"
#define NVIC_SystemReset CPU_RESTART
// Storage of FIDO2 resident keys
#define PAGE_SIZE		2048
#define PAGES			2
#define RK_NUM_PAGES    10
#define RK_START_PAGE   (PAGES - 14)
#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)     // not included
#define DEBUG_LEVEL 0
#define ENABLE_U2F
//#define ENABLE_U2F_EXTENSIONS
//#define BRIDGE_TO_WALLET
#endif
 
#ifndef OKU2F_H
#define OKU2F_H


typedef struct SHA256_HashContext{
    const uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

#ifdef __cplusplus
extern "C"
{
#endif

/*************************************/
//U2F assignments
/*************************************/
#define MAX_INITIAL_PACKET 57
#define MAX_CONTINUATION_PACKET 59
#define SET_MSG_LEN(b, v) do { (b)[5] = ((v) >> 8) & 0xff;  (b)[6] = (v) & 0xff; } while(0)

#define IS_CONTINUATION_PACKET(x) ( (x) < 0x80)
#define IS_NOT_CONTINUATION_PACKET(x) ( (x) >= 0x80)

#define U2FHID_MSG          (TYPE_INIT | 0x03)  // Send U2F message frame
#define U2FHID_ERROR        (TYPE_INIT | 0x3f)  // Error response

#define SW_CONDITIONS_NOT_SATISFIED       0x6985

#define APPEND_SW(x, v1, v2) do { (*x++)=v1; (*x++)=v2;} while (0)
#define APPEND_SW_NO_ERROR(x) do { (*x++)=0x90; (*x++)=0x00;} while (0)
	
/*************************************/
extern void sendLargeResponse(uint8_t *request, int len);
extern void fido_msg_timeout(uint8_t *buffer);
extern void recv_fido_msg(uint8_t *buffer);
extern void init_SHA256(const uECC_HashContext *base);
extern void update_SHA256(const uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size);                   
extern void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result);
extern void U2Finit();
extern void store_U2F_response (uint8_t *data, int len, bool encrypt);
extern void send_U2F_response(uint8_t *buffer);
extern void custom_error (uint8_t code);
extern void handle_firefox_u2f (uint8_t *msgid);
extern int recv_custom_msg(uint8_t *data, uint8_t *buffer);

#ifdef __cplusplus
}
#endif
#endif
#endif
