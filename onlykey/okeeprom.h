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


#ifndef OK_EEPROM_H
#define OK_EEPROM_H

#ifdef __cplusplus
extern "C"
{
#endif

#define EElen_noncehash	32
#define EElen_pinhash	32
#define EElen_selfdestructhash	32
#define EElen_2ndpinhash	32
#define EElen_aeskey	16
#define EElen_public	6
#define EElen_private	6
#define EElen_counter	2
#define EElen_label	16
#define EElen_username	56
#define EElen_url	56
#define EElen_addchar	1
#define EElen_delay	1
#define EElen_password	56
#define EElen_2FAtype	1
#define EElen_totpkey	64
#define EElen_keylen	1
#define EElen_ctrlen	1
#define EElen_prvlen	1
#define EElen_publen	1
#define EElen_passwordlen	1
#define EElen_labellen	1
#define EElen_usernamelen	1
#define EElen_urllen	1
#define EElen_totpkeylen	1
#define EElen_U2Fprivlen	1
#define EElen_U2Fcertlen	2
#define EElen_flashpos		1
#define EElen_failedlogins	1
#define EElen_sincelastregularlogin	1
#define EElen_U2Fcounter	4
#define EElen_backupkey	1
#define EElen_timeout	1
#define EElen_wipemode	1
#define EElen_backupkeymode	1
#define EElen_sshchallengemode	1
#define EElen_pgpchallengemode	1
#define EElen_2ndprofilemode	1
#define EElen_typespeed	1
#define EElen_keyboardlayout	1
#define EElen_ecckey	1
#define EElen_rsakey	1

#define EEpos_U2Fcounter	66 // 0 used for bootloader jump flag, 1 used for fwload flag, 2-65 used for fw integrity hash
#define EEpos_aeskey	(EEpos_U2Fcounter + EElen_U2Fcounter)
#define EEpos_public	(EEpos_aeskey + EElen_aeskey)
#define EEpos_private	(EEpos_public + EElen_public)
#define EEpos_counter	(EEpos_private + EElen_private)

#define EEpos_url1len	(EEpos_counter + EElen_counter)
#define EEpos_url2len	(EEpos_url1len + EElen_urllen)
#define EEpos_url3len	(EEpos_url2len + EElen_urllen)
#define EEpos_url4len	(EEpos_url3len + EElen_urllen)
#define EEpos_url5len	(EEpos_url4len + EElen_urllen)
#define EEpos_url6len	(EEpos_url5len + EElen_urllen)
#define EEpos_url7len	(EEpos_url6len + EElen_urllen)
#define EEpos_url8len	(EEpos_url7len + EElen_urllen)
#define EEpos_url9len	(EEpos_url8len + EElen_urllen)
#define EEpos_url10len	(EEpos_url9len + EElen_urllen)
#define EEpos_url11len	(EEpos_url10len + EElen_urllen)
#define EEpos_url12len	(EEpos_url11len + EElen_urllen)
#define EEpos_url13len	(EEpos_url12len + EElen_urllen)
#define EEpos_url14len	(EEpos_url13len + EElen_urllen)
#define EEpos_url15len	(EEpos_url14len + EElen_urllen)
#define EEpos_url16len	(EEpos_url15len + EElen_urllen)
#define EEpos_url17len	(EEpos_url16len + EElen_urllen)
#define EEpos_url18len	(EEpos_url17len + EElen_urllen)
#define EEpos_url19len	(EEpos_url18len + EElen_urllen)
#define EEpos_url20len	(EEpos_url19len + EElen_urllen)
#define EEpos_url21len	(EEpos_url20len + EElen_urllen)
#define EEpos_url22len	(EEpos_url21len + EElen_urllen)
#define EEpos_url23len	(EEpos_url22len + EElen_urllen)
#define EEpos_url24len	(EEpos_url23len + EElen_urllen)

#define EEpos_addchar_1	(EEpos_url24len + EElen_urllen)
#define EEpos_addchar_2	(EEpos_addchar_1 + EElen_addchar)
#define EEpos_addchar_3	(EEpos_addchar_2 + EElen_addchar)
#define EEpos_addchar_4	(EEpos_addchar_3 + EElen_addchar)
#define EEpos_addchar_5	(EEpos_addchar_4 + EElen_addchar)
#define EEpos_addchar_6	(EEpos_addchar_5 + EElen_addchar)
#define EEpos_addchar_7	(EEpos_addchar_6 + EElen_addchar)
#define EEpos_addchar_8	(EEpos_addchar_7 + EElen_addchar)
#define EEpos_addchar_9	(EEpos_addchar_8 + EElen_addchar)
#define EEpos_addchar_10	(EEpos_addchar_9 + EElen_addchar)
#define EEpos_addchar_11	(EEpos_addchar_10 + EElen_addchar)
#define EEpos_addchar_12	(EEpos_addchar_11 + EElen_addchar)
#define EEpos_addchar_13	(EEpos_addchar_12 + EElen_addchar)
#define EEpos_addchar_14	(EEpos_addchar_13 + EElen_addchar)
#define EEpos_addchar_15	(EEpos_addchar_14 + EElen_addchar)
#define EEpos_addchar_16	(EEpos_addchar_15 + EElen_addchar)
#define EEpos_addchar_17	(EEpos_addchar_16 + EElen_addchar)
#define EEpos_addchar_18	(EEpos_addchar_17 + EElen_addchar)
#define EEpos_addchar_19	(EEpos_addchar_18 + EElen_addchar)
#define EEpos_addchar_20	(EEpos_addchar_19 + EElen_addchar)
#define EEpos_addchar_21	(EEpos_addchar_20 + EElen_addchar)
#define EEpos_addchar_22	(EEpos_addchar_21 + EElen_addchar)
#define EEpos_addchar_23	(EEpos_addchar_22 + EElen_addchar)
#define EEpos_addchar_24	(EEpos_addchar_23 + EElen_addchar)

#define EEpos_delay1_1	(EEpos_addchar_24 + EElen_addchar)
#define EEpos_delay1_2	(EEpos_delay1_1 + EElen_delay)
#define EEpos_delay1_3	(EEpos_delay1_2 + EElen_delay)
#define EEpos_delay1_4	(EEpos_delay1_3 + EElen_delay)
#define EEpos_delay1_5	(EEpos_delay1_4 + EElen_delay)
#define EEpos_delay1_6	(EEpos_delay1_5 + EElen_delay)
#define EEpos_delay1_7	(EEpos_delay1_6 + EElen_delay)
#define EEpos_delay1_8	(EEpos_delay1_7 + EElen_delay)
#define EEpos_delay1_9	(EEpos_delay1_8 + EElen_delay)
#define EEpos_delay1_10	(EEpos_delay1_9 + EElen_delay)
#define EEpos_delay1_11	(EEpos_delay1_10 + EElen_delay)
#define EEpos_delay1_12	(EEpos_delay1_11 + EElen_delay)
#define EEpos_delay1_13	(EEpos_delay1_12 + EElen_delay)
#define EEpos_delay1_14	(EEpos_delay1_13 + EElen_delay)
#define EEpos_delay1_15	(EEpos_delay1_14 + EElen_delay)
#define EEpos_delay1_16	(EEpos_delay1_15 + EElen_delay)
#define EEpos_delay1_17	(EEpos_delay1_16 + EElen_delay)
#define EEpos_delay1_18	(EEpos_delay1_17 + EElen_delay)
#define EEpos_delay1_19	(EEpos_delay1_18 + EElen_delay)
#define EEpos_delay1_20	(EEpos_delay1_19 + EElen_delay)
#define EEpos_delay1_21	(EEpos_delay1_20 + EElen_delay)
#define EEpos_delay1_22	(EEpos_delay1_21 + EElen_delay)
#define EEpos_delay1_23	(EEpos_delay1_22 + EElen_delay)
#define EEpos_delay1_24	(EEpos_delay1_23 + EElen_delay)

#define EEpos_username1len	(EEpos_delay1_24 + EElen_delay)
#define EEpos_username2len	(EEpos_username1len + EElen_usernamelen)
#define EEpos_username3len	(EEpos_username2len + EElen_usernamelen)
#define EEpos_username4len	(EEpos_username3len + EElen_usernamelen)
#define EEpos_username5len	(EEpos_username4len + EElen_usernamelen)
#define EEpos_username6len	(EEpos_username5len + EElen_usernamelen)
#define EEpos_username7len	(EEpos_username6len + EElen_usernamelen)
#define EEpos_username8len	(EEpos_username7len + EElen_usernamelen)
#define EEpos_username9len	(EEpos_username8len + EElen_usernamelen)
#define EEpos_username10len	(EEpos_username9len + EElen_usernamelen)
#define EEpos_username11len	(EEpos_username10len + EElen_usernamelen)
#define EEpos_username12len	(EEpos_username11len + EElen_usernamelen)
#define EEpos_username13len	(EEpos_username12len + EElen_usernamelen)
#define EEpos_username14len	(EEpos_username13len + EElen_usernamelen)
#define EEpos_username15len	(EEpos_username14len + EElen_usernamelen)
#define EEpos_username16len	(EEpos_username15len + EElen_usernamelen)
#define EEpos_username17len	(EEpos_username16len + EElen_usernamelen)
#define EEpos_username18len	(EEpos_username17len + EElen_usernamelen)
#define EEpos_username19len	(EEpos_username18len + EElen_usernamelen)
#define EEpos_username20len	(EEpos_username19len + EElen_usernamelen)
#define EEpos_username21len	(EEpos_username20len + EElen_usernamelen)
#define EEpos_username22len	(EEpos_username21len + EElen_usernamelen)
#define EEpos_username23len	(EEpos_username22len + EElen_usernamelen)
#define EEpos_username24len	(EEpos_username23len + EElen_usernamelen)

#define EEpos_delay2_1	(EEpos_username24len + EElen_usernamelen)
#define EEpos_delay2_2	(EEpos_delay2_1 + EElen_delay)
#define EEpos_delay2_3	(EEpos_delay2_2 + EElen_delay)
#define EEpos_delay2_4	(EEpos_delay2_3 + EElen_delay)
#define EEpos_delay2_5	(EEpos_delay2_4 + EElen_delay)
#define EEpos_delay2_6	(EEpos_delay2_5 + EElen_delay)
#define EEpos_delay2_7	(EEpos_delay2_6 + EElen_delay)
#define EEpos_delay2_8	(EEpos_delay2_7 + EElen_delay)
#define EEpos_delay2_9	(EEpos_delay2_8 + EElen_delay)
#define EEpos_delay2_10	(EEpos_delay2_9 + EElen_delay)
#define EEpos_delay2_11	(EEpos_delay2_10 + EElen_delay)
#define EEpos_delay2_12	(EEpos_delay2_11 + EElen_delay)
#define EEpos_delay2_13	(EEpos_delay2_12 + EElen_delay)
#define EEpos_delay2_14	(EEpos_delay2_13 + EElen_delay)
#define EEpos_delay2_15	(EEpos_delay2_14 + EElen_delay)
#define EEpos_delay2_16	(EEpos_delay2_15 + EElen_delay)
#define EEpos_delay2_17	(EEpos_delay2_16 + EElen_delay)
#define EEpos_delay2_18	(EEpos_delay2_17 + EElen_delay)
#define EEpos_delay2_19	(EEpos_delay2_18 + EElen_delay)
#define EEpos_delay2_20	(EEpos_delay2_19 + EElen_delay)
#define EEpos_delay2_21	(EEpos_delay2_20 + EElen_delay)
#define EEpos_delay2_22	(EEpos_delay2_21 + EElen_delay)
#define EEpos_delay2_23	(EEpos_delay2_22 + EElen_delay)
#define EEpos_delay2_24	(EEpos_delay2_23 + EElen_delay)

#define EEpos_password1	(EEpos_delay2_24 + EElen_delay)
#define EEpos_password2	(EEpos_password1 + EElen_password)
#define EEpos_password3	(EEpos_password2 + EElen_password)
#define EEpos_password4	(EEpos_password3 + EElen_password)
#define EEpos_password5	(EEpos_password4 + EElen_password)
#define EEpos_password6	(EEpos_password5 + EElen_password)
#define EEpos_password7	(EEpos_password6 + EElen_password)
#define EEpos_password8	(EEpos_password7 + EElen_password)
#define EEpos_password9	(EEpos_password8 + EElen_password)
#define EEpos_password10	(EEpos_password9 + EElen_password)
#define EEpos_password11	(EEpos_password10 + EElen_password)
#define EEpos_password12	(EEpos_password11 + EElen_password)
#define EEpos_password13	(EEpos_password12 + EElen_password)
#define EEpos_password14	(EEpos_password13 + EElen_password)
#define EEpos_password15	(EEpos_password14 + EElen_password)
#define EEpos_password16	(EEpos_password15 + EElen_password)
#define EEpos_password17	(EEpos_password16 + EElen_password)
#define EEpos_password18	(EEpos_password17 + EElen_password)
#define EEpos_password19	(EEpos_password18 + EElen_password)
#define EEpos_password20	(EEpos_password19 + EElen_password)
#define EEpos_password21	(EEpos_password20 + EElen_password)
#define EEpos_password22	(EEpos_password21 + EElen_password)
#define EEpos_password23	(EEpos_password22 + EElen_password)
#define EEpos_password24	(EEpos_password23 + EElen_password)

#define EEpos_password1len	(EEpos_password24 + EElen_password)
#define EEpos_password2len	(EEpos_password1len + EElen_passwordlen)
#define EEpos_password3len	(EEpos_password2len + EElen_passwordlen)
#define EEpos_password4len	(EEpos_password3len + EElen_passwordlen)
#define EEpos_password5len	(EEpos_password4len + EElen_passwordlen)
#define EEpos_password6len	(EEpos_password5len + EElen_passwordlen)
#define EEpos_password7len	(EEpos_password6len + EElen_passwordlen)
#define EEpos_password8len	(EEpos_password7len + EElen_passwordlen)
#define EEpos_password9len	(EEpos_password8len + EElen_passwordlen)
#define EEpos_password10len	(EEpos_password9len + EElen_passwordlen)
#define EEpos_password11len	(EEpos_password10len + EElen_passwordlen)
#define EEpos_password12len	(EEpos_password11len + EElen_passwordlen)
#define EEpos_password13len	(EEpos_password12len + EElen_passwordlen)
#define EEpos_password14len	(EEpos_password13len + EElen_passwordlen)
#define EEpos_password15len	(EEpos_password14len + EElen_passwordlen)
#define EEpos_password16len	(EEpos_password15len + EElen_passwordlen)
#define EEpos_password17len	(EEpos_password16len + EElen_passwordlen)
#define EEpos_password18len	(EEpos_password17len + EElen_passwordlen)
#define EEpos_password19len	(EEpos_password18len + EElen_passwordlen)
#define EEpos_password20len	(EEpos_password19len + EElen_passwordlen)
#define EEpos_password21len	(EEpos_password20len + EElen_passwordlen)
#define EEpos_password22len	(EEpos_password21len + EElen_passwordlen)
#define EEpos_password23len	(EEpos_password22len + EElen_passwordlen)
#define EEpos_password24len	(EEpos_password23len + EElen_passwordlen)

#define EEpos_delay3_1	(EEpos_password24len + EElen_passwordlen)
#define EEpos_delay3_2	(EEpos_delay3_1 + EElen_delay)
#define EEpos_delay3_3	(EEpos_delay3_2 + EElen_delay)
#define EEpos_delay3_4	(EEpos_delay3_3 + EElen_delay)
#define EEpos_delay3_5	(EEpos_delay3_4 + EElen_delay)
#define EEpos_delay3_6	(EEpos_delay3_5 + EElen_delay)
#define EEpos_delay3_7	(EEpos_delay3_6 + EElen_delay)
#define EEpos_delay3_8	(EEpos_delay3_7 + EElen_delay)
#define EEpos_delay3_9	(EEpos_delay3_8 + EElen_delay)
#define EEpos_delay3_10	(EEpos_delay3_9 + EElen_delay)
#define EEpos_delay3_11	(EEpos_delay3_10 + EElen_delay)
#define EEpos_delay3_12	(EEpos_delay3_11 + EElen_delay)
#define EEpos_delay3_13	(EEpos_delay3_12 + EElen_delay)
#define EEpos_delay3_14	(EEpos_delay3_13 + EElen_delay)
#define EEpos_delay3_15	(EEpos_delay3_14 + EElen_delay)
#define EEpos_delay3_16	(EEpos_delay3_15 + EElen_delay)
#define EEpos_delay3_17	(EEpos_delay3_16 + EElen_delay)
#define EEpos_delay3_18	(EEpos_delay3_17 + EElen_delay)
#define EEpos_delay3_19	(EEpos_delay3_18 + EElen_delay)
#define EEpos_delay3_20	(EEpos_delay3_19 + EElen_delay)
#define EEpos_delay3_21	(EEpos_delay3_20 + EElen_delay)
#define EEpos_delay3_22	(EEpos_delay3_21 + EElen_delay)
#define EEpos_delay3_23	(EEpos_delay3_22 + EElen_delay)
#define EEpos_delay3_24	(EEpos_delay3_23 + EElen_delay)

#define EEpos_2FAtype1	(EEpos_delay3_24 + EElen_delay)
#define EEpos_2FAtype2	(EEpos_2FAtype1 + EElen_2FAtype)
#define EEpos_2FAtype3	(EEpos_2FAtype2 + EElen_2FAtype)
#define EEpos_2FAtype4	(EEpos_2FAtype3 + EElen_2FAtype)
#define EEpos_2FAtype5	(EEpos_2FAtype4 + EElen_2FAtype)
#define EEpos_2FAtype6	(EEpos_2FAtype5 + EElen_2FAtype)
#define EEpos_2FAtype7	(EEpos_2FAtype6 + EElen_2FAtype)
#define EEpos_2FAtype8	(EEpos_2FAtype7 + EElen_2FAtype)
#define EEpos_2FAtype9	(EEpos_2FAtype8 + EElen_2FAtype)
#define EEpos_2FAtype10	(EEpos_2FAtype9 + EElen_2FAtype)
#define EEpos_2FAtype11	(EEpos_2FAtype10 + EElen_2FAtype)
#define EEpos_2FAtype12	(EEpos_2FAtype11 + EElen_2FAtype)
#define EEpos_2FAtype13	(EEpos_2FAtype12 + EElen_2FAtype)
#define EEpos_2FAtype14	(EEpos_2FAtype13 + EElen_2FAtype)
#define EEpos_2FAtype15	(EEpos_2FAtype14 + EElen_2FAtype)
#define EEpos_2FAtype16	(EEpos_2FAtype15 + EElen_2FAtype)
#define EEpos_2FAtype17	(EEpos_2FAtype16 + EElen_2FAtype)
#define EEpos_2FAtype18	(EEpos_2FAtype17 + EElen_2FAtype)
#define EEpos_2FAtype19	(EEpos_2FAtype18 + EElen_2FAtype)
#define EEpos_2FAtype20	(EEpos_2FAtype19 + EElen_2FAtype)
#define EEpos_2FAtype21	(EEpos_2FAtype20 + EElen_2FAtype)
#define EEpos_2FAtype22	(EEpos_2FAtype21 + EElen_2FAtype)
#define EEpos_2FAtype23	(EEpos_2FAtype22 + EElen_2FAtype)
#define EEpos_2FAtype24	(EEpos_2FAtype23 + EElen_2FAtype)

#define EEpos_totpkey1len	(EEpos_2FAtype24 + EElen_2FAtype)
#define EEpos_totpkey2len	(EEpos_totpkey1len + EElen_totpkeylen)
#define EEpos_totpkey3len	(EEpos_totpkey2len + EElen_totpkeylen)
#define EEpos_totpkey4len	(EEpos_totpkey3len + EElen_totpkeylen)
#define EEpos_totpkey5len	(EEpos_totpkey4len + EElen_totpkeylen)
#define EEpos_totpkey6len	(EEpos_totpkey5len + EElen_totpkeylen)
#define EEpos_totpkey7len	(EEpos_totpkey6len + EElen_totpkeylen)
#define EEpos_totpkey8len	(EEpos_totpkey7len + EElen_totpkeylen)
#define EEpos_totpkey9len	(EEpos_totpkey8len + EElen_totpkeylen)
#define EEpos_totpkey10len	(EEpos_totpkey9len + EElen_totpkeylen)
#define EEpos_totpkey11len	(EEpos_totpkey10len + EElen_totpkeylen)
#define EEpos_totpkey12len	(EEpos_totpkey11len + EElen_totpkeylen)
#define EEpos_totpkey13len	(EEpos_totpkey12len + EElen_totpkeylen)
#define EEpos_totpkey14len	(EEpos_totpkey13len + EElen_totpkeylen)
#define EEpos_totpkey15len	(EEpos_totpkey14len + EElen_totpkeylen)
#define EEpos_totpkey16len	(EEpos_totpkey15len + EElen_totpkeylen)
#define EEpos_totpkey17len	(EEpos_totpkey16len + EElen_totpkeylen)
#define EEpos_totpkey18len	(EEpos_totpkey17len + EElen_totpkeylen)
#define EEpos_totpkey19len	(EEpos_totpkey18len + EElen_totpkeylen)
#define EEpos_totpkey20len	(EEpos_totpkey19len + EElen_totpkeylen)
#define EEpos_totpkey21len	(EEpos_totpkey20len + EElen_totpkeylen)
#define EEpos_totpkey22len	(EEpos_totpkey21len + EElen_totpkeylen)
#define EEpos_totpkey23len	(EEpos_totpkey22len + EElen_totpkeylen)
#define EEpos_totpkey24len	(EEpos_totpkey23len + EElen_totpkeylen)

#define EEpos_ecckey1	(EEpos_totpkey24len + EElen_totpkeylen)
#define EEpos_ecckey2	(EEpos_ecckey1 + EElen_ecckey)
#define EEpos_ecckey3	(EEpos_ecckey2 + EElen_ecckey)
#define EEpos_ecckey4	(EEpos_ecckey3 + EElen_ecckey)
#define EEpos_ecckey5	(EEpos_ecckey4 + EElen_ecckey)
#define EEpos_ecckey6	(EEpos_ecckey5 + EElen_ecckey)
#define EEpos_ecckey7	(EEpos_ecckey6 + EElen_ecckey)
#define EEpos_ecckey8	(EEpos_ecckey7 + EElen_ecckey)
#define EEpos_ecckey9	(EEpos_ecckey8 + EElen_ecckey)
#define EEpos_ecckey10	(EEpos_ecckey9 + EElen_ecckey)
#define EEpos_ecckey11	(EEpos_ecckey10 + EElen_ecckey)
#define EEpos_ecckey12	(EEpos_ecckey11 + EElen_ecckey)
#define EEpos_ecckey13	(EEpos_ecckey12 + EElen_ecckey)
#define EEpos_ecckey14	(EEpos_ecckey13 + EElen_ecckey)
#define EEpos_ecckey15	(EEpos_ecckey14 + EElen_ecckey)
#define EEpos_ecckey16	(EEpos_ecckey15 + EElen_ecckey)
#define EEpos_ecckey17	(EEpos_ecckey16 + EElen_ecckey)
#define EEpos_ecckey18	(EEpos_ecckey17 + EElen_ecckey)
#define EEpos_ecckey19	(EEpos_ecckey18 + EElen_ecckey)
#define EEpos_ecckey20	(EEpos_ecckey19 + EElen_ecckey)
#define EEpos_ecckey21	(EEpos_ecckey20 + EElen_ecckey)
#define EEpos_ecckey22	(EEpos_ecckey21 + EElen_ecckey)
#define EEpos_ecckey23	(EEpos_ecckey22 + EElen_ecckey)
#define EEpos_ecckey24	(EEpos_ecckey23 + EElen_ecckey)
#define EEpos_ecckey25	(EEpos_ecckey24 + EElen_ecckey)
#define EEpos_ecckey26	(EEpos_ecckey25 + EElen_ecckey)
#define EEpos_ecckey27	(EEpos_ecckey26 + EElen_ecckey)
#define EEpos_ecckey28	(EEpos_ecckey27 + EElen_ecckey)
#define EEpos_ecckey29	(EEpos_ecckey28 + EElen_ecckey)
#define EEpos_ecckey30	(EEpos_ecckey29 + EElen_ecckey)
#define EEpos_ecckey31	(EEpos_ecckey30 + EElen_ecckey)
#define EEpos_ecckey32	(EEpos_ecckey31 + EElen_ecckey)

#define EEpos_rsakey1	(EEpos_ecckey32 + EElen_ecckey)
#define EEpos_rsakey2	(EEpos_rsakey1 + EElen_rsakey)
#define EEpos_rsakey3	(EEpos_rsakey2 + EElen_rsakey)
#define EEpos_rsakey4	(EEpos_rsakey3 + EElen_rsakey)

#define EEpos_keylen	(EEpos_rsakey4 + EElen_rsakey)
#define EEpos_ctrlen	(EEpos_keylen + EElen_keylen)
#define EEpos_prvlen	(EEpos_ctrlen + EElen_ctrlen)
#define EEpos_publen	(EEpos_prvlen + EElen_prvlen)
#define EEpos_U2Fprivlen	(EEpos_publen + EElen_publen)
#define EEpos_U2Fcertlen	(EEpos_U2Fprivlen + EElen_U2Fprivlen)
#define EEpos_flashpos	(EEpos_U2Fcertlen + EElen_U2Fcertlen)
#define EEpos_backupkey	(EEpos_flashpos + EElen_flashpos)
#define EEpos_timeout	(EEpos_backupkey + EElen_backupkey)
#define EEpos_wipemode	(EEpos_timeout + EElen_timeout)
#define EEpos_backupkeymode	(EEpos_wipemode + EElen_wipemode)
#define EEpos_sshchallengemode	(EEpos_backupkeymode + EElen_backupkeymode)
#define EEpos_pgpchallengemode	(EEpos_sshchallengemode + EElen_sshchallengemode)
#define EEpos_2ndprofilemode	(EEpos_pgpchallengemode + EElen_pgpchallengemode)
#define EEpos_typespeed	(EEpos_2ndprofilemode + EElen_2ndprofilemode)
#define EEpos_keyboardlayout	(EEpos_typespeed + EElen_typespeed)
#define EEpos_sincelastregularlogin	(EEpos_keyboardlayout + EElen_keyboardlayout)
#define EEpos_failedlogins	(EEpos_sincelastregularlogin + EElen_sincelastregularlogin)

extern int  onlykey_eeget_backupkey (uint8_t *ptr);
extern void onlykey_eeset_backupkey(uint8_t *ptr);

extern int  onlykey_eeget_timeout (uint8_t *ptr);
extern void onlykey_eeset_timeout(uint8_t *ptr);

extern int  onlykey_eeget_wipemode (uint8_t *ptr);
extern void onlykey_eeset_wipemode(uint8_t *ptr);

extern int  onlykey_eeget_backupkeymode (uint8_t *ptr);
extern void onlykey_eeset_backupkeymode(uint8_t *ptr);

extern int  onlykey_eeget_sshchallengemode (uint8_t *ptr);
extern void onlykey_eeset_sshchallengemode(uint8_t *ptr);

extern int  onlykey_eeget_pgpchallengemode (uint8_t *ptr);
extern void onlykey_eeset_pgpchallengemode(uint8_t *ptr);

extern int  onlykey_eeget_2ndprofilemode (uint8_t *ptr);
extern void onlykey_eeset_2ndprofilemode(uint8_t *ptr);

extern int  onlykey_eeget_typespeed (uint8_t *ptr);
extern void onlykey_eeset_typespeed(uint8_t *ptr);

extern int  onlykey_eeget_keyboardlayout (uint8_t *ptr);
extern void onlykey_eeset_keyboardlayout(uint8_t *ptr);

extern int  onlykey_eeget_failedlogins (uint8_t *ptr);
extern void onlykey_eeset_failedlogins(uint8_t *ptr);

extern int  onlykey_eeget_sincelastregularlogin (uint8_t *ptr);
extern void onlykey_eeset_sincelastregularlogin(uint8_t *ptr);

extern int  onlykey_eeget_aeskey (uint8_t *ptr);
extern void onlykey_eeset_aeskey (uint8_t *ptr);

extern int  yubikey_eeget_counter (uint8_t *ptr);
extern void yubikey_eeset_counter (uint8_t *ptr);

extern int  onlykey_eeget_private (uint8_t *ptr);
extern void onlykey_eeset_private (uint8_t *ptr);

extern int  onlykey_eeget_public (uint8_t *ptr);
extern void onlykey_eeset_public (uint8_t *ptr);

extern int  onlykey_eeget_password (uint8_t *ptr, int slot);
extern void onlykey_eeset_password (uint8_t *ptr, int len, int slot);

extern int  onlykey_eeget_2FAtype (uint8_t *ptr, int slot);
extern void onlykey_eeset_2FAtype (uint8_t *ptr, int slot);

extern int  onlykey_eeget_addchar (uint8_t *ptr, int slot);
extern void onlykey_eeset_addchar (uint8_t *ptr, int slot);

extern int  onlykey_eeget_delay1 (uint8_t *ptr, int slot);
extern void onlykey_eeset_delay1 (uint8_t *ptr, int slot);

extern int  onlykey_eeget_delay2 (uint8_t *ptr, int slot);
extern void onlykey_eeset_delay2 (uint8_t *ptr, int slot);

extern int  onlykey_eeget_delay3 (uint8_t *ptr, int slot);
extern void onlykey_eeset_delay3 (uint8_t *ptr, int slot);

extern int  onlykey_eeget_ecckey (uint8_t *ptr, int slot);
extern void onlykey_eeset_ecckey (uint8_t *ptr, int slot);

extern int  onlykey_eeget_rsakey (uint8_t *ptr, int slot);
extern void onlykey_eeset_rsakey (uint8_t *ptr, int slot);

extern int  onlykey_eeget_U2Fprivlen (uint8_t *ptr);
extern void onlykey_eeset_U2Fprivlen (uint8_t *ptr);

extern int  onlykey_eeget_U2Fcertlen (uint8_t *ptr);
extern void onlykey_eeset_U2Fcertlen (uint8_t *ptr);

extern int  onlykey_eeget_flashpos (uint8_t *ptr);
extern void onlykey_eeset_flashpos (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen1 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen1 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen2 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen2 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen3 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen3 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen4 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen4 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen5 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen5 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen6 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen6 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen7 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen7 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen8 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen8 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen9 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen9 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen10 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen10 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen11 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen11 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen12 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen12 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen13 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen13 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen14 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen14 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen15 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen15 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen16 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen16 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen17 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen17 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen18 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen18 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen19 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen19 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen20 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen20 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen21 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen21 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen22 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen22 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen23 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen23 (uint8_t *ptr);

extern int  onlykey_eeget_passwordlen24 (uint8_t *ptr);
extern void onlykey_eeset_passwordlen24 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen1 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen1 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen2 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen2 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen3 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen3 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen4 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen4 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen5 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen5 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen6 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen6 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen7 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen7 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen8 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen8 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen9 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen9 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen10 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen10 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen11 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen11 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen12 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen12 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen13 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen13 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen14 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen14 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen15 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen15 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen16 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen16 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen17 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen17 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen18 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen18 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen19 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen19 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen20 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen20 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen21 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen21 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen22 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen22 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen23 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen23 (uint8_t *ptr);

extern int  onlykey_eeget_usernamelen24 (uint8_t *ptr);
extern void onlykey_eeset_usernamelen24 (uint8_t *ptr);

extern int  onlykey_eeget_urllen1 (uint8_t *ptr);
extern void onlykey_eeset_urllen1 (uint8_t *ptr);

extern int  onlykey_eeget_urllen2 (uint8_t *ptr);
extern void onlykey_eeset_urllen2 (uint8_t *ptr);

extern int  onlykey_eeget_urllen3 (uint8_t *ptr);
extern void onlykey_eeset_urllen3 (uint8_t *ptr);

extern int  onlykey_eeget_urllen4 (uint8_t *ptr);
extern void onlykey_eeset_urllen4 (uint8_t *ptr);

extern int  onlykey_eeget_urllen5 (uint8_t *ptr);
extern void onlykey_eeset_urllen5 (uint8_t *ptr);

extern int  onlykey_eeget_urllen6 (uint8_t *ptr);
extern void onlykey_eeset_urllen6 (uint8_t *ptr);

extern int  onlykey_eeget_urllen7 (uint8_t *ptr);
extern void onlykey_eeset_urllen7 (uint8_t *ptr);

extern int  onlykey_eeget_urllen8 (uint8_t *ptr);
extern void onlykey_eeset_urllen8 (uint8_t *ptr);

extern int  onlykey_eeget_urllen9 (uint8_t *ptr);
extern void onlykey_eeset_urllen9 (uint8_t *ptr);

extern int  onlykey_eeget_urllen10 (uint8_t *ptr);
extern void onlykey_eeset_urllen10 (uint8_t *ptr);

extern int  onlykey_eeget_urllen11 (uint8_t *ptr);
extern void onlykey_eeset_urllen11 (uint8_t *ptr);

extern int  onlykey_eeget_urllen12 (uint8_t *ptr);
extern void onlykey_eeset_urllen12 (uint8_t *ptr);

extern int  onlykey_eeget_urllen13 (uint8_t *ptr);
extern void onlykey_eeset_urllen13 (uint8_t *ptr);

extern int  onlykey_eeget_urllen14 (uint8_t *ptr);
extern void onlykey_eeset_urllen14 (uint8_t *ptr);

extern int  onlykey_eeget_urllen15 (uint8_t *ptr);
extern void onlykey_eeset_urllen15 (uint8_t *ptr);

extern int  onlykey_eeget_urllen16 (uint8_t *ptr);
extern void onlykey_eeset_urllen16 (uint8_t *ptr);

extern int  onlykey_eeget_urllen17 (uint8_t *ptr);
extern void onlykey_eeset_urllen17 (uint8_t *ptr);

extern int  onlykey_eeget_urllen18 (uint8_t *ptr);
extern void onlykey_eeset_urllen18 (uint8_t *ptr);

extern int  onlykey_eeget_urllen19 (uint8_t *ptr);
extern void onlykey_eeset_urllen19 (uint8_t *ptr);

extern int  onlykey_eeget_urllen20 (uint8_t *ptr);
extern void onlykey_eeset_urllen20 (uint8_t *ptr);

extern int  onlykey_eeget_urllen21 (uint8_t *ptr);
extern void onlykey_eeset_urllen21 (uint8_t *ptr);

extern int  onlykey_eeget_urllen22 (uint8_t *ptr);
extern void onlykey_eeset_urllen22 (uint8_t *ptr);

extern int  onlykey_eeget_urllen23 (uint8_t *ptr);
extern void onlykey_eeset_urllen23 (uint8_t *ptr);

extern int  onlykey_eeget_urllen24 (uint8_t *ptr);
extern void onlykey_eeset_urllen24 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen1 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen1 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen2 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen2 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen3 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen3 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen4 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen4 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen5 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen5 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen6 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen6 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen7 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen7 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen8 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen8 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen9 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen9 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen10 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen10 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen11 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen11 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen12 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen12 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen13 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen13 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen14 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen14 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen15 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen15 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen16 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen16 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen17 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen17 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen18 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen18 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen19 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen19 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen20 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen20 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen21 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen21 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen22 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen22 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen23 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen23 (uint8_t *ptr);

extern int  onlykey_eeget_totpkeylen24 (uint8_t *ptr);
extern void onlykey_eeset_totpkeylen24 (uint8_t *ptr);


#ifdef __cplusplus
}
#endif
#endif
