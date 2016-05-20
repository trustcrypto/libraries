/* okseeprom.h --- adaption of libonlykey for Teensy 3.X
**
**  msd, 25-sep-2012:	EEPROM functions
**  ts, 05-MAY-2016:	EEPROM functions added for OnlyKey
**  
*/

/*
 * Modifications by Tim Steiner
 * Copyright (c) 2016 , CryptoTrust LLC.
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
 * Original - YKSEEPROM.H
 * Written by Michael Doerr.
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

#ifndef OK_EEPROM_H
#define OK_EEPROM_H

#ifdef __cplusplus
extern "C"
{
#endif

#define EElen_noncehash	32
#define EElen_pinhash	32
#define EElen_selfdestructhash	32
#define EElen_plausdenyhash	32
#define EElen_aeskey	16
#define EElen_public	6
#define EElen_private	6
#define EElen_counter	2
#define EElen_label	10
#define EElen_username	32
#define EElen_addchar	1
#define EElen_delay	1
#define EElen_password	32
#define EElen_2FAtype	1
#define EElen_totpkey	20
#define EElen_keylen	1
#define EElen_ctrlen	1
#define EElen_prvlen	1
#define EElen_publen	1
#define EElen_passwordlen	1
#define EElen_labellen	1
#define EElen_usernamelen	1
#define EElen_totpkeylen	1
#define EElen_U2Fprivlen	1
#define EElen_U2Fcertlen	2
#define EElen_U2Fprivpos	2
#define EElen_U2Fcertpos	2
#define EElen_hashpos		2
#define EElen_failedlogins	1
#define EElen_U2Fcounter	2
#define EElen_timeout	1

#define EEpos_U2Fcounter	0
#define EEpos_aeskey	(EEpos_U2Fcounter + EElen_U2Fcounter)
#define EEpos_public	(EEpos_aeskey + EElen_aeskey)
#define EEpos_private	(EEpos_public + EElen_public)
#define EEpos_counter	(EEpos_private + EElen_private)

#define EEpos_label1	(EEpos_counter + EElen_counter)
#define EEpos_label2	(EEpos_label1 + EElen_label)
#define EEpos_label3	(EEpos_label2 + EElen_label)
#define EEpos_label4	(EEpos_label3 + EElen_label)
#define EEpos_label5	(EEpos_label4 + EElen_label)
#define EEpos_label6	(EEpos_label5 + EElen_label)
#define EEpos_label7	(EEpos_label6 + EElen_label)
#define EEpos_label8	(EEpos_label7 + EElen_label)
#define EEpos_label9	(EEpos_label8 + EElen_label)
#define EEpos_label10	(EEpos_label9 + EElen_label)
#define EEpos_label11	(EEpos_label10 + EElen_label)
#define EEpos_label12	(EEpos_label11 + EElen_label)
#define EEpos_label13	(EEpos_label12 + EElen_label)
#define EEpos_label14	(EEpos_label13 + EElen_label)
#define EEpos_label15	(EEpos_label14 + EElen_label)
#define EEpos_label16	(EEpos_label15 + EElen_label)
#define EEpos_label17	(EEpos_label16 + EElen_label)
#define EEpos_label18	(EEpos_label17 + EElen_label)
#define EEpos_label19	(EEpos_label18 + EElen_label)
#define EEpos_label20	(EEpos_label19 + EElen_label)
#define EEpos_label21	(EEpos_label20 + EElen_label)
#define EEpos_label22	(EEpos_label21 + EElen_label)
#define EEpos_label23	(EEpos_label22 + EElen_label)
#define EEpos_label24	(EEpos_label23 + EElen_label)

#define EEpos_username1	(EEpos_label24 + EElen_label)
#define EEpos_username2	(EEpos_username1 + EElen_username)
#define EEpos_username3	(EEpos_username2 + EElen_username)
#define EEpos_username4	(EEpos_username3 + EElen_username)
#define EEpos_username5	(EEpos_username4 + EElen_username)
#define EEpos_username6	(EEpos_username5 + EElen_username)
#define EEpos_username7	(EEpos_username6 + EElen_username)
#define EEpos_username8	(EEpos_username7 + EElen_username)
#define EEpos_username9	(EEpos_username8 + EElen_username)
#define EEpos_username10	(EEpos_username9 + EElen_username)
#define EEpos_username11	(EEpos_username10 + EElen_username)
#define EEpos_username12	(EEpos_username11 + EElen_username)
#define EEpos_username13	(EEpos_username12 + EElen_username)
#define EEpos_username14	(EEpos_username13 + EElen_username)
#define EEpos_username15	(EEpos_username14 + EElen_username)
#define EEpos_username16	(EEpos_username15 + EElen_username)
#define EEpos_username17	(EEpos_username16 + EElen_username)
#define EEpos_username18	(EEpos_username17 + EElen_username)
#define EEpos_username19	(EEpos_username18 + EElen_username)
#define EEpos_username20	(EEpos_username19 + EElen_username)
#define EEpos_username21	(EEpos_username20 + EElen_username)
#define EEpos_username22	(EEpos_username21 + EElen_username)
#define EEpos_username23	(EEpos_username22 + EElen_username)
#define EEpos_username24	(EEpos_username23 + EElen_username)

#define EEpos_username1len	(EEpos_username24 + EElen_username)
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

#define EEpos_addchar1_1	(EEpos_username24len + EElen_usernamelen)
#define EEpos_addchar1_2	(EEpos_addchar1_1 + EElen_addchar)
#define EEpos_addchar1_3	(EEpos_addchar1_2 + EElen_addchar)
#define EEpos_addchar1_4	(EEpos_addchar1_3 + EElen_addchar)
#define EEpos_addchar1_5	(EEpos_addchar1_4 + EElen_addchar)
#define EEpos_addchar1_6	(EEpos_addchar1_5 + EElen_addchar)
#define EEpos_addchar1_7	(EEpos_addchar1_6 + EElen_addchar)
#define EEpos_addchar1_8	(EEpos_addchar1_7 + EElen_addchar)
#define EEpos_addchar1_9	(EEpos_addchar1_8 + EElen_addchar)
#define EEpos_addchar1_10	(EEpos_addchar1_9 + EElen_addchar)
#define EEpos_addchar1_11	(EEpos_addchar1_10 + EElen_addchar)
#define EEpos_addchar1_12	(EEpos_addchar1_11 + EElen_addchar)
#define EEpos_addchar1_13	(EEpos_addchar1_12 + EElen_addchar)
#define EEpos_addchar1_14	(EEpos_addchar1_13 + EElen_addchar)
#define EEpos_addchar1_15	(EEpos_addchar1_14 + EElen_addchar)
#define EEpos_addchar1_16	(EEpos_addchar1_15 + EElen_addchar)
#define EEpos_addchar1_17	(EEpos_addchar1_16 + EElen_addchar)
#define EEpos_addchar1_18	(EEpos_addchar1_17 + EElen_addchar)
#define EEpos_addchar1_19	(EEpos_addchar1_18 + EElen_addchar)
#define EEpos_addchar1_20	(EEpos_addchar1_19 + EElen_addchar)
#define EEpos_addchar1_21	(EEpos_addchar1_20 + EElen_addchar)
#define EEpos_addchar1_22	(EEpos_addchar1_21 + EElen_addchar)
#define EEpos_addchar1_23	(EEpos_addchar1_22 + EElen_addchar)
#define EEpos_addchar1_24	(EEpos_addchar1_23 + EElen_addchar)

#define EEpos_delay1_1	(EEpos_addchar1_24 + EElen_addchar)
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

#define EEpos_password1	(EEpos_delay1_24 + EElen_delay)
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

#define EEpos_addchar2_1	(EEpos_password24len + EElen_passwordlen)
#define EEpos_addchar2_2	(EEpos_addchar2_1 + EElen_addchar)
#define EEpos_addchar2_3	(EEpos_addchar2_2 + EElen_addchar)
#define EEpos_addchar2_4	(EEpos_addchar2_3 + EElen_addchar)
#define EEpos_addchar2_5	(EEpos_addchar2_4 + EElen_addchar)
#define EEpos_addchar2_6	(EEpos_addchar2_5 + EElen_addchar)
#define EEpos_addchar2_7	(EEpos_addchar2_6 + EElen_addchar)
#define EEpos_addchar2_8	(EEpos_addchar2_7 + EElen_addchar)
#define EEpos_addchar2_9	(EEpos_addchar2_8 + EElen_addchar)
#define EEpos_addchar2_10	(EEpos_addchar2_9 + EElen_addchar)
#define EEpos_addchar2_11	(EEpos_addchar2_10 + EElen_addchar)
#define EEpos_addchar2_12	(EEpos_addchar2_11 + EElen_addchar)
#define EEpos_addchar2_13	(EEpos_addchar2_12 + EElen_addchar)
#define EEpos_addchar2_14	(EEpos_addchar2_13 + EElen_addchar)
#define EEpos_addchar2_15	(EEpos_addchar2_14 + EElen_addchar)
#define EEpos_addchar2_16	(EEpos_addchar2_15 + EElen_addchar)
#define EEpos_addchar2_17	(EEpos_addchar2_16 + EElen_addchar)
#define EEpos_addchar2_18	(EEpos_addchar2_17 + EElen_addchar)
#define EEpos_addchar2_19	(EEpos_addchar2_18 + EElen_addchar)
#define EEpos_addchar2_20	(EEpos_addchar2_19 + EElen_addchar)
#define EEpos_addchar2_21	(EEpos_addchar2_20 + EElen_addchar)
#define EEpos_addchar2_22	(EEpos_addchar2_21 + EElen_addchar)
#define EEpos_addchar2_23	(EEpos_addchar2_22 + EElen_addchar)
#define EEpos_addchar2_24	(EEpos_addchar2_23 + EElen_addchar)

#define EEpos_delay2_1	(EEpos_addchar2_24 + EElen_addchar)
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

#define EEpos_2FAtype1	(EEpos_delay2_12 + EElen_delay)
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

#define EEpos_totpkey1len	(EEpos_2FAtype12 + EElen_2FAtype)
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

#define EEpos_keylen	(EEpos_totpkey12len + EElen_totpkeylen)
#define EEpos_ctrlen	(EEpos_keylen + EElen_keylen)
#define EEpos_prvlen	(EEpos_ctrlen + EElen_ctrlen)
#define EEpos_publen	(EEpos_prvlen + EElen_prvlen)
#define EEpos_U2Fprivlen	(EEpos_publen + EElen_publen)
#define EEpos_U2Fcertlen	(EEpos_U2Fprivlen + EElen_U2Fprivlen)
#define EEpos_U2Fprivpos	(EEpos_U2Fcertlen + EElen_U2Fcertlen)
#define EEpos_U2Fcertpos	(EEpos_U2Fprivpos + EElen_U2Fprivpos)
#define EEpos_hashpos	(EEpos_U2Fcertpos + EElen_U2Fcertpos)
#define EEpos_timeout	(EEpos_hashpos + EElen_hashpos)
#define EEpos_failedlogins	(EEpos_hashpos + EElen_hashpos)

extern int  onlykey_eeget_timeout (uint8_t *ptr);
extern void onlykey_eeset_timeout(uint8_t *ptr);

extern int  onlykey_eeget_failedlogins (uint8_t *ptr);
extern void onlykey_eeset_failedlogins(uint8_t *ptr);

extern int  onlykey_eeget_aeskey (uint8_t *ptr);
extern void onlykey_eeset_aeskey (uint8_t *ptr, int len);

extern int  yubikey_eeget_counter (uint8_t *ptr);
extern void yubikey_eeset_counter (uint8_t *ptr);

extern int  onlykey_eeget_private (uint8_t *ptr);
extern void onlykey_eeset_private (uint8_t *ptr);

extern int  onlykey_eeget_public (uint8_t *ptr);
extern void onlykey_eeset_public (uint8_t *ptr, int len);

extern int  onlykey_eeget_password (uint8_t *ptr, int slot);
extern void onlykey_eeset_password (uint8_t *ptr, int len, int slot);

extern int  onlykey_eeget_username (uint8_t *ptr, int slot);
extern void onlykey_eeset_username (uint8_t *ptr, int len, int slot);

extern int  onlykey_eeget_label (uint8_t *ptr, int slot);
extern void onlykey_eeset_label (uint8_t *ptr, int len, int slot);

extern int  onlykey_eeget_2FAtype (uint8_t *ptr, int slot);
extern void onlykey_eeset_2FAtype (uint8_t *ptr, int slot);

extern int  onlykey_eeget_addchar1 (uint8_t *ptr, int slot);
extern void onlykey_eeset_addchar1 (uint8_t *ptr, int slot);

extern int  onlykey_eeget_addchar2 (uint8_t *ptr, int slot);
extern void onlykey_eeset_addchar2 (uint8_t *ptr, int slot);

extern int  onlykey_eeget_delay1 (uint8_t *ptr, int slot);
extern void onlykey_eeset_delay1 (uint8_t *ptr, int slot);

extern int  onlykey_eeget_delay2 (uint8_t *ptr, int slot);
extern void onlykey_eeset_delay2 (uint8_t *ptr, int slot);

extern int  onlykey_eeget_U2Fprivlen (uint8_t *ptr);
extern void onlykey_eeset_U2Fprivlen (uint8_t *ptr);

extern int  onlykey_eeget_U2Fcertlen (uint8_t *ptr);
extern void onlykey_eeset_U2Fcertlen (uint8_t *ptr);

extern int  onlykey_eeget_U2Fprivpos (uint8_t *ptr);
extern void onlykey_eeset_U2Fprivpos (uint8_t *ptr);

extern int  onlykey_eeget_U2Fcertpos (uint8_t *ptr);
extern void onlykey_eeset_U2Fcertpos (uint8_t *ptr);

extern int  onlykey_eeget_hashpos (uint8_t *ptr);
extern void onlykey_eeset_hashpos (uint8_t *ptr);

extern int  yubikey_eeget_keylen (uint8_t *ptr);
extern void yubikey_eeset_keylen (uint8_t *ptr);

extern int  yubikey_eeget_ctrlen (uint8_t *ptr);
extern void yubikey_eeset_ctrlen (uint8_t *ptr);

extern int  yubikey_eeget_prvlen (uint8_t *ptr);
extern void yubikey_eeset_prvlen (uint8_t *ptr);

extern int  yubikey_eeget_publen (uint8_t *ptr);
extern void yubikey_eeset_publen (uint8_t *ptr);

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


#ifdef __cplusplus
}
#endif
#endif
