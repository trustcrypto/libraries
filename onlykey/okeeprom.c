/* ykseeprom.c --- adaption of libonlykey for Teensy 3.X
**
**  msd, 25-sep-2012:	read/write persistent values from/to EEPROM
**  ts, 05-MAY-2016:	read/write persistent values from/to EEPROM for OnlyKey
**  
*/

#include <Arduino.h>
#include <avr/eeprom.h>
#include "okeeprom.h"


/*********************************/
/*********************************/
void onlykey_eeget_common(
	uint8_t	*ptr,
	int	addr,
	int	len)
{
    while (len--) {
	*ptr++ = eeprom_read_byte(addr++);
    }
}

void onlykey_eeset_common(
	uint8_t	*ptr,
	int	addr,
	int	len)
{
    while (len--) {
	eeprom_write_byte(addr++, *ptr++);
    }
}
/*********************************/
/*********************************/
int onlykey_eeget_timeout (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_timeout, EElen_timeout);
    return EElen_timeout;
}
void onlykey_eeset_timeout (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_timeout, EElen_timeout);
}
/*********************************/
/*********************************/
int onlykey_eeget_wipemode (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_wipemode, EElen_wipemode);
    return EElen_wipemode;
}
void onlykey_eeset_wipemode (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_wipemode, EElen_wipemode);
}
/*********************************/
/*********************************/
int onlykey_eeget_failedlogins (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_failedlogins, EElen_failedlogins);
    return EElen_failedlogins;
}
void onlykey_eeset_failedlogins (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_failedlogins, EElen_failedlogins);
}

/*********************************/
/*********************************/

int onlykey_eeget_U2Fprivlen (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_U2Fprivlen, EElen_U2Fprivlen);
    return EElen_U2Fprivlen;
}
void onlykey_eeset_U2Fprivlen (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_U2Fprivlen, EElen_U2Fprivlen);
}

/*********************************/
/*********************************/

int onlykey_eeget_U2Fcertlen (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_U2Fcertlen, EElen_U2Fcertlen);
    return EElen_U2Fcertlen;
}
void onlykey_eeset_U2Fcertlen (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_U2Fcertlen, EElen_U2Fcertlen);
}

/*********************************/
/*********************************/

int onlykey_eeget_hashpos (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_hashpos, EElen_hashpos);
    return EElen_hashpos;
}
void onlykey_eeset_hashpos (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_hashpos, EElen_hashpos);
}

/*********************************/
/*********************************/

int yubikey_eeget_keylen (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_keylen, EElen_keylen);
    return EElen_keylen;
}
void yubikey_eeset_keylen (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_keylen, EElen_keylen);
}
/*********************************/
/*********************************/
int yubikey_eeget_ctrlen (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_ctrlen, EElen_ctrlen);
    return EElen_ctrlen;
}
void yubikey_eeset_ctrlen (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_ctrlen, EElen_ctrlen);
}
/*********************************/
/*********************************/
int yubikey_eeget_prvlen (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_prvlen, EElen_prvlen);
    return EElen_prvlen;
}
void yubikey_eeset_prvlen (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_prvlen, EElen_prvlen);
}
/*********************************/
/*********************************/
int yubikey_eeget_publen (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_publen, EElen_publen);
    return EElen_publen;
}
void yubikey_eeset_publen (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_publen, EElen_publen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen1 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password1len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen1 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password1len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen2 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password2len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen2 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password2len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen3 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password3len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen3 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password3len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen4 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password4len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen4 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password4len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen5 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password5len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen5 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password5len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen6 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password6len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen6 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password6len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen7 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password7len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen7 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password7len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen8 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password8len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen8 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password8len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen9 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password9len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen9 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password9len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen10 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password10len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen10 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password10len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen11 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password11len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen11 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password11len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen12 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password12len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen12 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password12len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen13 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password13len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen13 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password13len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen14 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password14len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen14 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password14len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen15 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password15len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen15 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password15len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen16 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password16len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen16 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password16len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen17 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password17len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen17 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password17len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen18 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password18len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen18 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password18len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen19 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password19len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen19 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password19len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen20 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password20len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen20 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password20len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen21 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password21len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen21 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password21len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen22 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password22len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen22 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password22len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen23 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password23len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen23 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password23len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_passwordlen24 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_password24len, EElen_passwordlen);
    return EElen_passwordlen;
}
void onlykey_eeset_passwordlen24 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_password24len, EElen_passwordlen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen1 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username1len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen1 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username1len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen2 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username2len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen2 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username2len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen3 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username3len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen3 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username3len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen4 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username4len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen4 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username4len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen5 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username5len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen5 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username5len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen6 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username6len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen6 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username6len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen7 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username7len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen7 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username7len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen8 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username8len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen8 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username8len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen9 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username9len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen9 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username9len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen10 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username10len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen10 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username10len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen11 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username11len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen11 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username11len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen12 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username12len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen12 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username12len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen13 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username13len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen13 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username13len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen14 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username14len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen14 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username14len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen15 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username15len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen15 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username15len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen16 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username16len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen16 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username16len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen17 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username17len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen17 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username17len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen18 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username18len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen18 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username18len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen19 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username19len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen19 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username19len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen20 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username20len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen20 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username20len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen21 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username21len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen21 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username21len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen22 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username22len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen22 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username22len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen23 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username23len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen23 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username23len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_usernamelen24 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_username24len, EElen_usernamelen);
    return EElen_usernamelen;
}
void onlykey_eeset_usernamelen24 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_username24len, EElen_usernamelen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen1 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey1len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen1 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey1len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen2 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey2len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen2 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey2len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen3 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey3len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen3 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey3len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen4 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey4len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen4 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey4len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen5 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey5len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen5 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey5len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen6 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey6len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen6 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey6len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen7 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey7len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen7 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey7len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen8 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey8len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen8 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey8len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen9 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey9len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen9 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey9len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen10 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey10len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen10 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey10len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen11 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey11len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen11 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey11len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen12 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey12len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen12 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey12len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen13 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey13len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen13 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey13len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen14 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey14len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen14 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey14len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen15 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey15len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen15 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey15len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen16 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey16len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen16 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey16len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen17 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey17len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen17 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey17len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen18 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey18len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen18 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey18len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen19 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey19len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen19 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey19len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen20 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey20len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen20 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey20len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen21 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey21len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen21 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey21len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen22 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey22len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen22 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey22len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen23 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey23len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen23 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey23len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_totpkeylen24 (uint8_t *ptr) {
    onlykey_eeget_common(ptr, EEpos_totpkey24len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void onlykey_eeset_totpkeylen24 (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_totpkey24len, EElen_totpkeylen);
}
/*********************************/
/*********************************/
int onlykey_eeget_aeskey (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_keylen(&length);
    int size = (int) length;
    if (length != EElen_aeskey) return 0;
    onlykey_eeget_common(ptr, EEpos_aeskey, EElen_aeskey);
    return size;
}
void onlykey_eeset_aeskey (uint8_t *ptr, int size) {
    if (size > EElen_aeskey) size = EElen_aeskey;
    onlykey_eeset_common(ptr, EEpos_aeskey, EElen_aeskey);
    uint8_t length = (uint8_t) size;
    yubikey_eeset_keylen(&length);
}
/*********************************/
/*********************************/
int yubikey_eeget_counter (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_ctrlen(&length);
    if (length != EElen_counter) return 0;
    onlykey_eeget_common(ptr, EEpos_counter, EElen_counter);
    return EElen_counter;
}
void yubikey_eeset_counter (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_counter, EElen_counter);
    uint8_t length = EElen_counter;
    yubikey_eeset_ctrlen(&length);
}
/*********************************/
/*********************************/
int onlykey_eeget_private (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_prvlen(&length);
    if (length != EElen_private) return 0;
    onlykey_eeget_common(ptr, EEpos_private, EElen_private);
    return EElen_private;
}
void onlykey_eeset_private (uint8_t *ptr) {
    onlykey_eeset_common(ptr, EEpos_private, EElen_private);
    uint8_t length = EElen_private;
    yubikey_eeset_prvlen(&length);
}
/*********************************/
/*********************************/
int onlykey_eeget_public (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_publen(&length);
    int size = (int) length;
    if (size > EElen_public) size = EElen_public;
    onlykey_eeget_common(ptr, EEpos_public, EElen_public);
    return size;
}
void onlykey_eeset_public (uint8_t *ptr, int size) {
    if (size > EElen_public) size = EElen_public;
    onlykey_eeset_common(ptr, EEpos_public, EElen_public);
    uint8_t length = (uint8_t) size;
    yubikey_eeset_publen(&length);
}
/*********************************/
/*********************************/
int onlykey_eeget_password (uint8_t *ptr, int slot) {
    
	switch (slot) {
		uint8_t length;
		int size;
        	case 1:
			onlykey_eeget_passwordlen1(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password1, EElen_password);
			return size;
            break;
		case 2:
			onlykey_eeget_passwordlen2(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password2, EElen_password);
			return size;
            break;
		case 3:
			onlykey_eeget_passwordlen3(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password3, EElen_password);
			return size;
            break;
		case 4:
			onlykey_eeget_passwordlen4(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password4, EElen_password);
			return size;
            break;
		case 5:
			onlykey_eeget_passwordlen5(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password5, EElen_password);
			return size;
            break;
		case 6:
			onlykey_eeget_passwordlen6(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password6, EElen_password);
			return size;
            break;
		case 7:
			onlykey_eeget_passwordlen7(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password7, EElen_password);
			return size;
            break;
		case 8:
			onlykey_eeget_passwordlen8(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password8, EElen_password);
			return size;
            break;
		case 9:
			onlykey_eeget_passwordlen9(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password9, EElen_password);
			return size;
            break;
		case 10:
			onlykey_eeget_passwordlen10(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password10, EElen_password);
			return size;
            break;
		case 11:
			onlykey_eeget_passwordlen11(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password11, EElen_password);
			return size;
            break;
		case 12:
			onlykey_eeget_passwordlen12(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password12, EElen_password);
			return size;
            break;
		case 13:
			onlykey_eeget_passwordlen13(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password13, EElen_password);
			return size;
            break;
		case 14:
			onlykey_eeget_passwordlen14(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password14, EElen_password);
			return size;
            break;
		case 15:
			onlykey_eeget_passwordlen15(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password15, EElen_password);
			return size;
            break;
		case 16:
			onlykey_eeget_passwordlen16(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password16, EElen_password);
			return size;
            break;
		case 17:
			onlykey_eeget_passwordlen17(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password17, EElen_password);
			return size;
            break;
		case 18:
			onlykey_eeget_passwordlen18(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password18, EElen_password);
			return size;
            break;
		case 19:
			onlykey_eeget_passwordlen19(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password19, EElen_password);
			return size;
            break;
		case 20:
			onlykey_eeget_passwordlen20(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password20, EElen_password);
			return size;
            break;
		case 21:
			onlykey_eeget_passwordlen21(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password21, EElen_password);
			return size;
            break;
		case 22:
			onlykey_eeget_passwordlen22(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password22, EElen_password);
			return size;
            break;
		case 23:
			onlykey_eeget_passwordlen23(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password23, EElen_password);
			return size;
            break;
		case 24:
			onlykey_eeget_passwordlen24(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			onlykey_eeget_common(ptr, EEpos_password24, EElen_password);
			return size;
            break;	
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_password (uint8_t *ptr, int size, int slot) {
    
		switch (slot) {
			uint8_t length;
        	case 1:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password1, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen1(&length);
            break;
		case 2:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password2, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen2(&length);
            break;
		case 3:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password3, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen3(&length);
            break;
		case 4:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password4, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen4(&length);
            break;
		case 5:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password5, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen5(&length);
            break;
		case 6:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password6, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen6(&length);
            break;
		case 7:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password7, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen7(&length);
            break;
		case 8:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password8, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen8(&length);
            break;
		case 9:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password9, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen9(&length);
            break;
		case 10:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password10, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen10(&length);
            break;
		case 11:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password11, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen11(&length);
            break;
		case 12:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password12, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen11(&length);
            break;
            case 13:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password13, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen13(&length);
            break;
		case 14:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password14, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen14(&length);
            break;
		case 15:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password15, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen15(&length);
            break;
		case 16:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password16, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen16(&length);
            break;
		case 17:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password17, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen17(&length);
            break;
		case 18:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password18, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen18(&length);
            break;
		case 19:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password19, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen19(&length);
            break;
		case 20:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password20, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen20(&length);
            break;
		case 21:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password21, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen21(&length);
            break;
		case 22:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password22, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen22(&length);
            break;
		case 23:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password23, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen23(&length);
            break;
		case 24:
		
			if (size > EElen_password) size = EElen_password;
			onlykey_eeset_common(ptr, EEpos_password24, EElen_password);
			length = (uint8_t) size;
			onlykey_eeset_passwordlen24(&length);
            break;
	}

}
/*********************************/
/*********************************/
int onlykey_eeget_label (uint8_t *ptr, int slot) {
    
	switch (slot) {
		int size;
        	case 1:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label1, size);
			return size;
            break;
		case 2:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label2, size);
			return size;
            break;
		case 3:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label3, size);
			return size;
            break;
		case 4:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label4, size);
			return size;
            break;
		case 5:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label5, size);
			return size;
            break;
		case 6:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label6, size);
			return size;
            break;
		case 7:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label7, size);
			return size;
            break;
		case 8:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label8, size);
			return size;
            break;
		case 9:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label9, size);
			return size;
            break;
		case 10:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label10, size);
			return size;
            break;
		case 11:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label11, size);
			return size;
            break;
		case 12:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label12, size);
			return size;
            break;
            	case 13:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label13, size);
			return size;
            break;
		case 14:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label14, size);
			return size;
            break;
		case 15:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label15, size);
			return size;
            break;
		case 16:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label16, size);
			return size;
            break;
		case 17:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label17, size);
			return size;
            break;
		case 18:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label18, size);
			return size;
            break;
		case 19:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label19, size);
			return size;
            break;
		case 20:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label20, size);
			return size;
            break;
		case 21:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label21, size);
			return size;
            break;
		case 22:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label22, size);
			return size;
            break;
		case 23:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label23, size);
			return size;
            break;
		case 24:
			size = EElen_label;
			onlykey_eeget_common(ptr, EEpos_label24, size);
			return size;
            break;
			
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_label (uint8_t *ptr, int size, int slot) {
    
		switch (slot) {
        	case 1:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label1, size);
            break;
		case 2:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label2, size);
            break;
		case 3:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label3, size);
            break;
		case 4:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label4, size);
            break;
		case 5:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label5, size);
            break;
		case 6:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label6, size);
            break;
		case 7:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label7, size);
            break;
		case 8:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label8, size);
            break;
		case 9:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label9, size);
            break;
		case 10:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label10, size);
            break;
		case 11:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label11, size);
            break;
		case 12:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label12, size);
            break;
            	case 13:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label13, size);
            break;
		case 14:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label14, size);
            break;
		case 15:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label15, size);
            break;
		case 16:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label16, size);
            break;
		case 17:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label17, size);
            break;
		case 18:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label18, size);
            break;
		case 19:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label19, size);
            break;
		case 20:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label20, size);
            break;
		case 21:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label21, size);
            break;
		case 22:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label22, size);
            break;
		case 23:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label23, size);
            break;
		case 24:
			size = EElen_label;
			onlykey_eeset_common(ptr, EEpos_label24, size);
            break;
	}

}
/*********************************/
/*********************************/
int onlykey_eeget_addchar1 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        	case 1:
			onlykey_eeget_common(ptr, EEpos_addchar1_1, EElen_addchar);
			return EElen_addchar;
            break;
		case 2:
			onlykey_eeget_common(ptr, EEpos_addchar1_2, EElen_addchar);
			return EElen_addchar;
            break;
		case 3:
			onlykey_eeget_common(ptr, EEpos_addchar1_3, EElen_addchar);
			return EElen_addchar;
            break;
		case 4:
			onlykey_eeget_common(ptr, EEpos_addchar1_4, EElen_addchar);
			return EElen_addchar;
            break;
		case 5:
			onlykey_eeget_common(ptr, EEpos_addchar1_5, EElen_addchar);
			return EElen_addchar;
            break;
		case 6:
			onlykey_eeget_common(ptr, EEpos_addchar1_6, EElen_addchar);
			return EElen_addchar;
            break;
		case 7:
			onlykey_eeget_common(ptr, EEpos_addchar1_7, EElen_addchar);
			return EElen_addchar;
            break;
		case 8:
			onlykey_eeget_common(ptr, EEpos_addchar1_8, EElen_addchar);
			return EElen_addchar;
            break;
		case 9:
			onlykey_eeget_common(ptr, EEpos_addchar1_9, EElen_addchar);
			return EElen_addchar;
            break;
		case 10:
			onlykey_eeget_common(ptr, EEpos_addchar1_10, EElen_addchar);
			return EElen_addchar;
            break;
		case 11:
			onlykey_eeget_common(ptr, EEpos_addchar1_11, EElen_addchar);
			return EElen_addchar;
            break;
		case 12:
			onlykey_eeget_common(ptr, EEpos_addchar1_12, EElen_addchar);
			return EElen_addchar;
            break;
		case 13:
			onlykey_eeget_common(ptr, EEpos_addchar1_13, EElen_addchar);
			return EElen_addchar;
            break;
		case 14:
			onlykey_eeget_common(ptr, EEpos_addchar1_14, EElen_addchar);
			return EElen_addchar;
            break;
		case 15:
			onlykey_eeget_common(ptr, EEpos_addchar1_15, EElen_addchar);
			return EElen_addchar;
            break;
		case 16:
			onlykey_eeget_common(ptr, EEpos_addchar1_16, EElen_addchar);
			return EElen_addchar;
            break;
		case 17:
			onlykey_eeget_common(ptr, EEpos_addchar1_17, EElen_addchar);
			return EElen_addchar;
            break;
		case 18:
			onlykey_eeget_common(ptr, EEpos_addchar1_18, EElen_addchar);
			return EElen_addchar;
            break;
		case 19:
			onlykey_eeget_common(ptr, EEpos_addchar1_19, EElen_addchar);
			return EElen_addchar;
            break;
		case 20:
			onlykey_eeget_common(ptr, EEpos_addchar1_20, EElen_addchar);
			return EElen_addchar;
            break;
		case 21:
			onlykey_eeget_common(ptr, EEpos_addchar1_21, EElen_addchar);
			return EElen_addchar;
            break;
		case 22:
			onlykey_eeget_common(ptr, EEpos_addchar1_22, EElen_addchar);
			return EElen_addchar;
            break;
		case 23:
			onlykey_eeget_common(ptr, EEpos_addchar1_23, EElen_addchar);
			return EElen_addchar;
            break;
		case 24:
			onlykey_eeget_common(ptr, EEpos_addchar1_24, EElen_addchar);
			return EElen_addchar;
            break;	
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_addchar1 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        	case 1:
		onlykey_eeset_common(ptr, EEpos_addchar1_1, EElen_addchar);
            break;
		case 2:
		onlykey_eeset_common(ptr, EEpos_addchar1_2, EElen_addchar);
            break;
		case 3:
		onlykey_eeset_common(ptr, EEpos_addchar1_3, EElen_addchar);
            break;
		case 4:
		onlykey_eeset_common(ptr, EEpos_addchar1_4, EElen_addchar);
            break;
		case 5:
		onlykey_eeset_common(ptr, EEpos_addchar1_5, EElen_addchar);
            break;
		case 6:
		onlykey_eeset_common(ptr, EEpos_addchar1_6, EElen_addchar);
            break;
		case 7:
		onlykey_eeset_common(ptr, EEpos_addchar1_7, EElen_addchar);
            break;
		case 8:
		onlykey_eeset_common(ptr, EEpos_addchar1_8, EElen_addchar);
            break;
		case 9:
		onlykey_eeset_common(ptr, EEpos_addchar1_9, EElen_addchar);
            break;
		case 10:
		onlykey_eeset_common(ptr, EEpos_addchar1_10, EElen_addchar);
            break;
		case 11:
		onlykey_eeset_common(ptr, EEpos_addchar1_11, EElen_addchar);
            break;
		case 12:
		onlykey_eeset_common(ptr, EEpos_addchar1_12, EElen_addchar);
            break;
            	case 13:
		onlykey_eeset_common(ptr, EEpos_addchar1_13, EElen_addchar);
            break;
		case 14:
		onlykey_eeset_common(ptr, EEpos_addchar1_14, EElen_addchar);
            break;
		case 15:
		onlykey_eeset_common(ptr, EEpos_addchar1_15, EElen_addchar);
            break;
		case 16:
		onlykey_eeset_common(ptr, EEpos_addchar1_16, EElen_addchar);
            break;
		case 17:
		onlykey_eeset_common(ptr, EEpos_addchar1_17, EElen_addchar);
            break;
		case 18:
		onlykey_eeset_common(ptr, EEpos_addchar1_18, EElen_addchar);
            break;
		case 19:
		onlykey_eeset_common(ptr, EEpos_addchar1_19, EElen_addchar);
            break;
		case 20:
		onlykey_eeset_common(ptr, EEpos_addchar1_20, EElen_addchar);
            break;
		case 21:
		onlykey_eeset_common(ptr, EEpos_addchar1_21, EElen_addchar);
            break;
		case 22:
		onlykey_eeset_common(ptr, EEpos_addchar1_22, EElen_addchar);
            break;
		case 23:
		onlykey_eeset_common(ptr, EEpos_addchar1_23, EElen_addchar);
            break;
		case 24:
		onlykey_eeset_common(ptr, EEpos_addchar1_24, EElen_addchar);
            break;
	}

}
/*********************************/
/*********************************/
int onlykey_eeget_addchar2 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        	case 1:
			onlykey_eeget_common(ptr, EEpos_addchar2_1, EElen_addchar);
			return EElen_addchar;
            break;
		case 2:
			onlykey_eeget_common(ptr, EEpos_addchar2_2, EElen_addchar);
			return EElen_addchar;
            break;
		case 3:
			onlykey_eeget_common(ptr, EEpos_addchar2_3, EElen_addchar);
			return EElen_addchar;
            break;
		case 4:
			onlykey_eeget_common(ptr, EEpos_addchar2_4, EElen_addchar);
			return EElen_addchar;
            break;
		case 5:
			onlykey_eeget_common(ptr, EEpos_addchar2_5, EElen_addchar);
			return EElen_addchar;
            break;
		case 6:
			onlykey_eeget_common(ptr, EEpos_addchar2_6, EElen_addchar);
			return EElen_addchar;
            break;
		case 7:
			onlykey_eeget_common(ptr, EEpos_addchar2_7, EElen_addchar);
			return EElen_addchar;
            break;
		case 8:
			onlykey_eeget_common(ptr, EEpos_addchar2_8, EElen_addchar);
			return EElen_addchar;
            break;
		case 9:
			onlykey_eeget_common(ptr, EEpos_addchar2_9, EElen_addchar);
			return EElen_addchar;
            break;
		case 10:
			onlykey_eeget_common(ptr, EEpos_addchar2_10, EElen_addchar);
			return EElen_addchar;
            break;
		case 11:
			onlykey_eeget_common(ptr, EEpos_addchar2_11, EElen_addchar);
			return EElen_addchar;
            break;
		case 12:
			onlykey_eeget_common(ptr, EEpos_addchar2_12, EElen_addchar);
			return EElen_addchar;
            break;
		case 13:
			onlykey_eeget_common(ptr, EEpos_addchar2_13, EElen_addchar);
			return EElen_addchar;
            break;
		case 14:
			onlykey_eeget_common(ptr, EEpos_addchar2_14, EElen_addchar);
			return EElen_addchar;
            break;
		case 15:
			onlykey_eeget_common(ptr, EEpos_addchar2_15, EElen_addchar);
			return EElen_addchar;
            break;
		case 16:
			onlykey_eeget_common(ptr, EEpos_addchar2_16, EElen_addchar);
			return EElen_addchar;
            break;
		case 17:
			onlykey_eeget_common(ptr, EEpos_addchar2_17, EElen_addchar);
			return EElen_addchar;
            break;
		case 18:
			onlykey_eeget_common(ptr, EEpos_addchar2_18, EElen_addchar);
			return EElen_addchar;
            break;
		case 19:
			onlykey_eeget_common(ptr, EEpos_addchar2_19, EElen_addchar);
			return EElen_addchar;
            break;
		case 20:
			onlykey_eeget_common(ptr, EEpos_addchar2_20, EElen_addchar);
			return EElen_addchar;
            break;
		case 21:
			onlykey_eeget_common(ptr, EEpos_addchar2_21, EElen_addchar);
			return EElen_addchar;
            break;
		case 22:
			onlykey_eeget_common(ptr, EEpos_addchar2_22, EElen_addchar);
			return EElen_addchar;
            break;
		case 23:
			onlykey_eeget_common(ptr, EEpos_addchar2_23, EElen_addchar);
			return EElen_addchar;
            break;
		case 24:
			onlykey_eeget_common(ptr, EEpos_addchar2_24, EElen_addchar);
			return EElen_addchar;
            break;	
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_addchar2 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        	case 1:
		onlykey_eeset_common(ptr, EEpos_addchar2_1, EElen_addchar);
            break;
		case 2:
		onlykey_eeset_common(ptr, EEpos_addchar2_2, EElen_addchar);
            break;
		case 3:
		onlykey_eeset_common(ptr, EEpos_addchar2_3, EElen_addchar);
            break;
		case 4:
		onlykey_eeset_common(ptr, EEpos_addchar2_4, EElen_addchar);
            break;
		case 5:
		onlykey_eeset_common(ptr, EEpos_addchar2_5, EElen_addchar);
            break;
		case 6:
		onlykey_eeset_common(ptr, EEpos_addchar2_6, EElen_addchar);
            break;
		case 7:
		onlykey_eeset_common(ptr, EEpos_addchar2_7, EElen_addchar);
            break;
		case 8:
		onlykey_eeset_common(ptr, EEpos_addchar2_8, EElen_addchar);
            break;
		case 9:
		onlykey_eeset_common(ptr, EEpos_addchar2_9, EElen_addchar);
            break;
		case 10:
		onlykey_eeset_common(ptr, EEpos_addchar2_10, EElen_addchar);
            break;
		case 11:
		onlykey_eeset_common(ptr, EEpos_addchar2_11, EElen_addchar);
            break;
		case 12:
		onlykey_eeset_common(ptr, EEpos_addchar2_12, EElen_addchar);
            break;
        case 13:
		onlykey_eeset_common(ptr, EEpos_addchar2_13, EElen_addchar);
            break;
		case 14:
		onlykey_eeset_common(ptr, EEpos_addchar2_14, EElen_addchar);
            break;
		case 15:
		onlykey_eeset_common(ptr, EEpos_addchar2_15, EElen_addchar);
            break;
		case 16:
		onlykey_eeset_common(ptr, EEpos_addchar2_16, EElen_addchar);
            break;
		case 17:
		onlykey_eeset_common(ptr, EEpos_addchar2_17, EElen_addchar);
            break;
		case 18:
		onlykey_eeset_common(ptr, EEpos_addchar2_18, EElen_addchar);
            break;
		case 19:
		onlykey_eeset_common(ptr, EEpos_addchar2_19, EElen_addchar);
            break;
		case 20:
		onlykey_eeset_common(ptr, EEpos_addchar2_20, EElen_addchar);
            break;
		case 21:
		onlykey_eeset_common(ptr, EEpos_addchar2_21, EElen_addchar);
            break;
		case 22:
		onlykey_eeset_common(ptr, EEpos_addchar2_22, EElen_addchar);
            break;
		case 23:
		onlykey_eeset_common(ptr, EEpos_addchar2_23, EElen_addchar);
            break;
		case 24:
		onlykey_eeset_common(ptr, EEpos_addchar2_24, EElen_addchar);
            break;
	}

}
/*********************************/
/*********************************/
int onlykey_eeget_delay1 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        	case 1:
			onlykey_eeget_common(ptr, EEpos_delay1_1, EElen_delay);
			return EElen_delay;
            break;
		case 2:
			onlykey_eeget_common(ptr, EEpos_delay1_2, EElen_delay);
			return EElen_delay;
            break;
		case 3:
			onlykey_eeget_common(ptr, EEpos_delay1_3, EElen_delay);
			return EElen_delay;
            break;
		case 4:
			onlykey_eeget_common(ptr, EEpos_delay1_4, EElen_delay);
			return EElen_delay;
            break;
		case 5:
			onlykey_eeget_common(ptr, EEpos_delay1_5, EElen_delay);
			return EElen_delay;
            break;
		case 6:
			onlykey_eeget_common(ptr, EEpos_delay1_6, EElen_delay);
			return EElen_delay;
            break;
		case 7:
			onlykey_eeget_common(ptr, EEpos_delay1_7, EElen_delay);
			return EElen_delay;
            break;
		case 8:
			onlykey_eeget_common(ptr, EEpos_delay1_8, EElen_delay);
			return EElen_delay;
            break;
		case 9:
			onlykey_eeget_common(ptr, EEpos_delay1_9, EElen_delay);
			return EElen_delay;
            break;
		case 10:
			onlykey_eeget_common(ptr, EEpos_delay1_10, EElen_delay);
			return EElen_delay;
            break;
		case 11:
			onlykey_eeget_common(ptr, EEpos_delay1_11, EElen_delay);
			return EElen_delay;
            break;
		case 12:
			onlykey_eeget_common(ptr, EEpos_delay1_12, EElen_delay);
			return EElen_delay;
            break;
		case 13:
			onlykey_eeget_common(ptr, EEpos_delay1_13, EElen_delay);
			return EElen_delay;
            break;
		case 14:
			onlykey_eeget_common(ptr, EEpos_delay1_14, EElen_delay);
			return EElen_delay;
            break;
		case 15:
			onlykey_eeget_common(ptr, EEpos_delay1_15, EElen_delay);
			return EElen_delay;
            break;
		case 16:
			onlykey_eeget_common(ptr, EEpos_delay1_16, EElen_delay);
			return EElen_delay;
            break;
		case 17:
			onlykey_eeget_common(ptr, EEpos_delay1_17, EElen_delay);
			return EElen_delay;
            break;
		case 18:
			onlykey_eeget_common(ptr, EEpos_delay1_18, EElen_delay);
			return EElen_delay;
            break;
		case 19:
			onlykey_eeget_common(ptr, EEpos_delay1_19, EElen_delay);
			return EElen_delay;
            break;
		case 20:
			onlykey_eeget_common(ptr, EEpos_delay1_20, EElen_delay);
			return EElen_delay;
            break;
		case 21:
			onlykey_eeget_common(ptr, EEpos_delay1_21, EElen_delay);
			return EElen_delay;
            break;
		case 22:
			onlykey_eeget_common(ptr, EEpos_delay1_22, EElen_delay);
			return EElen_delay;
            break;
		case 23:
			onlykey_eeget_common(ptr, EEpos_delay1_23, EElen_delay);
			return EElen_delay;
            break;
		case 24:
			onlykey_eeget_common(ptr, EEpos_delay1_24, EElen_delay);
			return EElen_delay;
            break;	
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_delay1 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        	case 1:
		onlykey_eeset_common(ptr, EEpos_delay1_1, EElen_delay);
            break;
		case 2:
		onlykey_eeset_common(ptr, EEpos_delay1_2, EElen_delay);
            break;
		case 3:
		onlykey_eeset_common(ptr, EEpos_delay1_3, EElen_delay);
            break;
		case 4:
		onlykey_eeset_common(ptr, EEpos_delay1_4, EElen_delay);
            break;
		case 5:
		onlykey_eeset_common(ptr, EEpos_delay1_5, EElen_delay);
            break;
		case 6:
		onlykey_eeset_common(ptr, EEpos_delay1_6, EElen_delay);
            break;
		case 7:
		onlykey_eeset_common(ptr, EEpos_delay1_7, EElen_delay);
            break;
		case 8:
		onlykey_eeset_common(ptr, EEpos_delay1_8, EElen_delay);
            break;
		case 9:
		onlykey_eeset_common(ptr, EEpos_delay1_9, EElen_delay);
            break;
		case 10:
		onlykey_eeset_common(ptr, EEpos_delay1_10, EElen_delay);
            break;
		case 11:
		onlykey_eeset_common(ptr, EEpos_delay1_11, EElen_delay);
            break;
		case 12:
		onlykey_eeset_common(ptr, EEpos_delay1_12, EElen_delay);
            break;
        case 13:
		onlykey_eeset_common(ptr, EEpos_delay1_13, EElen_delay);
            break;
		case 14:
		onlykey_eeset_common(ptr, EEpos_delay1_14, EElen_delay);
            break;
		case 15:
		onlykey_eeset_common(ptr, EEpos_delay1_15, EElen_delay);
            break;
		case 16:
		onlykey_eeset_common(ptr, EEpos_delay1_16, EElen_delay);
            break;
		case 17:
		onlykey_eeset_common(ptr, EEpos_delay1_17, EElen_delay);
            break;
		case 18:
		onlykey_eeset_common(ptr, EEpos_delay1_18, EElen_delay);
            break;
		case 19:
		onlykey_eeset_common(ptr, EEpos_delay1_19, EElen_delay);
            break;
		case 20:
		onlykey_eeset_common(ptr, EEpos_delay1_20, EElen_delay);
            break;
		case 21:
		onlykey_eeset_common(ptr, EEpos_delay1_21, EElen_delay);
            break;
		case 22:
		onlykey_eeset_common(ptr, EEpos_delay1_22, EElen_delay);
            break;
		case 23:
		onlykey_eeset_common(ptr, EEpos_delay1_23, EElen_delay);
            break;
		case 24:
		onlykey_eeset_common(ptr, EEpos_delay1_24, EElen_delay);
            break;
	}

}
/*********************************/
/*********************************/
int onlykey_eeget_delay2 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        case 1:
			onlykey_eeget_common(ptr, EEpos_delay2_1, EElen_delay);
			return EElen_delay;
            break;
		case 2:
			onlykey_eeget_common(ptr, EEpos_delay2_2, EElen_delay);
			return EElen_delay;
            break;
		case 3:
			onlykey_eeget_common(ptr, EEpos_delay2_3, EElen_delay);
			return EElen_delay;
            break;
		case 4:
			onlykey_eeget_common(ptr, EEpos_delay2_4, EElen_delay);
			return EElen_delay;
            break;
		case 5:
			onlykey_eeget_common(ptr, EEpos_delay2_5, EElen_delay);
			return EElen_delay;
            break;
		case 6:
			onlykey_eeget_common(ptr, EEpos_delay2_6, EElen_delay);
			return EElen_delay;
            break;
		case 7:
			onlykey_eeget_common(ptr, EEpos_delay2_7, EElen_delay);
			return EElen_delay;
            break;
		case 8:
			onlykey_eeget_common(ptr, EEpos_delay2_8, EElen_delay);
			return EElen_delay;
            break;
		case 9:
			onlykey_eeget_common(ptr, EEpos_delay2_9, EElen_delay);
			return EElen_delay;
            break;
		case 10:
			onlykey_eeget_common(ptr, EEpos_delay2_10, EElen_delay);
			return EElen_delay;
            break;
		case 11:
			onlykey_eeget_common(ptr, EEpos_delay2_11, EElen_delay);
			return EElen_delay;
            break;
		case 12:
			onlykey_eeget_common(ptr, EEpos_delay2_12, EElen_delay);
			return EElen_delay;
            break;
			
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_delay2 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        case 1:
		onlykey_eeset_common(ptr, EEpos_delay2_1, EElen_delay);
            break;
		case 2:
		onlykey_eeset_common(ptr, EEpos_delay2_2, EElen_delay);
            break;
		case 3:
		onlykey_eeset_common(ptr, EEpos_delay2_3, EElen_delay);
            break;
		case 4:
		onlykey_eeset_common(ptr, EEpos_delay2_4, EElen_delay);
            break;
		case 5:
		onlykey_eeset_common(ptr, EEpos_delay2_5, EElen_delay);
            break;
		case 6:
		onlykey_eeset_common(ptr, EEpos_delay2_6, EElen_delay);
            break;
		case 7:
		onlykey_eeset_common(ptr, EEpos_delay2_7, EElen_delay);
            break;
		case 8:
		onlykey_eeset_common(ptr, EEpos_delay2_8, EElen_delay);
            break;
		case 9:
		onlykey_eeset_common(ptr, EEpos_delay2_9, EElen_delay);
            break;
		case 10:
		onlykey_eeset_common(ptr, EEpos_delay2_10, EElen_delay);
            break;
		case 11:
		onlykey_eeset_common(ptr, EEpos_delay2_11, EElen_delay);
            break;
		case 12:
		onlykey_eeset_common(ptr, EEpos_delay2_12, EElen_delay);
            break;
	}

}
/*********************************/
/*********************************/
int onlykey_eeget_2FAtype (uint8_t *ptr, int slot) {
    
	switch (slot) {
        	case 1:
			onlykey_eeget_common(ptr, EEpos_2FAtype1, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 2:
			onlykey_eeget_common(ptr, EEpos_2FAtype2, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 3:
			onlykey_eeget_common(ptr, EEpos_2FAtype3, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 4:
			onlykey_eeget_common(ptr, EEpos_2FAtype4, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 5:
			onlykey_eeget_common(ptr, EEpos_2FAtype5, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 6:
			onlykey_eeget_common(ptr, EEpos_2FAtype6, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 7:
			onlykey_eeget_common(ptr, EEpos_2FAtype7, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 8:
			onlykey_eeget_common(ptr, EEpos_2FAtype8, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 9:
			onlykey_eeget_common(ptr, EEpos_2FAtype9, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 10:
			onlykey_eeget_common(ptr, EEpos_2FAtype10, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 11:
			onlykey_eeget_common(ptr, EEpos_2FAtype11, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 12:
			onlykey_eeget_common(ptr, EEpos_2FAtype12, EElen_2FAtype);
			return EElen_2FAtype;
            break;
            	case 13:
			onlykey_eeget_common(ptr, EEpos_2FAtype13, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 14:
			onlykey_eeget_common(ptr, EEpos_2FAtype14, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 15:
			onlykey_eeget_common(ptr, EEpos_2FAtype15, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 16:
			onlykey_eeget_common(ptr, EEpos_2FAtype16, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 17:
			onlykey_eeget_common(ptr, EEpos_2FAtype17, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 18:
			onlykey_eeget_common(ptr, EEpos_2FAtype18, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 19:
			onlykey_eeget_common(ptr, EEpos_2FAtype19, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 20:
			onlykey_eeget_common(ptr, EEpos_2FAtype20, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 21:
			onlykey_eeget_common(ptr, EEpos_2FAtype21, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 22:
			onlykey_eeget_common(ptr, EEpos_2FAtype22, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 23:
			onlykey_eeget_common(ptr, EEpos_2FAtype23, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 24:
			onlykey_eeget_common(ptr, EEpos_2FAtype24, EElen_2FAtype);
			return EElen_2FAtype;
            break;
			
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_2FAtype (uint8_t *ptr, int slot) {
    
		switch (slot) {

        	case 1:
		onlykey_eeset_common(ptr, EEpos_2FAtype1, EElen_2FAtype);
            break;
		case 2:
		onlykey_eeset_common(ptr, EEpos_2FAtype2, EElen_2FAtype);
            break;
		case 3:
		onlykey_eeset_common(ptr, EEpos_2FAtype3, EElen_2FAtype);
            break;
		case 4:
		onlykey_eeset_common(ptr, EEpos_2FAtype4, EElen_2FAtype);
            break;
		case 5:
		onlykey_eeset_common(ptr, EEpos_2FAtype5, EElen_2FAtype);
            break;
		case 6:
		onlykey_eeset_common(ptr, EEpos_2FAtype6, EElen_2FAtype);
            break;
		case 7:
		onlykey_eeset_common(ptr, EEpos_2FAtype7, EElen_2FAtype);
            break;
		case 8:
		onlykey_eeset_common(ptr, EEpos_2FAtype8, EElen_2FAtype);
            break;
		case 9:
		onlykey_eeset_common(ptr, EEpos_2FAtype9, EElen_2FAtype);
            break;
		case 10:
		onlykey_eeset_common(ptr, EEpos_2FAtype10, EElen_2FAtype);
            break;
		case 11:
		onlykey_eeset_common(ptr, EEpos_2FAtype11, EElen_2FAtype);
            break;
		case 12:
		onlykey_eeset_common(ptr, EEpos_2FAtype12, EElen_2FAtype);
            break;
            	case 13:
		onlykey_eeset_common(ptr, EEpos_2FAtype13, EElen_2FAtype);
            break;
		case 14:
		onlykey_eeset_common(ptr, EEpos_2FAtype14, EElen_2FAtype);
            break;
		case 15:
		onlykey_eeset_common(ptr, EEpos_2FAtype15, EElen_2FAtype);
            break;
		case 16:
		onlykey_eeset_common(ptr, EEpos_2FAtype16, EElen_2FAtype);
            break;
		case 17:
		onlykey_eeset_common(ptr, EEpos_2FAtype17, EElen_2FAtype);
            break;
		case 18:
		onlykey_eeset_common(ptr, EEpos_2FAtype18, EElen_2FAtype);
            break;
		case 19:
		onlykey_eeset_common(ptr, EEpos_2FAtype19, EElen_2FAtype);
            break;
		case 20:
		onlykey_eeset_common(ptr, EEpos_2FAtype20, EElen_2FAtype);
            break;
		case 21:
		onlykey_eeset_common(ptr, EEpos_2FAtype21, EElen_2FAtype);
            break;
		case 22:
		onlykey_eeset_common(ptr, EEpos_2FAtype22, EElen_2FAtype);
            break;
		case 23:
		onlykey_eeset_common(ptr, EEpos_2FAtype23, EElen_2FAtype);
            break;
		case 24:
		onlykey_eeset_common(ptr, EEpos_2FAtype24, EElen_2FAtype);
            break;
	}

}
/*********************************/
/*********************************/
int onlykey_eeget_username (uint8_t *ptr, int slot) {
    
	switch (slot) {
		uint8_t length;
		int size;
        	case 1:
			onlykey_eeget_usernamelen1(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username1, EElen_username);
			return size;
            break;
		case 2:
			onlykey_eeget_usernamelen2(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username2, EElen_username);
			return size;
            break;
		case 3:
			onlykey_eeget_usernamelen3(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username3, EElen_username);
			return size;
            break;
		case 4:
			onlykey_eeget_usernamelen4(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username4, EElen_username);
			return size;
            break;
		case 5:
			onlykey_eeget_usernamelen5(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username5, EElen_username);
			return size;
            break;
		case 6:
			onlykey_eeget_usernamelen6(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username6, EElen_username);
			return size;
            break;
		case 7:
			onlykey_eeget_usernamelen7(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username7, EElen_username);
			return size;
            break;
		case 8:
			onlykey_eeget_usernamelen8(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username8, EElen_username);
			return size;
            break;
		case 9:
			onlykey_eeget_usernamelen9(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username9, EElen_username);
			return size;
            break;
		case 10:
			onlykey_eeget_usernamelen10(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username10, EElen_username);
			return size;
            break;
		case 11:
			onlykey_eeget_usernamelen11(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username11, EElen_username);
			return size;
            break;
		case 12:
			onlykey_eeget_usernamelen12(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username12, EElen_username);
			return size;
            break;
        case 13:
			onlykey_eeget_usernamelen13(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username13, EElen_username);
			return size;
            break;
		case 14:
			onlykey_eeget_usernamelen14(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username14, EElen_username);
			return size;
            break;
		case 15:
			onlykey_eeget_usernamelen15(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username15, EElen_username);
			return size;
            break;
		case 16:
			onlykey_eeget_usernamelen16(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username16, EElen_username);
			return size;
            break;
		case 17:
			onlykey_eeget_usernamelen17(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username17, EElen_username);
			return size;
            break;
		case 18:
			onlykey_eeget_usernamelen18(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username18, EElen_username);
			return size;
            break;
		case 19:
			onlykey_eeget_usernamelen19(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username19, EElen_username);
			return size;
            break;
		case 20:
			onlykey_eeget_usernamelen20(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username20, EElen_username);
			return size;
            break;
		case 21:
			onlykey_eeget_usernamelen21(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username21, EElen_username);
			return size;
            break;
		case 22:
			onlykey_eeget_usernamelen22(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username22, EElen_username);
			return size;
            break;
		case 23:
			onlykey_eeget_usernamelen23(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username23, EElen_username);
			return size;
            break;
		case 24:
			onlykey_eeget_usernamelen24(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_eeget_common(ptr, EEpos_username24, EElen_username);
			return size;
            break;
			
	}

}
/*********************************/
/*********************************/
void onlykey_eeset_username (uint8_t *ptr, int size, int slot) {
    
		switch (slot) {
			uint8_t length;
        case 1:
			
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username1, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen1(&length);
            break;
		case 2:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username2, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen2(&length);
            break;
		case 3:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username3, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen3(&length);
            break;
		case 4:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username4, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen4(&length);
            break;
		case 5:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username5, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen5(&length);
            break;
		case 6:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username6, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen6(&length);
            break;
		case 7:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username7, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen7(&length);
            break;
		case 8:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username8, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen8(&length);
            break;
		case 9:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username9, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen9(&length);
            break;
		case 10:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username10, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen10(&length);
            break;
		case 11:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username11, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen11(&length);
            break;
		case 12:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username12, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen11(&length);
            break;
        case 13:
			
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username13, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen13(&length);
            break;
		case 14:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username14, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen14(&length);
            break;
		case 15:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username15, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen15(&length);
            break;
		case 16:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username16, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen16(&length);
            break;
		case 17:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username17, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen17(&length);
            break;
		case 18:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username18, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen18(&length);
            break;
		case 19:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username19, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen19(&length);
            break;
		case 20:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username20, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen20(&length);
            break;
		case 21:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username21, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen21(&length);
            break;
		case 22:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username22, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen22(&length);
            break;
		case 23:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username23, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen23(&length);
            break;
		case 24:
		
			if (size > EElen_username) size = EElen_username;
			onlykey_eeset_common(ptr, EEpos_username24, EElen_username);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen24(&length);
            break;
            
	}

}


