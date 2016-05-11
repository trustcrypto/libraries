/* ykseeprom.c --- adaption of libyubikey for Teensy 3.X
**
**  msd, 25-sep-2012:	read/write persistent values from/to EEPROM
**  
*/

#include <Arduino.h>
#include <avr/eeprom.h>
#include "ykseeprom.h"

/*********************************/

void yubikey_eeget_common(
	uint8_t	*ptr,
	int	addr,
	int	len)
{
    while (len--) {
	*ptr++ = eeprom_read_byte(addr++);
    }
}

void yubikey_eeset_common(
	uint8_t	*ptr,
	int	addr,
	int	len)
{
    while (len--) {
	eeprom_write_byte(addr++, *ptr++);
    }
}

/*********************************/

int yubikey_eeget_failedlogins (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_failedlogins, EElen_failedlogins);
    return EElen_failedlogins;
}
void yubikey_eeset_failedlogins (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_failedlogins, EElen_failedlogins);
}

/*********************************/

/*********************************/

int yubikey_eeget_noncehash (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_noncehash , EElen_noncehash);
    return EElen_noncehash;
}
void yubikey_eeset_noncehash (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_noncehash, EElen_noncehash);
}

/*********************************/

/*********************************/

int yubikey_eeget_pinhash (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_pinhash, EElen_pinhash);
    return EElen_pinhash;
}
void yubikey_eeset_pinhash (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_pinhash, EElen_pinhash);
}

/*********************************/
/*********************************/

int yubikey_eeget_selfdestructhash (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_selfdestructhash, EElen_selfdestructhash);
    return EElen_selfdestructhash;
}
void yubikey_eeset_selfdestructhash (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_selfdestructhash, EElen_selfdestructhash);
}

/*********************************/
/*********************************/

int yubikey_eeget_plausdenyhash (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_plausdenyhash, EElen_plausdenyhash);
    return EElen_plausdenyhash;
}
void yubikey_eeset_plausdenyhash (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_plausdenyhash, EElen_plausdenyhash);
}

/*********************************/


/*********************************/

int yubikey_eeget_U2Fprivlen (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_U2Fprivlen, EElen_U2Fprivlen);
    return EElen_U2Fprivlen;
}
void yubikey_eeset_U2Fprivlen (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_U2Fprivlen, EElen_U2Fprivlen);
}

/*********************************/

/*********************************/

int yubikey_eeget_U2Fcertlen (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_U2Fcertlen, EElen_U2Fcertlen);
    return EElen_U2Fcertlen;
}
void yubikey_eeset_U2Fcertlen (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_U2Fcertlen, EElen_U2Fcertlen);
}

/*********************************/
/*********************************/

int yubikey_eeget_U2Fprivpos (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_U2Fprivpos, EElen_U2Fprivpos);
    return EElen_U2Fprivpos;
}
void yubikey_eeset_U2Fprivpos (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_U2Fprivpos, EElen_U2Fprivpos);
}

/*********************************/

/*********************************/

int yubikey_eeget_U2Fcertpos (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_U2Fcertpos, EElen_U2Fcertpos);
    return EElen_U2Fcertpos;
}
void yubikey_eeset_U2Fcertpos (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_U2Fcertpos, EElen_U2Fcertpos);
}

/*********************************/

/*********************************/

int yubikey_eeget_keylen (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_keylen, EElen_keylen);
    return EElen_keylen;
}
void yubikey_eeset_keylen (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_keylen, EElen_keylen);
}

/*********************************/

int yubikey_eeget_ctrlen (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_ctrlen, EElen_ctrlen);
    return EElen_ctrlen;
}
void yubikey_eeset_ctrlen (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_ctrlen, EElen_ctrlen);
}

/*********************************/

int yubikey_eeget_prvlen (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_prvlen, EElen_prvlen);
    return EElen_prvlen;
}
void yubikey_eeset_prvlen (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_prvlen, EElen_prvlen);
}


/*********************************/

int yubikey_eeget_publen (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_publen, EElen_publen);
    return EElen_publen;
}
void yubikey_eeset_publen (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_publen, EElen_publen);
}

/*********************************/

int yubikey_eeget_passwordlen1 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password1len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen1 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password1len, EElen_passwordlen);
}

/********************************/

int yubikey_eeget_passwordlen2 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password2len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen2 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password2len, EElen_passwordlen);
}

/********************************/

int yubikey_eeget_passwordlen3 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password3len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen3 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password3len, EElen_passwordlen);
}

/********************************/

int yubikey_eeget_passwordlen4 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password4len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen4 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password4len, EElen_passwordlen);
}

/********************************/

int yubikey_eeget_passwordlen5 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password5len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen5 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password5len, EElen_passwordlen);
}

/********************************/

int yubikey_eeget_passwordlen6 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password6len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen6 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password6len, EElen_passwordlen);
}

/********************************/
/*********************************/

int yubikey_eeget_passwordlen7 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password7len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen7 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password7len, EElen_passwordlen);
}

/********************************/
/*********************************/

int yubikey_eeget_passwordlen8 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password8len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen8 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password8len, EElen_passwordlen);
}

/********************************/
/*********************************/

int yubikey_eeget_passwordlen9 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password9len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen9 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password9len, EElen_passwordlen);
}

/********************************/
/*********************************/

int yubikey_eeget_passwordlen10 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password10len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen10 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password10len, EElen_passwordlen);
}

/********************************/
/*********************************/

int yubikey_eeget_passwordlen11 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password11len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen11 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password11len, EElen_passwordlen);
}

/********************************/
/*********************************/

int yubikey_eeget_passwordlen12 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_password12len, EElen_passwordlen);
    return EElen_passwordlen;
}
void yubikey_eeset_passwordlen12 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_password12len, EElen_passwordlen);
}

/********************************/
/*********************************/

int yubikey_eeget_usernamelen1 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username1len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen1 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username1len, EElen_usernamelen);
}

/********************************/

int yubikey_eeget_usernamelen2 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username2len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen2 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username2len, EElen_usernamelen);
}

/********************************/

int yubikey_eeget_usernamelen3 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username3len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen3 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username3len, EElen_usernamelen);
}

/********************************/

int yubikey_eeget_usernamelen4 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username4len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen4 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username4len, EElen_usernamelen);
}

/********************************/

int yubikey_eeget_usernamelen5 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username5len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen5 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username5len, EElen_usernamelen);
}

/********************************/

int yubikey_eeget_usernamelen6 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username6len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen6 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username6len, EElen_usernamelen);
}

/********************************/
/*********************************/

int yubikey_eeget_usernamelen7 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username7len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen7 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username7len, EElen_usernamelen);
}

/********************************/
/*********************************/

int yubikey_eeget_usernamelen8 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username8len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen8 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username8len, EElen_usernamelen);
}

/********************************/
/*********************************/

int yubikey_eeget_usernamelen9 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username9len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen9 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username9len, EElen_usernamelen);
}

/********************************/
/*********************************/

int yubikey_eeget_usernamelen10 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username10len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen10 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username10len, EElen_usernamelen);
}

/********************************/
/*********************************/

int yubikey_eeget_usernamelen11 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username11len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen11 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username11len, EElen_usernamelen);
}

/********************************/
/*********************************/

int yubikey_eeget_usernamelen12 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_username12len, EElen_usernamelen);
    return EElen_usernamelen;
}
void yubikey_eeset_usernamelen12 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_username12len, EElen_usernamelen);
}

/********************************/

/*********************************/

int yubikey_eeget_totpkeylen1 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey1len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen1 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey1len, EElen_totpkeylen);
}

/********************************/

int yubikey_eeget_totpkeylen2 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey2len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen2 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey2len, EElen_totpkeylen);
}

/********************************/

int yubikey_eeget_totpkeylen3 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey3len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen3 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey3len, EElen_totpkeylen);
}

/********************************/

int yubikey_eeget_totpkeylen4 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey4len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen4 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey4len, EElen_totpkeylen);
}

/********************************/

int yubikey_eeget_totpkeylen5 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey5len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen5 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey5len, EElen_totpkeylen);
}

/********************************/

int yubikey_eeget_totpkeylen6 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey6len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen6 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey6len, EElen_totpkeylen);
}

/********************************/
/*********************************/

int yubikey_eeget_totpkeylen7 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey7len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen7 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey7len, EElen_totpkeylen);
}

/********************************/
/*********************************/

int yubikey_eeget_totpkeylen8 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey8len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen8 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey8len, EElen_totpkeylen);
}

/********************************/
/*********************************/

int yubikey_eeget_totpkeylen9 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey9len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen9 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey9len, EElen_totpkeylen);
}

/********************************/
/*********************************/

int yubikey_eeget_totpkeylen10 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey10len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen10 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey10len, EElen_totpkeylen);
}

/********************************/
/*********************************/

int yubikey_eeget_totpkeylen11 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey11len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen11 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey11len, EElen_totpkeylen);
}

/********************************/
/*********************************/

int yubikey_eeget_totpkeylen12 (uint8_t *ptr) {
    yubikey_eeget_common(ptr, EEpos_totpkey12len, EElen_totpkeylen);
    return EElen_totpkeylen;
}
void yubikey_eeset_totpkeylen12 (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_totpkey12len, EElen_totpkeylen);
}

/********************************/

int yubikey_eeget_aeskey (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_keylen(&length);
    if (length != EElen_aeskey) return 0;
    yubikey_eeget_common(ptr, EEpos_aeskey, EElen_aeskey);
    return EElen_aeskey;
}
void yubikey_eeset_aeskey (uint8_t *ptr, int size) {
    if (size > EElen_aeskey) size = EElen_aeskey;
    yubikey_eeset_common(ptr, EEpos_aeskey, size);
    uint8_t length = (uint8_t) size;
    yubikey_eeset_keylen(&length);
}

/*********************************/

int yubikey_eeget_counter (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_ctrlen(&length);
    if (length != EElen_counter) return 0;
    yubikey_eeget_common(ptr, EEpos_counter, EElen_counter);
    return EElen_counter;
}
void yubikey_eeset_counter (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_counter, EElen_counter);
    uint8_t length = EElen_counter;
    yubikey_eeset_ctrlen(&length);
}

/*********************************/

int yubikey_eeget_private (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_prvlen(&length);
    if (length != EElen_private) return 0;
    yubikey_eeget_common(ptr, EEpos_private, EElen_private);
    return EElen_private;
}
void yubikey_eeset_private (uint8_t *ptr) {
    yubikey_eeset_common(ptr, EEpos_private, EElen_private);
    uint8_t length = EElen_private;
    yubikey_eeset_prvlen(&length);
}

/*********************************/

int yubikey_eeget_public (uint8_t *ptr) {
    uint8_t length;
    yubikey_eeget_publen(&length);
    int size = (int) length;
    if (size > EElen_public) size = EElen_public;
    yubikey_eeget_common(ptr, EEpos_public, size);
    return size;
}
void yubikey_eeset_public (uint8_t *ptr, int size) {
    if (size > EElen_public) size = EElen_public;
    yubikey_eeset_common(ptr, EEpos_public, size);
    uint8_t length = (uint8_t) size;
    yubikey_eeset_publen(&length);
}

/*********************************/

/*********************************/



int yubikey_eeget_password (uint8_t *ptr, int slot) {
    
	switch (slot) {
		uint8_t length;
		int size;
        case 1:
			yubikey_eeget_passwordlen1(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password1, size);
			return size;
            break;
		case 2:
			yubikey_eeget_passwordlen2(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password2, size);
			return size;
            break;
		case 3:
			yubikey_eeget_passwordlen3(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password3, size);
			return size;
            break;
		case 4:
			yubikey_eeget_passwordlen4(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password4, size);
			return size;
            break;
		case 5:
			yubikey_eeget_passwordlen5(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password5, size);
			return size;
            break;
		case 6:
			yubikey_eeget_passwordlen6(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password6, size);
			return size;
            break;
		case 7:
			yubikey_eeget_passwordlen7(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password7, size);
			return size;
            break;
		case 8:
			yubikey_eeget_passwordlen8(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password8, size);
			return size;
            break;
		case 9:
			yubikey_eeget_passwordlen9(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password9, size);
			return size;
            break;
		case 10:
			yubikey_eeget_passwordlen10(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password10, size);
			return size;
            break;
		case 11:
			yubikey_eeget_passwordlen11(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password11, size);
			return size;
            break;
		case 12:
			yubikey_eeget_passwordlen12(&length);
			size = (int) length;
			if (size > EElen_password) size = EElen_password;
			yubikey_eeget_common(ptr, EEpos_password12, size);
			return size;
            break;
			
	}

}
void yubikey_eeset_password (uint8_t *ptr, int size, int slot) {
    
		switch (slot) {
			uint8_t length;
        case 1:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password1, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen1(&length);
            break;
		case 2:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password2, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen2(&length);
            break;
		case 3:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password3, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen3(&length);
            break;
		case 4:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password4, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen4(&length);
            break;
		case 5:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password5, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen5(&length);
            break;
		case 6:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password6, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen6(&length);
            break;
		case 7:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password7, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen7(&length);
            break;
		case 8:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password8, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen8(&length);
            break;
		case 9:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password9, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen9(&length);
            break;
		case 10:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password10, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen10(&length);
            break;
		case 11:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password11, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen11(&length);
            break;
		case 12:
		
			if (size > EElen_password) size = EElen_password;
			yubikey_eeset_common(ptr, EEpos_password12, size);
			length = (uint8_t) size;
			yubikey_eeset_passwordlen11(&length);
            break;
	}

}

/*********************************/

/*********************************/



int yubikey_eeget_label (uint8_t *ptr, int slot) {
    
	switch (slot) {
		int size;
        case 1:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label1, size);
			return size;
            break;
		case 2:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label2, size);
			return size;
            break;
		case 3:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label3, size);
			return size;
            break;
		case 4:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label4, size);
			return size;
            break;
		case 5:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label5, size);
			return size;
            break;
		case 6:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label6, size);
			return size;
            break;
		case 7:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label7, size);
			return size;
            break;
		case 8:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label8, size);
			return size;
            break;
		case 9:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label9, size);
			return size;
            break;
		case 10:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label10, size);
			return size;
            break;
		case 11:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label11, size);
			return size;
            break;
		case 12:
			size = EElen_label;
			yubikey_eeget_common(ptr, EEpos_label12, size);
			return size;
            break;
			
	}

}
void yubikey_eeset_label (uint8_t *ptr, int size, int slot) {
    
		switch (slot) {
        case 1:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label1, size);
            break;
		case 2:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label2, size);
            break;
		case 3:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label3, size);
            break;
		case 4:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label4, size);
            break;
		case 5:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label5, size);
            break;
		case 6:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label6, size);
            break;
		case 7:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label7, size);
            break;
		case 8:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label8, size);
            break;
		case 9:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label9, size);
            break;
		case 10:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label10, size);
            break;
		case 11:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label11, size);
            break;
		case 12:
			size = EElen_label;
			yubikey_eeset_common(ptr, EEpos_label12, size);
            break;
	}

}

/*********************************/

/*********************************/



int yubikey_eeget_addchar1 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        case 1:
			yubikey_eeget_common(ptr, EEpos_addchar1_1, EElen_addchar);
			return EElen_addchar;
            break;
		case 2:
			yubikey_eeget_common(ptr, EEpos_addchar1_2, EElen_addchar);
			return EElen_addchar;
            break;
		case 3:
			yubikey_eeget_common(ptr, EEpos_addchar1_3, EElen_addchar);
			return EElen_addchar;
            break;
		case 4:
			yubikey_eeget_common(ptr, EEpos_addchar1_4, EElen_addchar);
			return EElen_addchar;
            break;
		case 5:
			yubikey_eeget_common(ptr, EEpos_addchar1_5, EElen_addchar);
			return EElen_addchar;
            break;
		case 6:
			yubikey_eeget_common(ptr, EEpos_addchar1_6, EElen_addchar);
			return EElen_addchar;
            break;
		case 7:
			yubikey_eeget_common(ptr, EEpos_addchar1_7, EElen_addchar);
			return EElen_addchar;
            break;
		case 8:
			yubikey_eeget_common(ptr, EEpos_addchar1_8, EElen_addchar);
			return EElen_addchar;
            break;
		case 9:
			yubikey_eeget_common(ptr, EEpos_addchar1_9, EElen_addchar);
			return EElen_addchar;
            break;
		case 10:
			yubikey_eeget_common(ptr, EEpos_addchar1_10, EElen_addchar);
			return EElen_addchar;
            break;
		case 11:
			yubikey_eeget_common(ptr, EEpos_addchar1_11, EElen_addchar);
			return EElen_addchar;
            break;
		case 12:
			yubikey_eeget_common(ptr, EEpos_addchar1_12, EElen_addchar);
			return EElen_addchar;
            break;
			
	}

}
void yubikey_eeset_addchar1 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        case 1:
		yubikey_eeset_common(ptr, EEpos_addchar1_1, EElen_addchar);
            break;
		case 2:
		yubikey_eeset_common(ptr, EEpos_addchar1_2, EElen_addchar);
            break;
		case 3:
		yubikey_eeset_common(ptr, EEpos_addchar1_3, EElen_addchar);
            break;
		case 4:
		yubikey_eeset_common(ptr, EEpos_addchar1_4, EElen_addchar);
            break;
		case 5:
		yubikey_eeset_common(ptr, EEpos_addchar1_5, EElen_addchar);
            break;
		case 6:
		yubikey_eeset_common(ptr, EEpos_addchar1_6, EElen_addchar);
            break;
		case 7:
		yubikey_eeset_common(ptr, EEpos_addchar1_7, EElen_addchar);
            break;
		case 8:
		yubikey_eeset_common(ptr, EEpos_addchar1_8, EElen_addchar);
            break;
		case 9:
		yubikey_eeset_common(ptr, EEpos_addchar1_9, EElen_addchar);
            break;
		case 10:
		yubikey_eeset_common(ptr, EEpos_addchar1_10, EElen_addchar);
            break;
		case 11:
		yubikey_eeset_common(ptr, EEpos_addchar1_11, EElen_addchar);
            break;
		case 12:
		yubikey_eeset_common(ptr, EEpos_addchar1_12, EElen_addchar);
            break;
	}

}

/*********************************/

int yubikey_eeget_addchar2 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        case 1:
			yubikey_eeget_common(ptr, EEpos_addchar2_1, EElen_addchar);
			return EElen_addchar;
            break;
		case 2:
			yubikey_eeget_common(ptr, EEpos_addchar2_2, EElen_addchar);
			return EElen_addchar;
            break;
		case 3:
			yubikey_eeget_common(ptr, EEpos_addchar2_3, EElen_addchar);
			return EElen_addchar;
            break;
		case 4:
			yubikey_eeget_common(ptr, EEpos_addchar2_4, EElen_addchar);
			return EElen_addchar;
            break;
		case 5:
			yubikey_eeget_common(ptr, EEpos_addchar2_5, EElen_addchar);
			return EElen_addchar;
            break;
		case 6:
			yubikey_eeget_common(ptr, EEpos_addchar2_6, EElen_addchar);
			return EElen_addchar;
            break;
		case 7:
			yubikey_eeget_common(ptr, EEpos_addchar2_7, EElen_addchar);
			return EElen_addchar;
            break;
		case 8:
			yubikey_eeget_common(ptr, EEpos_addchar2_8, EElen_addchar);
			return EElen_addchar;
            break;
		case 9:
			yubikey_eeget_common(ptr, EEpos_addchar2_9, EElen_addchar);
			return EElen_addchar;
            break;
		case 10:
			yubikey_eeget_common(ptr, EEpos_addchar2_10, EElen_addchar);
			return EElen_addchar;
            break;
		case 11:
			yubikey_eeget_common(ptr, EEpos_addchar2_11, EElen_addchar);
			return EElen_addchar;
            break;
		case 12:
			yubikey_eeget_common(ptr, EEpos_addchar2_12, EElen_addchar);
			return EElen_addchar;
            break;
			
	}

}
void yubikey_eeset_addchar2 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        case 1:
		yubikey_eeset_common(ptr, EEpos_addchar2_1, EElen_addchar);
            break;
		case 2:
		yubikey_eeset_common(ptr, EEpos_addchar2_2, EElen_addchar);
            break;
		case 3:
		yubikey_eeset_common(ptr, EEpos_addchar2_3, EElen_addchar);
            break;
		case 4:
		yubikey_eeset_common(ptr, EEpos_addchar2_4, EElen_addchar);
            break;
		case 5:
		yubikey_eeset_common(ptr, EEpos_addchar2_5, EElen_addchar);
            break;
		case 6:
		yubikey_eeset_common(ptr, EEpos_addchar2_6, EElen_addchar);
            break;
		case 7:
		yubikey_eeset_common(ptr, EEpos_addchar2_7, EElen_addchar);
            break;
		case 8:
		yubikey_eeset_common(ptr, EEpos_addchar2_8, EElen_addchar);
            break;
		case 9:
		yubikey_eeset_common(ptr, EEpos_addchar2_9, EElen_addchar);
            break;
		case 10:
		yubikey_eeset_common(ptr, EEpos_addchar2_10, EElen_addchar);
            break;
		case 11:
		yubikey_eeset_common(ptr, EEpos_addchar2_11, EElen_addchar);
            break;
		case 12:
		yubikey_eeset_common(ptr, EEpos_addchar2_12, EElen_addchar);
            break;
	}

}

/*********************************/



int yubikey_eeget_delay1 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        case 1:
			yubikey_eeget_common(ptr, EEpos_delay1_1, EElen_delay);
			return EElen_delay;
            break;
		case 2:
			yubikey_eeget_common(ptr, EEpos_delay1_2, EElen_delay);
			return EElen_delay;
            break;
		case 3:
			yubikey_eeget_common(ptr, EEpos_delay1_3, EElen_delay);
			return EElen_delay;
            break;
		case 4:
			yubikey_eeget_common(ptr, EEpos_delay1_4, EElen_delay);
			return EElen_delay;
            break;
		case 5:
			yubikey_eeget_common(ptr, EEpos_delay1_5, EElen_delay);
			return EElen_delay;
            break;
		case 6:
			yubikey_eeget_common(ptr, EEpos_delay1_6, EElen_delay);
			return EElen_delay;
            break;
		case 7:
			yubikey_eeget_common(ptr, EEpos_delay1_7, EElen_delay);
			return EElen_delay;
            break;
		case 8:
			yubikey_eeget_common(ptr, EEpos_delay1_8, EElen_delay);
			return EElen_delay;
            break;
		case 9:
			yubikey_eeget_common(ptr, EEpos_delay1_9, EElen_delay);
			return EElen_delay;
            break;
		case 10:
			yubikey_eeget_common(ptr, EEpos_delay1_10, EElen_delay);
			return EElen_delay;
            break;
		case 11:
			yubikey_eeget_common(ptr, EEpos_delay1_11, EElen_delay);
			return EElen_delay;
            break;
		case 12:
			yubikey_eeget_common(ptr, EEpos_delay1_12, EElen_delay);
			return EElen_delay;
            break;
			
	}

}
void yubikey_eeset_delay1 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        case 1:
		yubikey_eeset_common(ptr, EEpos_delay1_1, EElen_delay);
            break;
		case 2:
		yubikey_eeset_common(ptr, EEpos_delay1_2, EElen_delay);
            break;
		case 3:
		yubikey_eeset_common(ptr, EEpos_delay1_3, EElen_delay);
            break;
		case 4:
		yubikey_eeset_common(ptr, EEpos_delay1_4, EElen_delay);
            break;
		case 5:
		yubikey_eeset_common(ptr, EEpos_delay1_5, EElen_delay);
            break;
		case 6:
		yubikey_eeset_common(ptr, EEpos_delay1_6, EElen_delay);
            break;
		case 7:
		yubikey_eeset_common(ptr, EEpos_delay1_7, EElen_delay);
            break;
		case 8:
		yubikey_eeset_common(ptr, EEpos_delay1_8, EElen_delay);
            break;
		case 9:
		yubikey_eeset_common(ptr, EEpos_delay1_9, EElen_delay);
            break;
		case 10:
		yubikey_eeset_common(ptr, EEpos_delay1_10, EElen_delay);
            break;
		case 11:
		yubikey_eeset_common(ptr, EEpos_delay1_11, EElen_delay);
            break;
		case 12:
		yubikey_eeset_common(ptr, EEpos_delay1_12, EElen_delay);
            break;
	}

}

/*********************************/

int yubikey_eeget_delay2 (uint8_t *ptr, int slot) {
    
	switch (slot) {
        case 1:
			yubikey_eeget_common(ptr, EEpos_delay2_1, EElen_delay);
			return EElen_delay;
            break;
		case 2:
			yubikey_eeget_common(ptr, EEpos_delay2_2, EElen_delay);
			return EElen_delay;
            break;
		case 3:
			yubikey_eeget_common(ptr, EEpos_delay2_3, EElen_delay);
			return EElen_delay;
            break;
		case 4:
			yubikey_eeget_common(ptr, EEpos_delay2_4, EElen_delay);
			return EElen_delay;
            break;
		case 5:
			yubikey_eeget_common(ptr, EEpos_delay2_5, EElen_delay);
			return EElen_delay;
            break;
		case 6:
			yubikey_eeget_common(ptr, EEpos_delay2_6, EElen_delay);
			return EElen_delay;
            break;
		case 7:
			yubikey_eeget_common(ptr, EEpos_delay2_7, EElen_delay);
			return EElen_delay;
            break;
		case 8:
			yubikey_eeget_common(ptr, EEpos_delay2_8, EElen_delay);
			return EElen_delay;
            break;
		case 9:
			yubikey_eeget_common(ptr, EEpos_delay2_9, EElen_delay);
			return EElen_delay;
            break;
		case 10:
			yubikey_eeget_common(ptr, EEpos_delay2_10, EElen_delay);
			return EElen_delay;
            break;
		case 11:
			yubikey_eeget_common(ptr, EEpos_delay2_11, EElen_delay);
			return EElen_delay;
            break;
		case 12:
			yubikey_eeget_common(ptr, EEpos_delay2_12, EElen_delay);
			return EElen_delay;
            break;
			
	}

}
void yubikey_eeset_delay2 (uint8_t *ptr, int slot) {
    
		switch (slot) {

        case 1:
		yubikey_eeset_common(ptr, EEpos_delay2_1, EElen_delay);
            break;
		case 2:
		yubikey_eeset_common(ptr, EEpos_delay2_2, EElen_delay);
            break;
		case 3:
		yubikey_eeset_common(ptr, EEpos_delay2_3, EElen_delay);
            break;
		case 4:
		yubikey_eeset_common(ptr, EEpos_delay2_4, EElen_delay);
            break;
		case 5:
		yubikey_eeset_common(ptr, EEpos_delay2_5, EElen_delay);
            break;
		case 6:
		yubikey_eeset_common(ptr, EEpos_delay2_6, EElen_delay);
            break;
		case 7:
		yubikey_eeset_common(ptr, EEpos_delay2_7, EElen_delay);
            break;
		case 8:
		yubikey_eeset_common(ptr, EEpos_delay2_8, EElen_delay);
            break;
		case 9:
		yubikey_eeset_common(ptr, EEpos_delay2_9, EElen_delay);
            break;
		case 10:
		yubikey_eeset_common(ptr, EEpos_delay2_10, EElen_delay);
            break;
		case 11:
		yubikey_eeset_common(ptr, EEpos_delay2_11, EElen_delay);
            break;
		case 12:
		yubikey_eeset_common(ptr, EEpos_delay2_12, EElen_delay);
            break;
	}

}

/*********************************/
/*********************************/



int yubikey_eeget_2FAtype (uint8_t *ptr, int slot) {
    
	switch (slot) {
        case 1:
			yubikey_eeget_common(ptr, EEpos_2FAtype1, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 2:
			yubikey_eeget_common(ptr, EEpos_2FAtype2, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 3:
			yubikey_eeget_common(ptr, EEpos_2FAtype3, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 4:
			yubikey_eeget_common(ptr, EEpos_2FAtype4, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 5:
			yubikey_eeget_common(ptr, EEpos_2FAtype5, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 6:
			yubikey_eeget_common(ptr, EEpos_2FAtype6, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 7:
			yubikey_eeget_common(ptr, EEpos_2FAtype7, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 8:
			yubikey_eeget_common(ptr, EEpos_2FAtype8, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 9:
			yubikey_eeget_common(ptr, EEpos_2FAtype9, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 10:
			yubikey_eeget_common(ptr, EEpos_2FAtype10, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 11:
			yubikey_eeget_common(ptr, EEpos_2FAtype11, EElen_2FAtype);
			return EElen_2FAtype;
            break;
		case 12:
			yubikey_eeget_common(ptr, EEpos_2FAtype12, EElen_2FAtype);
			return EElen_2FAtype;
            break;
			
	}

}
void yubikey_eeset_2FAtype (uint8_t *ptr, int slot) {
    
		switch (slot) {

        case 1:
		yubikey_eeset_common(ptr, EEpos_2FAtype1, EElen_2FAtype);
            break;
		case 2:
		yubikey_eeset_common(ptr, EEpos_2FAtype2, EElen_2FAtype);
            break;
		case 3:
		yubikey_eeset_common(ptr, EEpos_2FAtype3, EElen_2FAtype);
            break;
		case 4:
		yubikey_eeset_common(ptr, EEpos_2FAtype4, EElen_2FAtype);
            break;
		case 5:
		yubikey_eeset_common(ptr, EEpos_2FAtype5, EElen_2FAtype);
            break;
		case 6:
		yubikey_eeset_common(ptr, EEpos_2FAtype6, EElen_2FAtype);
            break;
		case 7:
		yubikey_eeset_common(ptr, EEpos_2FAtype7, EElen_2FAtype);
            break;
		case 8:
		yubikey_eeset_common(ptr, EEpos_2FAtype8, EElen_2FAtype);
            break;
		case 9:
		yubikey_eeset_common(ptr, EEpos_2FAtype9, EElen_2FAtype);
            break;
		case 10:
		yubikey_eeset_common(ptr, EEpos_2FAtype10, EElen_2FAtype);
            break;
		case 11:
		yubikey_eeset_common(ptr, EEpos_2FAtype11, EElen_2FAtype);
            break;
		case 12:
		yubikey_eeset_common(ptr, EEpos_2FAtype12, EElen_2FAtype);
            break;
	}

}

/*********************************/

int yubikey_eeget_username (uint8_t *ptr, int slot) {
    
	switch (slot) {
		uint8_t length;
		int size;
        case 1:
			yubikey_eeget_usernamelen1(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username1, size);
			return size;
            break;
		case 2:
			yubikey_eeget_usernamelen2(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username2, size);
			return size;
            break;
		case 3:
			yubikey_eeget_usernamelen3(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username3, size);
			return size;
            break;
		case 4:
			yubikey_eeget_usernamelen4(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username4, size);
			return size;
            break;
		case 5:
			yubikey_eeget_usernamelen5(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username5, size);
			return size;
            break;
		case 6:
			yubikey_eeget_usernamelen6(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username6, size);
			return size;
            break;
		case 7:
			yubikey_eeget_usernamelen7(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username7, size);
			return size;
            break;
		case 8:
			yubikey_eeget_usernamelen8(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username8, size);
			return size;
            break;
		case 9:
			yubikey_eeget_usernamelen9(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username9, size);
			return size;
            break;
		case 10:
			yubikey_eeget_usernamelen10(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username10, size);
			return size;
            break;
		case 11:
			yubikey_eeget_usernamelen11(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username11, size);
			return size;
            break;
		case 12:
			yubikey_eeget_usernamelen12(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			yubikey_eeget_common(ptr, EEpos_username12, size);
			return size;
            break;
			
	}

}
void yubikey_eeset_username (uint8_t *ptr, int size, int slot) {
    
		switch (slot) {
			uint8_t length;
        case 1:
			
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username1, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen1(&length);
            break;
		case 2:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username2, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen2(&length);
            break;
		case 3:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username3, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen3(&length);
            break;
		case 4:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username4, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen4(&length);
            break;
		case 5:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username5, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen5(&length);
            break;
		case 6:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username6, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen6(&length);
            break;
		case 7:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username7, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen7(&length);
            break;
		case 8:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username8, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen8(&length);
            break;
		case 9:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username9, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen9(&length);
            break;
		case 10:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username10, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen10(&length);
            break;
		case 11:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username11, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen11(&length);
            break;
		case 12:
		
			if (size > EElen_username) size = EElen_username;
			yubikey_eeset_common(ptr, EEpos_username12, size);
			length = (uint8_t) size;
			yubikey_eeset_usernamelen11(&length);
            break;
	}

}

/*********************************/

int yubikey_eeget_totpkey (uint8_t *ptr, int slot) {
    
	switch (slot) {
		uint8_t length;
		int size;
        case 1:
			yubikey_eeget_totpkeylen1(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey1, size);
			return size;
            break;
		case 2:
			yubikey_eeget_totpkeylen2(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey2, size);
			return size;
            break;
		case 3:
			yubikey_eeget_totpkeylen3(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey3, size);
			return size;
            break;
		case 4:
			yubikey_eeget_totpkeylen4(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey4, size);
			return size;
            break;
		case 5:
			yubikey_eeget_totpkeylen5(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey5, size);
			return size;
            break;
		case 6:
			yubikey_eeget_totpkeylen6(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey6, size);
			return size;
            break;
		case 7:
			yubikey_eeget_totpkeylen7(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey7, size);
			return size;
            break;
		case 8:
			yubikey_eeget_totpkeylen8(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey8, size);
			return size;
            break;
		case 9:
			yubikey_eeget_totpkeylen9(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey9, size);
			return size;
            break;
		case 10:
			yubikey_eeget_totpkeylen10(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey10, size);
			return size;
            break;
		case 11:
			yubikey_eeget_totpkeylen11(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey11, size);
			return size;
            break;
		case 12:
			yubikey_eeget_totpkeylen12(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeget_common(ptr, EEpos_totpkey12, size);
			return size;
            break;
			
	}

}
void yubikey_eeset_totpkey (uint8_t *ptr, int size, int slot) {
    
		switch (slot) {
			uint8_t length;
        case 1:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey1, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen1(&length);
            break;
		case 2:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey2, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen2(&length);
            break;
		case 3:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey3, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen3(&length);
            break;
		case 4:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey4, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen4(&length);
            break;
		case 5:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey5, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen5(&length);
            break;
		case 6:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey6, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen6(&length);
            break;
		case 7:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey7, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen7(&length);
            break;
		case 8:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey8, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen8(&length);
            break;
		case 9:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey9, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen9(&length);
            break;
		case 10:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey10, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen10(&length);
            break;
		case 11:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey11, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen11(&length);
            break;
		case 12:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			yubikey_eeset_common(ptr, EEpos_totpkey12, size);
			length = (uint8_t) size;
			yubikey_eeset_totpkeylen11(&length);
            break;
	}

}

/*********************************/
