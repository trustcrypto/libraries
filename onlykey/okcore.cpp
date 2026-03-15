/* 
 * Copyright (c) 2015-2022, CryptoTrust LLC.
 * All rights reserved.
 * 
 * Author : Tim Steiner <t@crp.to>
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
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "CryptoTrust" must not be used to
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
 *    the OnlyKey Project (https://crp.to/ok)"
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

/*************************************/
//Standard Libraries 
/*************************************/
#include "sha256.h"
#include "string.h"
#include "EEPROM.h"
#include "SoftTimer.h"
#include "DelayRun.h"
#include "T3MacLib.h"
#include "password.h"
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include "RNG.h"
#include "base64.h"
#include "Curve25519.h"

/*************************************/
//Color LED Libraries 
/*************************************/
#ifdef OK_Color
#include "Adafruit_NeoPixel.h"
#define NEOPIN 10
// #define CORE_PIN10_CONFIG	PORTC_PCR4
#define NUMPIXELS 2
Adafruit_NeoPixel pixels = Adafruit_NeoPixel(NUMPIXELS, NEOPIN, NEO_GRB + NEO_KHZ800);
#endif
uint8_t NEO_Color;
uint8_t NEO_Brightness[1];
int Profile_Offset = 0;
/*************************************/
//Additional Libraries to Load for STD firmware version
//These libraries will only be used if STD_VERSION is defined
/*************************************/
#ifdef STD_VERSION
#include "ctap_errors.h"
#include "yksim.h"
#include "uECC.h"
#include "ykcore.h"
#include "ctaphid.h"
#include "ok_extension.h"
#include "usb_dev.h"
#endif
#ifndef STD_VERSION
// Parts of some libraries required for international travel edition 
// not including full libraries as those libraries include crypto 

#define CTAPHID_BUFFER_SIZE         7609
#define CTAP2_ERR_NO_OPERATION_PENDING      0x2A
#define CTAP2_ERR_USER_ACTION_PENDING       0x23
#define CTAP2_ERR_DATA_READY                0xF6
#define CTAP2_ERR_DATA_WIPE                 0xF7
#define OKSIGN_ERR_USER_ACTION_PENDING 0xF8
#define OKDECRYPT_ERR_USER_ACTION_PENDING  0xF9

uint16_t
yubikey_crc16 (const uint8_t * buf, size_t buf_size)
{
  uint16_t m_crc = 0xffff;

  while (buf_size--)
    {
      int i, j;
      m_crc ^= (uint8_t) * buf++ & 0xFF;
      for (i = 0; i < 8; i++)
	{
	  j = m_crc & 1;
	  m_crc >>= 1;
	  if (j)
	    m_crc ^= 0x8408;
	}
    }

  return m_crc;
}
#endif
/*************************************/
//Global assignments
/*************************************/
uint32_t unixTimeStamp;
int pin_set = 0;
uint8_t profilemode;
bool unlocked = false;
bool initialized = false;
bool configmode = false;
uint8_t TIMEOUT[1] = {30};  //Default 30 Min
uint8_t TYPESPEED[1] = {3}; //Default
uint8_t mod_keys_enabled = 0; //Default
extern uint8_t KeyboardLayout[1];
elapsedMillis idletimer;
uint8_t useinterface = 0;
uint8_t onlykeyhw = OK_HW_COLOR;
/*************************************/
//SoftTimer Tasks
/*************************************/
Task FadeinTask(15, increment);
Task FadeoutTask(10, decrement);
DelayRun Wipedata(5000, wipebuffersafter5sec);  //5 second delay to wipe data after last message
DelayRun Usertimeout(20000, fadeoffafter20sec); //20 second delay to wait for user
DelayRun Endfade(2500, fadeendafter2sec);		//delay to prevent inadvertent button press after challenge PIN
uint8_t fade = 0;
uint8_t isfade = 0;
#define THRESHOLD   .5
/*************************************/
//Yubikey core assignments
/*************************************/
#ifdef STD_VERSION
yubikey_ctx_st ctx;
#endif
/*************************************/
//Password.cpp assignments
/*************************************/
Password password = Password((char *)"not used");
extern uint8_t profilekey[32];
extern uint8_t p1hash[32];
extern uint8_t sdhash[32];
extern uint8_t p2hash[32];
extern uint8_t nonce[32];
extern int integrityctr1;
extern int integrityctr2;
int initcheck;
/*************************************/
//Touch button assignments
/*************************************/
uint8_t BLINKPIN;
uint8_t TOUCHPIN1;
uint8_t TOUCHPIN2;
uint8_t TOUCHPIN3;
uint8_t TOUCHPIN4;
uint8_t TOUCHPIN5;
uint8_t TOUCHPIN6;
uint8_t ANALOGPIN1;
uint8_t ANALOGPIN2;
unsigned int touchread1;
unsigned int touchread2;
unsigned int touchread3; // OnlyKey Go Button #1
unsigned int touchread4;
unsigned int touchread5; // OnlyKey Go Button #2
unsigned int touchread6;
unsigned int touchread1ref;
unsigned int touchread2ref;
unsigned int touchread3ref;
unsigned int touchread4ref;
unsigned int touchread5ref;
unsigned int touchread6ref;
unsigned int sumofall;
int button_selected = 0; 
uint8_t touchoffset;
/*************************************/
//HMCAC SHA1 Assignments
/*************************************/
uint8_t setBuffer[9] = {0};
uint8_t getBuffer[9] = {0, 2, 2, 3, 3, 3, 5, 0, 0};
uint8_t keyboard_buffer[KEYBOARD_BUFFER_SIZE] = {0};
uint8_t sess_counter = 3;
uint8_t may_block = 5;
/*************************************/
//ECC key assignments
/*************************************/
#ifdef STD_VERSION
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE * 2) + 1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
/*************************************/
//RSA key assignments
/*************************************/
extern uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
extern uint8_t type;
/*************************************/
//FIDO2 assignments
/*************************************/
extern uint16_t attestation_key_size;
extern uint8_t attestation_key[33];
#endif
int large_buffer_len;
int large_buffer_offset;
int packet_buffer_offset = 0;
int large_resp_buffer_offset;

uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
// Reuse ctap_buffer as it uses 7K of RAM
uint8_t *large_resp_buffer = ctap_buffer + CTAPHID_BUFFER_SIZE - LARGE_RESP_BUFFER_SIZE;				// Last 1024 bytes used to store temp data
uint8_t *large_buffer = ctap_buffer + CTAPHID_BUFFER_SIZE - LARGE_RESP_BUFFER_SIZE - LARGE_BUFFER_SIZE; // Next 1024 bytes used to store temp data
uint8_t packet_buffer[PACKET_BUFFER_SIZE];
uint8_t packet_buffer_details[5];
uint8_t recv_buffer[64];
uint8_t resp_buffer[64];
int outputmode = 0;
uint8_t pending_operation;
/*************************************/
//Crypto Challenge assignments
/*************************************/
uint8_t Challenge_button1 = 0;
uint8_t Challenge_button2 = 0;
uint8_t Challenge_button3 = 0;
uint8_t CRYPTO_AUTH = 0;
uint8_t derived_key_challenge_mode = 0;
uint8_t stored_key_challenge_mode = 0;
/*************************************/
//RNG Assignments
/*************************************/
size_t length = 48; // First block should wait for the pool to fill up.
/*************************************/
uint8_t Duo_config[2];

// Main loop to receive data
void recvmsg(int n)
{
	//Debug stored response
	//Serial.println("Stored Response:");
    //byteprint(large_resp_buffer, 64);

	// FIDO2 operation processing
	if (profilemode != NONENCRYPTEDPROFILE)
	{
#ifdef STD_VERSION
		if (pending_operation==CTAP2_ERR_OPERATION_PENDING) {
			return;
		}
#endif
	}

	// Debug for get and setBuffer
	/* 
	if (setBuffer[7] >= 0x80)
	{
		Serial.println("setbuffer = ");
		byteprint(setBuffer, 9);
		Serial.println("getbuffer = ");
		byteprint(getBuffer, 9);
		byteprint(keyboard_buffer, KEYBOARD_BUFFER_SIZE);
	}
	*/

	// This is for staging large response via keyboard, not currently used
	//if (store_keyboard_response()) return;

	if (!n)
	{
		n = RawHID.recv(recv_buffer, 0); // 0 timeout = do not wait
		if (outputmode != RAW_USB && n) changeoutputmode(RAW_USB); //USB
	}

	//Integrity Check
	if (integrityctr1 != integrityctr2)
	{
		unlocked = false;
		CPU_RESTART();
		return;
	}

	if (n > 0)
	{
#ifdef DEBUG
		Serial.print(F("\n\nReceived packet"));
		byteprint(recv_buffer, 64);
#endif

		if (configmode == true && recv_buffer[4] != OKCONNECT && recv_buffer[4] != OKWIPESLOT && recv_buffer[4] != OKSETSLOT && recv_buffer[4] != OKSETPRIV && recv_buffer[4] != OKRESTORE && recv_buffer[4] != OKFWUPDATE && recv_buffer[4] != OKWIPEPRIV && recv_buffer[4] != OKGETLABELS && recv_buffer[4] != OKPIN && recv_buffer[4] != OKPINSEC && recv_buffer[4] != OKPINSD)
		{
#ifdef DEBUG
			Serial.println("ERROR NOT SUPPORTED IN CONFIG MODE");
#endif
			return;
		}

		switch (recv_buffer[4])
		{
		case OKPIN:
			if (profilemode != NONENCRYPTEDPROFILE)
			{
				if (!initcheck || configmode == true) {
					if (recv_buffer[5]==0xff) okcore_quick_setup(SETUP_MANUAL); // Received request to set PINs/passphrase
					else set_primary_pin(recv_buffer, 0); // Received request to enter primary PIN on OnlyKey (not DUO)
				} 
			}
			else
			{
				if (!initcheck || configmode == true) set_secondary_pin(recv_buffer, 0);
			}
			return;
		case OKPINSD:
			if (!initcheck || configmode == true) set_sd_pin(recv_buffer, 0);
			return;
		case OKPINSEC:
			if (!initcheck || configmode == true) set_secondary_pin(recv_buffer, 0);
			return;
		case OKCONNECT:
			set_time(recv_buffer);
			return;
		case OKGETLABELS:
			if (initialized == false && unlocked == true)
			{
				hidprint("Error OnlyKey must be initialized first");
				return;
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2)
			{
				if (recv_buffer[5] == 'k')
					get_key_labels(2);
				else
					get_slot_labels(2);
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKSETSLOT:
			if (initialized == false && unlocked == true && integrityctr1 == integrityctr2)
			{
				if (recv_buffer[6] == 12 || recv_buffer[6] == 20)
				{ //You can set wipemode and backupkeymode any time but they are set once settings
					if (recv_buffer[0] != 0xBA)
						set_slot(recv_buffer);
				}
				else
				{
					hidprint("Error OnlyKey must be initialized first");
				}
				return;
			}
			else if ((initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2) || (!initcheck && unlocked == true && initialized == true && integrityctr1 == integrityctr2))
			{
				if (recv_buffer[0] != 0xBA)
				{
					if (profilemode != NONENCRYPTEDPROFILE) 
					{
						#ifdef STD_VERSION
						if (mod_keys_enabled && configmode == false) {
						
							hidprint("Error not in config mode");
							return;
						}
						#endif
					}
					set_slot(recv_buffer);
				}
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKWIPESLOT:
			if (initialized == false && unlocked == true)
			{
				hidprint("Error OnlyKey must be initialized first");
				return;
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2)
			{
				wipe_slot(recv_buffer);
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKSETPRIV:
			if ((initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && configmode == true) || (initialized == true && unlocked == true && !initcheck)) //Only permit loading keys on first use and while in config mode
			{
				if (profilemode != NONENCRYPTEDPROFILE)
				{
					#ifdef STD_VERSION
					if (recv_buffer[0] != 0xBA)
						set_private(recv_buffer);
					#endif
				}
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && configmode == false)
			{
				hidprint("Error not in config mode");
			}
			else if (recv_buffer[6] > 0x80 && onlykeyhw == OK_HW_DUO && initialized == false) { // App Setup of backup key, no pin
				memcpy(large_buffer, recv_buffer, 64);
				set_built_in_pin();
				set_private(large_buffer);
				// Lock backup key since there is no PIN required
				okeeprom_eeset_backupkeymode((uint8_t*)1);
				memset(large_buffer, 0, 64);
				initcheck = false;
			}
			else 
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKWIPEPRIV:
			if (initialized == false && unlocked == true)
			{
				hidprint("No PIN set, You must set a PIN first");
				return;
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && configmode == true)
			{
				if (profilemode != NONENCRYPTEDPROFILE)
				{
					#ifdef STD_VERSION
					wipe_private(recv_buffer, true);
					#endif
				}
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKSIGN:
			if (initialized == false && unlocked == true)
			{
				hidprint("No PIN set, You must set a PIN first");
				return;
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && !CRYPTO_AUTH)
			{
				if (profilemode != NONENCRYPTEDPROFILE)
				{
					#ifdef STD_VERSION
					fadeon(213); //Purple
					okcrypto_sign(recv_buffer);
					#endif
				}
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKDECRYPT:
			if (initialized == false && unlocked == true)
			{
				hidprint("No PIN set, You must set a PIN first");
				return;
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && !CRYPTO_AUTH)
			{
				if (profilemode != NONENCRYPTEDPROFILE)
				{
					#ifdef STD_VERSION
					fadeon(128); //Turquoise
					okcrypto_decrypt(recv_buffer);
					#endif
				}
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKGETPUBKEY:
			if (initialized == false && unlocked == true)
			{
				hidprint("No PIN set, You must set a PIN first");
				return;
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2)
			{
				if (profilemode != NONENCRYPTEDPROFILE)
				{
					#ifdef STD_VERSION
					okcrypto_getpubkey(recv_buffer);
					#endif
				}
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKRESTORE:
			if (initialized == false && unlocked == true)
			{
				hidprint("No PIN set, You must set a PIN first");
				return;
			}
			else if ((initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && configmode == true) || (initialized == true && unlocked == true && !initcheck && integrityctr1 == integrityctr2)) //Only permit loading backup on first use and while in config mode
			{
				if (profilemode != NONENCRYPTEDPROFILE)
				{
					#ifdef STD_VERSION
					RESTORE(recv_buffer);
					#endif
				}
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && configmode == false)
			{
				hidprint("Error not in config mode");
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		case OKFWUPDATE:
			if ((initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && configmode == true) || (!initcheck && integrityctr1 == integrityctr2)) //Only permit loading firmware on first use and while in config mode
			{
				hidprint("SUCCESSFULL FW LOAD REQUEST, REBOOTING...");
				eeprom_write_byte(0x00, 1);					 //Go to bootloader
				eeprom_write_byte((unsigned char *)0x01, 1); //Firmware ready to load
				delay(100);
				CPU_RESTART();
			}
			else if (initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2 && configmode == false)
			{
				hidprint("Error not in config mode");
			}
			else
			{
				hidprint("Error device locked");
				return;
			}
			return;
		default:
			if (profilemode != NONENCRYPTEDPROFILE && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2)
			{
				#ifdef STD_VERSION
				extern uint8_t onlykeyhw;
				if (onlykeyhw == OK_HW_DUO && initialized == false) { 
					// User attempting to use unconfigured OnlyKey for FIDO without first setting up with app
					// Provision OnlyKey with no device PIN and lock backup
					ctaphid_handle_packet(recv_buffer);
					set_built_in_pin();
					// Lock backup key since there is no PIN required
					okeeprom_eeset_backupkeymode((uint8_t*)1);
				}
				if (initialized == true && unlocked == true) {
					if (!useinterface) {
						// Android bug, Android selects random interface for FIDO if there are 
						// multiple interfaces, doesn't even check if the interface has usage page 0xf1d0
						delay(100);
						useinterface=n;
						n = RawHID.recv(recv_buffer, 0);
						if (n) useinterface=n;
						recv_fido_msg(recv_buffer);	
					} else if (useinterface == n) {
					recv_fido_msg(recv_buffer);	
					} else {
						// Fix for Android bug causes some OSes to select wrong interface if a user tries to do FIDO2 while OnlyKey is locked
						useinterface = n;
						recv_fido_msg(recv_buffer);	
						useinterface = 0;
					}
				}
				#endif
			}     
			return;
		}
	}
	else
	{
		if (profilemode != NONENCRYPTEDPROFILE && initialized == true && unlocked == true && FTFL_FSEC == 0x44 && integrityctr1 == integrityctr2)
		{
			#ifdef STD_VERSION
			fido_msg_timeout();
			#endif
		}
	}
}

uint32_t getCounter()
{
	unsigned int eeAddress = EEpos_U2Fcounter; //EEPROM address to start reading from
	uint32_t counter;
	EEPROM.get(eeAddress, counter);
	return counter;
}

void setCounter(uint32_t counter)
{
	unsigned int eeAddress = EEpos_U2Fcounter; //EEPROM address to start reading from
	EEPROM.put(eeAddress, counter);
}

void okcore_quick_setup(uint8_t step)
{
#ifdef DEBUG
	Serial.println("Keyboard-config OnlyKey");
#endif
	uint8_t buffer[64] = {0};
	KeyboardLayout[0] = 0;
	update_keyboard_layout();
	if (step == 0)
	{ //Manual/Auto
		keytype("*** WELCOME TO ONLYKEY QUICK SETUP ***");
		keytype("RUN THIS SETUP FROM A TRUSTED COMPUTER AND CAREFULLY WRITE DOWN");
		keytype("PINs AND PASSPHRASE. STORE IN A SECURE LOCATION SUCH AS A SAFE");
		keytype("WHEN FINISHED DELETE THIS TEXT");
		Keyboard.println();
		if (onlykeyhw!=OK_HW_DUO) {
			keytype("Three different PIN codes will be set up on your OnlyKey");
			keytype("The first PIN unlocks your primary profile (i.e Personal Accounts)"); 
			keytype("The second PIN unlocks an additional profile (i.e. Work Accounts)");
			keytype("The third PIN is your self-destruct PIN use this to wipe/factory default device");
		} 
		keytype("To choose the PINs yourself press 1 on OnlyKey, for random PINs press 2");
		keytype("You have 20 seconds starting now...");
		pin_set = 10;
		fadeoffafter20();
		//okcore_quick_setup(KEYBOARD_AUTO_PIN_SET);
		return;
	}
	if (step == KEYBOARD_MANUAL_PIN_SET)
	{ //Manual Set PIN
		pin_set = 0;
		keytype("You will now enter a PIN on the OnlyKey 6 button keypad");
		keytype("Choose a PIN 7-10 digits long");	

		set_primary_pin(NULL, 1);
		return;
	}
	else if (step == KEYBOARD_AUTO_PIN_SET)
	{ //Auto Set PIN

		keytype("Your OnlyKey will now be configured automatically with random PINs/Passphrase");
		pin_set = 3;

		generate_random_pin(buffer);
		//memset(buffer, '1', 7);
		set_primary_pin(buffer, KEYBOARD_AUTO_PIN_SET);

		Keyboard.println();
		keytype("YOUR ONLYKEY PIN IS:");
		keytype((char *)buffer);
		if (onlykeyhw!=OK_HW_DUO) {
			pin_set = 9;
			generate_random_pin(buffer);

			//memset(buffer, '2', 7);

			set_secondary_pin(buffer, KEYBOARD_AUTO_PIN_SET);

			keytype("YOUR ONLYKEY SECOND PROFILE PIN IS:");
			keytype((char *)buffer);
		}
		pin_set = 6;
		generate_random_pin(buffer);

		//memset(buffer, '3', 7);

		set_sd_pin(buffer, KEYBOARD_AUTO_PIN_SET);

		keytype("YOUR ONLYKEY SELF-DESTRUCT PIN IS:");
		keytype((char *)buffer);

	} else if (step == KEYBOARD_ONLYKEY_DUO_BACKUP) {
		keytype("*** WELCOME TO ONLYKEY DUO QUICK SETUP ***");
		keytype("RUN THIS SETUP FROM A TRUSTED COMPUTER AND CAREFULLY WRITE DOWN");
		keytype("YOUR BACKUP PASSPHRASE. STORE IN A SECURE LOCATION SUCH AS A SAFE");
		keytype("WHEN FINISHED DELETE THIS TEXT");
		Keyboard.println();
	} else if (step == KEYBOARD_ONLYKEY_DUO_NO_BACKUP) {
		set_built_in_pin();
	} else if (step == SETUP_MANUAL) {
		changeoutputmode(RAW_USB); //USB
		memcpy(buffer, recv_buffer, 64);
		if (buffer[6]>='0') { // 16 max length
			pin_set = 3;
			//Serial.println("SETTING PRIMARY PIN");
			//byteprint(buffer+6, 16);
			set_primary_pin(buffer+6, SETUP_MANUAL);
		}
		if (onlykeyhw!=OK_HW_DUO) {
			if (buffer[22]>='0') { // 16 max length
				pin_set = 9;
				//Serial.println("SETTING SEC PIN");
				//byteprint(buffer+22, 16);
				set_secondary_pin(buffer+22, SETUP_MANUAL);
			}
		}
		if (buffer[38]>='0') { // 16 max length
			//Serial.println("SETTING SD PIN");
			//byteprint(buffer+38, 16);
			pin_set = 6;
			set_sd_pin(buffer+38, SETUP_MANUAL);
		}
		return;
	} 

	// Set randomly generated backup passphrase
	buffer[5] = RESERVED_KEY_DEFAULT_BACKUP;
	buffer[6] = 0xA1;
	SHA256_CTX hash;
	sha256_init(&hash);

	if (step != KEYBOARD_ONLYKEY_DUO_NO_BACKUP) {
		keytype("YOUR ONLYKEY BACKUP PASSPHRASE IS:");
		generate_random_passphrase(buffer + 7);
		keytype((char *)(buffer + 7));
		//memset(buffer, 'a', 32);
		Keyboard.println();
		sha256_update(&hash, buffer + 7, 27);
		sha256_final(&hash, buffer + 7);
		set_private(buffer); //set backup ECC key
		if (onlykeyhw!=OK_HW_DUO) {
			keytype("To start using OnlyKey enter your primary or secondary PIN on the OnlyKey 6 button keypad");
		}
		keytype("OnlyKey is ready for use as a security key (FIDO2/U2F) and for challenge-response");
		keytype("For additional features such as password management install the OnlyKey desktop app");
		keytype("https://onlykey.io/app ");
		keytype("*** SETUP COMPLETE, DELETE THIS TEXT ***");
	} 

	if (step == KEYBOARD_ONLYKEY_DUO_BACKUP || step == KEYBOARD_ONLYKEY_DUO_NO_BACKUP) {
		// If KEYBOARD_ONLYKEY_DUO_BACKUP this disables changing backup key
		// If KEYBOARD_ONLYKEY_DUO_NO_BACKUP this disables backup feature	
		okeeprom_eeset_backupkeymode((uint8_t*)1);
	}

	CPU_RESTART();
}

void generate_random_pin(uint8_t *buffer)
{
	RNG2(buffer, 7);
	for (int i = 0; i < 7; i++)
	{
		buffer[i] = ((buffer[i] % 6) + 1) + '0';
	}
	buffer[7] = 0;
}

// Generate a random 27 char alpha-numeric passphrase 
// passphrase strength stronger than AES-128 key
// 256^16 = ~3E+38, 36^27 = ~1E+42
void generate_random_passphrase(uint8_t *buffer)
{
	RNG2(buffer, 27);
	byteprint(buffer, 27);
	for (int i = 0; i < 27; i++)
	{
		buffer[i] = ((buffer[i] % 36) + 1) + 96; //Alpha
		if (buffer[i] > 122) buffer[i] = buffer[i] - 75; //Numeric
	} 
	buffer[27] = 0;
}

void set_built_in_pin() {
	pin_set = 3;
	// 19-35 bytes of chip ID used instead of primary PIN
	set_primary_pin((uint8_t*)recv_buffer, KEYBOARD_AUTO_PIN_SET);
	okeeprom_eeset_timeout(0); // No timeout as there is no PIN required
	initcheck = okcore_flashget_noncehash ((uint8_t*)nonce, 32); 
	okcore_flashget_pinhashpublic ((uint8_t*)p1hash, 32); //store PIN hash
    initialized = true;
	if (password.profile1hashevaluate()) {
		unlocked = true;
		#ifdef STD_VERSION
    	U2Finit();
		#endif
	}
}

void set_primary_pin(uint8_t *buffer, uint8_t keyboard_mode)
{
#ifdef DEBUG
	Serial.println("OKPIN MESSAGE RECEIVED");
#endif

	if (pin_set > 3)
		pin_set = 0;

	switch (pin_set)
	{
	case 0:
		password.reset();
#ifdef DEBUG
		Serial.println("Enter PIN");
#endif
		pin_set = 1;
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
		{
			keytype("You have 20 seconds to enter primary profile PIN, starting now");
			fadeoffafter20();
		}
		else
			hidprint("OnlyKey is ready, enter your PIN");

		return;
	case 1:
		pin_set = 2;
		if (strlen(password.guess) > 6 && strlen(password.guess) < 11)
		{
#ifdef DEBUG
			Serial.println("Storing PIN");
#endif
			if (!keyboard_mode)
				hidprint("Successful PIN entry");
			else
				keytype("Successful PIN entry");
			static char passguess[10];
			for (unsigned int i = 0; i <= strlen(password.guess); i++)
			{
				passguess[i] = password.guess[i];
			}
			password.set(passguess);
			password.reset();
		}
		else
		{
#ifdef DEBUG
			Serial.println("Error PIN is not between 7 - 10 digits");
#endif
			if (!keyboard_mode)
				hidprint("Error PIN is not between 7 - 10 digits");
			else
				keytype("Error PIN is not between 7 - 10 digits");
			password.reset();
			pin_set = 0;
		}
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
			set_primary_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
		return;
	case 2:
#ifdef DEBUG
		Serial.println("Confirm PIN");
#endif
		pin_set = 3;
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
		{
			keytype("You have 20 seconds to re-enter PIN, starting now");
			fadeoffafter20();
		}
		else
			hidprint("OnlyKey is ready, re-enter your PIN to confirm");

		return;
	case 3:
		pin_set = 0;
		if ((strlen(password.guess) >= 7 && strlen(password.guess) < 11) || keyboard_mode == KEYBOARD_AUTO_PIN_SET || keyboard_mode == SETUP_MANUAL)
		{

			if ((password.evaluate()) || keyboard_mode == KEYBOARD_AUTO_PIN_SET || keyboard_mode == SETUP_MANUAL)
			{
#ifdef DEBUG
				Serial.println("Both PINs Match");
#endif
				//hidprint("Both PINs Match");
				uint8_t temp[32];
				uint8_t nonce2[32];

				RNG2((uint8_t*)nonce2, 32); //Fill temp with random data
				okeeprom_eeset_nonce2((uint8_t*)nonce2);

				//Hash PIN and Nonce
				SHA256_CTX pinhash;
				sha256_init(&pinhash);
				if (keyboard_mode == KEYBOARD_AUTO_PIN_SET) {
					if (onlykeyhw==OK_HW_DUO) memcpy(password.guess, (ID+18), 16);
					else memcpy(password.guess, buffer, 7);
				} else if (keyboard_mode == SETUP_MANUAL) {
					memcpy(password.guess, buffer, 16);
				}
				sha256_update(&pinhash, (uint8_t *)password.guess, strlen(password.guess)); //Add new PIN to hash
				// Set new nonce if none is set
				if (!initcheck) {				
					RNG2((uint8_t*)nonce, 32); //Fill temp with random data
					okcore_flashset_noncehash((uint8_t*)nonce); //Store in flash
					#ifdef DEBUG
					Serial.println("Generating NONCE");
					byteprint(nonce, 32);
					#endif
				}
				sha256_update(&pinhash, nonce, 32); //Add nonce to hash
				sha256_final(&pinhash, temp); //Create hash and store in temp

				okcore_flashset_pinhashpublic((uint8_t*)temp);
				
#ifdef DEBUG
				Serial.println();
				Serial.println("Successfully set PIN");
#endif
				if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
				{
					keytype("Successfully set PIN");
					if (onlykeyhw!=OK_HW_DUO) {
						set_secondary_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
					} else {
						set_sd_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
					}
				}
				else
					hidprint("Successfully set PIN");
			}
			else
			{
#ifdef DEBUG
				Serial.println("Error PINs Don't Match");
#endif
				if (!keyboard_mode)
					hidprint("Error PINs Don't Match");
				else
					keytype("Error PINs Don't Match");
				if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
					set_primary_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
			}
		}
		else
		{
#ifdef DEBUG
			Serial.println("Error PIN is not between 7 - 10 digits");
#endif
			if (!keyboard_mode)
				hidprint("Error PIN is not between 7 - 10 digits");
			else
				keytype("Error PIN is not between 7 - 10 digits");
			if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
				set_primary_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
		}
		password.reset();
		blink(3);
		return;
	}
}

void set_sd_pin(uint8_t *buffer, uint8_t keyboard_mode)
{
#ifdef DEBUG
	Serial.println("OKPINSDMESSAGE RECEIVED");
#endif

	if (pin_set < 4 || pin_set > 6)
		pin_set = 0;

	switch (pin_set)
	{
	case 0:
		password.reset();
#ifdef DEBUG
		Serial.println("Enter PIN");
#endif
		pin_set = 4;
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
		{
			keytype("You have 20 seconds to enter self-destruct PIN, starting now");
			fadeoffafter20();
		}
		else
			hidprint("OnlyKey is ready, enter your self-destruct PIN");

		return;
	case 4:
		pin_set = 5;
		if (strlen(password.guess) >= 7 && strlen(password.guess) < 11)
		{
#ifdef DEBUG
			Serial.println("Storing PIN");
#endif
			if (!keyboard_mode)
				hidprint("Successful PIN entry");
			else
				keytype("Successful PIN entry");
			static char passguess[10];
			for (unsigned int i = 0; i <= strlen(password.guess); i++)
			{
				passguess[i] = password.guess[i];
			}
			password.set(passguess);
			password.reset();
		}
		else
		{
#ifdef DEBUG
			Serial.println("Error PIN is not between 7 - 10 digits");
#endif
			if (!keyboard_mode)
				hidprint("Error PIN is not between 7 - 10 digits");
			else
				keytype("Error PIN is not between 7 - 10 digits");
			password.reset();
			pin_set = 0;
		}
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
			set_sd_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
		return;
	case 5:
#ifdef DEBUG
		Serial.println("Confirm PIN");
#endif
		pin_set = 6;
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
		{
			keytype("You have 20 seconds to re-enter PIN, starting now");
			fadeoffafter20();
		}
		else
			hidprint("OnlyKey is ready, re-enter your PIN to confirm");

		return;
	case 6:
		pin_set = 0;
		if ((strlen(password.guess) >= 7 && strlen(password.guess) < 11) || keyboard_mode == KEYBOARD_AUTO_PIN_SET || keyboard_mode == SETUP_MANUAL)
		{
			if ((password.evaluate()) || keyboard_mode == KEYBOARD_AUTO_PIN_SET || keyboard_mode == SETUP_MANUAL)
			{
#ifdef DEBUG
				Serial.println("Both PINs Match");
#endif
				//hidprint("Both PINs Match");
				uint8_t temp[32];

				//Copy characters to byte array
				if (keyboard_mode == KEYBOARD_AUTO_PIN_SET) memcpy(password.guess, buffer, 7);
				else if (keyboard_mode == SETUP_MANUAL) memcpy(password.guess, buffer, 16);
				for (unsigned int i = 0; i <= strlen(password.guess); i++)
				{
					temp[i] = (uint8_t)password.guess[i];
				}
				SHA256_CTX pinhash;
				sha256_init(&pinhash);
				sha256_update(&pinhash, temp, strlen(password.guess)); //Add new PIN to hash
#ifdef DEBUG
				Serial.println("Getting NONCE");
#endif

				sha256_update(&pinhash, nonce, 32); //Add nonce to hash
				sha256_final(&pinhash, temp);	  //Create hash and store in temp
#ifdef DEBUG
				Serial.println("Hashing SDPIN and storing to Flash");
#endif
				okcore_flashset_selfdestructhash((uint8_t*)temp);
				if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
				{
					keytype("Successfully set PIN");
					okcore_quick_setup(7); //Done setting PINs
				}
				else
					hidprint("Successfully set PIN");
			}
			else
			{
#ifdef DEBUG
				Serial.println("Error PINs Don't Match");
#endif
				if (!keyboard_mode)
					hidprint("Error PINs Don't Match");
				else
					keytype("Error PINs Don't Match");
				if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
					set_sd_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
			}
		}
		else
		{
#ifdef DEBUG
			Serial.println("Error PIN is not between 7 - 10 digits");
#endif
			if (!keyboard_mode)
				hidprint("Error PIN is not between 7 - 10 digits");
			else
				keytype("Error PIN is not between 7 - 10 digits");
			if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
				set_sd_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
		}
		password.reset();
		blink(3);
		return;
	}
}

void set_secondary_pin(uint8_t *buffer, uint8_t keyboard_mode)
{
#ifdef DEBUG
	Serial.println("OKPINSEC MESSAGE RECEIVED");
#endif
	if (pin_set < 7)
		pin_set = 0;

	switch (pin_set)
	{
	case 0:
		password.reset();
#ifdef DEBUG
		Serial.println("Enter PIN");
#endif
		pin_set = 7;
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
		{
			keytype("You have 20 seconds to enter second profile PIN, starting now");
			fadeoffafter20();
		}
		else
			hidprint("OnlyKey is ready, enter your PIN");
		return;
	case 7:
		pin_set = 8;
		if (strlen(password.guess) >= 7 && strlen(password.guess) < 11)
		{
#ifdef DEBUG
			Serial.println("Storing PIN");
#endif
			if (!keyboard_mode)
				hidprint("Successful PIN entry");
			else
				keytype("Successful PIN entry");
			static char passguess[10];
			for (unsigned int i = 0; i <= strlen(password.guess); i++)
			{
				passguess[i] = password.guess[i];
			}
			password.set(passguess);
			password.reset();
		}
		else
		{
#ifdef DEBUG
			Serial.println("Error PIN is not between 7 - 10 digits");
#endif
			if (!keyboard_mode)
				hidprint("Error PIN is not between 7 - 10 digits");
			else
				keytype("Error PIN is not between 7 - 10 digits");
			password.reset();
			pin_set = 0;
		}
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
			set_secondary_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
		return;
	case 8:
#ifdef DEBUG
		Serial.println("Confirm PIN");
#endif
		pin_set = 9;
		if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
		{
			keytype("You have 20 seconds to re-enter PIN, starting now");
			fadeoffafter20();
		}
		else
			hidprint("OnlyKey is ready, re-enter your PIN to confirm");

		return;
	case 9:
		pin_set = 0;
		if ((strlen(password.guess) >= 7 && strlen(password.guess) < 11) || keyboard_mode == KEYBOARD_AUTO_PIN_SET || keyboard_mode == SETUP_MANUAL)
		{
			if ((password.evaluate()) || keyboard_mode == KEYBOARD_AUTO_PIN_SET || keyboard_mode == SETUP_MANUAL)
			{
#ifdef DEBUG
				Serial.println("Both PINs Match");
#endif
				//hidprint("Both PINs Match");

				uint8_t temp[32];
				uint8_t nonce2[32];
				uint8_t p2mode;

				okeeprom_eeget_2ndprofilemode(&p2mode);
				if (p2mode!=NONENCRYPTEDPROFILE) {
					RNG2((uint8_t*)nonce2, 32); //Fill temp with random data
					okeeprom_eeset_nonce2((uint8_t*)nonce2);
				}

				//Hash PIN and Nonce
				SHA256_CTX pinhash;
				sha256_init(&pinhash);
				if (keyboard_mode == KEYBOARD_AUTO_PIN_SET) {
					memcpy(password.guess, buffer, 7);
				} else if (keyboard_mode == SETUP_MANUAL) {
					memcpy(password.guess, buffer, 16);
				}
				sha256_update(&pinhash, (uint8_t *)password.guess, strlen(password.guess)); //Add new PIN to hash
				if (!okcore_flashget_noncehash ((uint8_t*)nonce, 32)) {
					RNG2((uint8_t*)nonce, 32); //Fill temp with random data
					okcore_flashset_noncehash((uint8_t*)nonce); //Store in flash
					#ifdef DEBUG
					Serial.println("Generating NONCE");
					byteprint(nonce, 32);
					#endif
				}

				sha256_update(&pinhash, nonce, 32); //Add nonce to hash
				sha256_final(&pinhash, temp); //Create hash and store in temp

				okcore_flashset_2ndpinhashpublic((uint8_t*)temp);
#ifdef DEBUG
				Serial.println();
				Serial.println("Successfully set PIN");
#endif
				if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
				{
					keytype("Successfully set PIN");
					set_sd_pin(NULL, 1);
				}
				else
					hidprint("Successfully set PIN");
			}
			else
			{
#ifdef DEBUG
				Serial.println("Error PINs Don't Match");
#endif
				if (!keyboard_mode)
					hidprint("Error PINs Don't Match");
				else
					keytype("Error PINs Don't Match");
				if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
					set_secondary_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
			}
		}
		else
		{
#ifdef DEBUG
			Serial.println("Error PIN is not between 7 - 10 digits");
#endif
			if (!keyboard_mode)
				hidprint("Error PIN is not between 7 - 10 digits");
			else
				keytype("Error PIN is not between 7 - 10 digits");
			if (keyboard_mode == KEYBOARD_MANUAL_PIN_SET)
				set_secondary_pin(NULL, KEYBOARD_MANUAL_PIN_SET);
		}
		password.reset();
		blink(3);
		return;
	}
}

void set_time(uint8_t *buffer)
{
#ifdef DEBUG
	Serial.println();
	Serial.println("OKCONNECT MESSAGE RECEIVED");
#endif
	if ((initialized == false && unlocked == true) || (initialized == true && unlocked == true && !initcheck))
	{
#ifdef DEBUG
		Serial.print("UNINITIALIZED");
#endif
		hidprint(HW_MODEL(UNINITIALIZED));
		return;
	}
	else if (initialized == true && unlocked == true && configmode == true)
	{
#ifdef DEBUG
		Serial.print("CONFIG_MODE");
#endif
		hidprint(HW_MODEL(UNLOCKED));
	}
	else if (initialized == true && unlocked == true)
	{
#ifdef DEBUG
		Serial.print("UNLOCKED");
#endif
		hidprint(HW_MODEL(UNLOCKED));
		if (timeStatus() == timeNotSet)
		{
			int i, j;
			for (i = 0, j = 3; i < 4; i++, j--)
			{
				unixTimeStamp |= ((uint32_t)buffer[j + 5] << (i * 8));

#ifdef DEBUG
				Serial.println(buffer[j + 5], HEX);
#endif
			}
			if (idletimer < 3000)
			{
#ifdef DEBUG
				Serial.print("Adding time offset");
				Serial.println(millis());
#endif
				unixTimeStamp = unixTimeStamp + ((millis()) / 1000); //Device was just unlocked add difference in time since app sent settime
			}
			time_t t2 = unixTimeStamp;
#ifdef DEBUG
			Serial.print("Received Unix Epoch Time: ");
			Serial.println(unixTimeStamp, HEX);
#endif
			setTime(t2);
			uint32_t counter1 = getCounter();
			if (unixTimeStamp>0x5D2BA76E && ((unixTimeStamp-0x5D2BA76E)/5)>counter1) setCounter((unixTimeStamp-0x5D2BA76E)/5); 
#ifdef DEBUG
			Serial.println("Current Time Set to: ");
#endif
			digitalClockDisplay();
		}
		else
		{
#ifdef DEBUG
			Serial.println("Time Already Set");
#endif
		}
	}	
	return;
}

uint8_t get_key_labels(uint8_t output)
{
	if (profilemode == NONENCRYPTEDPROFILE)
		return 0;
#ifdef STD_VERSION
#ifdef DEBUG
	Serial.println();
	Serial.println("OKGETKEYLABELS MESSAGE RECEIVED");
#endif
	uint8_t label[EElen_label + 7] = {0};

	for (uint8_t i = 25; i <= 28; i++)
	{ //4 labels for RSA keys
		okcore_flashget_label((uint8_t *)label+2, i);
		label[0] = (uint8_t)i; //1-4
		label[1] = (uint8_t)0x7C;
		if (output == 1)
		{ //Output via keyboard
			memmove(label+5, label+2, EElen_label);
			label[0] = 'R';
			label[1] = 'S';
			label[2] = 'A';
			label[3] = ((i - 24) + '0');
			label[4] = 0x20;
			label[21] = 0;
			keytype((char *)label);
		}
		else if (output == 2)
		{ //Output via outputmode
			send_transport_response(label, 21, false, false);
			delay(20);
		}
		else if (output == 3)
		{ 	//Output slot number of matching label
			// For future use, store origin hash or keyid in label
			if (memcmp((uint8_t *)label+5, recv_buffer + 6, 16) == 0)
				return i - 24;
		}
	}
	for (uint8_t i = 29; i <= 44; i++)
	{ //30 labels for ECC keys
		okcore_flashget_label((uint8_t *)label+2, i);
		label[0] = (uint8_t)i; //101-132
		label[1] = (uint8_t)0x7C;
		if (output == 3)
		{ 	//Output slot number of matching label
			// For future use, store origin hash or keyid in label
			if (memcmp((uint8_t *)label+2, recv_buffer + 6, 16) == 0)
				return i - 24;
		}
		else if (output == 1)
		{ //Output via keyboard
			memmove(label+6, label+2, EElen_label);
			label[0] = 'E';
			label[1] = 'C';
			label[2] = 'C';
			if ((i - 28) < 10)
			{
				label[3] = ('0');
				label[4] = ((i - 28) + '0');
				label[5] = 0x20;
				label[22] = 0;
			}
			else if ((i - 28) < 17)
			{
				label[3] = ('1');
				label[4] = ((i - 28 - 10) + '0');
				label[5] = 0x20;
				label[22] = 0;
			}
			keytype((char *)label);
		}
		else if (output == 2)
		{ //Output via outputmode
			send_transport_response(label, 22, false, false);
			delay(20);
		}
	}
#endif
	return 0;
}

void get_slot_labels(uint8_t output)
{
#ifdef DEBUG
	Serial.println();
	Serial.println("OKGETSLOTLABELS MESSAGE RECEIVED");
#endif
	uint8_t label[EElen_label + 4 + 7] = {0};
	int offset = 0;
	int maxslots;
	if (profilemode) offset = 12;
	if (onlykeyhw==OK_HW_DUO) {
		maxslots = 24;
	} else {
		maxslots = 12;
	}
	for (int i = 1; i <= maxslots; i++)
	{
		okcore_flashget_label((uint8_t *)label+2, (offset + i));
		if (i <= 9) label[0] = i;
		else label[0] = i + 6;
		label[1] = (uint8_t)0x7C;
		if (output == 1)
		{
			if (onlykeyhw==OK_HW_DUO) {
				if (i == 1) keytype("GREEN");
				if (i == 7) keytype("BLUE");
				if (i == 13) keytype("YELLOW");
				if (i == 19) keytype("PURPLE");
				if (i <= 3)
				{
					label[0] = (i + '0');
					label[1] = 'a';
				}
				else if (i <= 6)
				{
					label[0] = (i - 3 + '0');
					label[1] = 'b';
				} else if (i <= 9)
				{
					label[0] = (i - 6 + '0');
					label[1] = 'a';
				} else if (i <= 12)
				{
					label[0] = (i - 9 + '0');
					label[1] = 'b';
				} else if (i <= 15)
				{
					label[0] = (i - 12 + '0');
					label[1] = 'a';
				} else if (i <= 18)
				{
					label[0] = (i - 15 + '0');
					label[1] = 'b';
				} else if (i <= 21)
				{
					label[0] = (i - 18 + '0');
					label[1] = 'a';
				} else if (i <= 24)
				{
					label[0] = (i - 21 + '0');
					label[1] = 'b';
				}
			} else {
				if (i <= 6)
				{
					label[0] = (i + '0');
					label[1] = 'a';
				}
				else
				{
					label[0] = (i - 6 + '0');
					label[1] = 'b';
				}
			}
			memmove(label + 3, label + 2, EElen_label);
			label[2] = 0x20;
			label[19] = 0;
			keytype((char *)label);
		}
		else
		{
			send_transport_response(label, 18, false, false);
			delay(20);
		}
	}
	if (output == 1) keytype("For OnlyKey on-the-go visit https://apps.crp.to");
	return;
}

void set_slot(uint8_t *buffer)
{
	int slot = buffer[5];
	int value = buffer[6];
	uint8_t temp;
	uint8_t mask;
	uint8_t mode;
	int length = 0;
	char cmd = buffer[4]; //cmd or continuation
	#ifdef DEBUG
	Serial.print("OKSETSLOT MESSAGE RECEIVED:");
	Serial.println((int)cmd - 0x80, HEX);
	Serial.print("Setting Slot #");
	Serial.println((int)slot, DEC);
	Serial.print("Value #");
	Serial.println((int)value, DEC);
	#endif
	for (int z = 0; buffer[z + 7] + buffer[z + 8] + buffer[z + 9] + buffer[z + 10] != 0x00; z++)
	{
		length = z + 1;
	#ifdef DEBUG
		Serial.print(buffer[z + 7], HEX);
	#endif
	}
	#ifdef DEBUG
	Serial.println(); //newline
	Serial.print("Length = ");
	Serial.println(length);
	#endif
	if (buffer[0] == 0xBA && slot > 12)
	{
		okeeprom_eeget_2ndprofilemode(&mode);
	}
	else
	{
		mode = profilemode;
	}
	if (profilemode && slot <= 12 && buffer[0] != 0xBA)  // 2nd profile slots 12 -24 0xBA is loading from backup
		slot = slot + 12;
	switch (value)
	{
	case 1:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing Label Value to Flash...");
		#endif
		okcore_flashset_label(buffer + 7, slot);
		hidprint("Successfully set Label");
		break;
	case 15:
		#ifdef DEBUG
		Serial.println("Writing URL Value to Flash...");
		#endif
		if (mode != NONENCRYPTEDPROFILE)
		{
			#ifdef DEBUG
			Serial.println("Unencrypted");
			byteprint(buffer + 7, 32);
			Serial.println();
			#endif
			okcore_aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
			#ifdef DEBUG
			Serial.println("Encrypted");
			byteprint(buffer + 7, 32);
			Serial.println();
			#endif
		}
		okcore_flashset_url(buffer + 7, length, slot);
		hidprint("Successfully set URL");
		break;
	case 16:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing after Username Additional Character to EEPROM...");
		#endif
		if (buffer[7] >= 0x30)
			buffer[7] = buffer[7] - '0';
		okeeprom_eeget_addchar(&temp, slot);
		mask = 0b00000011;
		buffer[7] = (temp & ~mask) | (buffer[7] & mask);
		okeeprom_eeset_addchar(buffer + 7, slot);
		#ifdef DEBUG
		Serial.print(buffer[7]);
		#endif
		hidprint("Successfully set after Username Additonal Character");
		break;
	case 17:
		//Set value in EEPROM
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing Delay1 to EEPROM...");
		#endif
		if (buffer[7] > '0')
			buffer[7] = (buffer[7] - '0');
		okeeprom_eeset_delay1(buffer + 7, slot);
		hidprint("Successfully set Delay1");
		break;
	case 18:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing before Username Additional Character to EEPROM...");
		#endif
		if (buffer[7] >= 0x30)
			buffer[7] = buffer[7] - '0';
		okeeprom_eeget_addchar(&temp, slot);
		mask = 0b00000100;
		buffer[7] = buffer[7] << 2;
		buffer[7] = (temp & ~mask) | (buffer[7] & mask);
		okeeprom_eeset_addchar(buffer + 7, slot);
		#ifdef DEBUG
		Serial.print(buffer[7]);
		#endif
		hidprint("Successfully set before Username Additional Character");
		break;
	case 19:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing before OTP Additional Character to EEPROM...");
		#endif
		if (buffer[7] >= 0x30)
			buffer[7] = buffer[7] - '0';
		okeeprom_eeget_addchar(&temp, slot);
		mask = 0b00001000;
		buffer[7] = buffer[7] << 3;
		buffer[7] = (temp & ~mask) | (buffer[7] & mask);
		okeeprom_eeset_addchar(buffer + 7, slot);
		#ifdef DEBUG
		Serial.print(buffer[7]);
		#endif
		hidprint("Successfully set before OTP Additional Character");
		break;
	case 2:
		//Encrypt and Set value in EEPROM
		#ifdef DEBUG
		Serial.println("Writing Username Value to Flash...");
		#endif
		if (mode != NONENCRYPTEDPROFILE)
		{
			#ifdef DEBUG
			Serial.println("Unencrypted");
			byteprint(buffer + 7, 32);
			Serial.println();
			#endif
			okcore_aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
			#ifdef DEBUG
			Serial.println("Encrypted");
			byteprint(buffer + 7, 32);
			Serial.println();
			#endif
		}
		okcore_flashset_username(buffer + 7, length, slot);
		hidprint("Successfully set Username");
		break;
	case 3:
		//Set value in EEPROM
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing Additional after password to EEPROM...");
		#endif
		if (buffer[7] >= 0x30)
			buffer[7] = buffer[7] - '0';
		okeeprom_eeget_addchar(&temp, slot);
		mask = 0b00110000;
		buffer[7] = buffer[7] << 4;
		buffer[7] = (temp & ~mask) | (buffer[7] & mask);
		okeeprom_eeset_addchar(buffer + 7, slot);
		#ifdef DEBUG
		Serial.print(buffer[7]);
		#endif
		hidprint("Successfully set additional character after password");
		break;
	case 4:
		//Set value in EEPROM
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing Delay2 to EEPROM...");
		#endif
		if (buffer[7] > '0')
			buffer[7] = (buffer[7] - '0');
		okeeprom_eeset_delay2(buffer + 7, slot);
		hidprint("Successfully set Delay2");
		break;
	case 5:
		//Encrypt and Set value in EEPROM
		#ifdef DEBUG
		Serial.println("Writing Password to EEPROM...");
		#endif
		if (mode != NONENCRYPTEDPROFILE)
		{
			if (Duo_config[0]==1) { // No PIN set
				okeeprom_eeget_2FAtype(&temp, slot);
				if (temp != 0) {
					hidprint("Error MFA already enabled on this slot, device PIN required");
					blink(1);
					return;
				}
			}
			#ifdef DEBUG
			Serial.println("Unencrypted");
			byteprint(buffer + 7, 32);
			Serial.println();
			#endif
			okcore_aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
			#ifdef DEBUG
			Serial.println("Encrypted");
			byteprint(buffer + 7, 32);
			Serial.println();
			#endif
		}
		okeeprom_eeset_password(buffer + 7, length, slot);
		hidprint("Successfully set Password");
		break;
	case 6:
		//Set value in EEPROM
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing After OTP Additional Character to EEPROM...");
		#endif
		if (buffer[7] >= 0x30)
			buffer[7] = buffer[7] - '0';
		okeeprom_eeget_addchar(&temp, slot);
		if (buffer[7] == 2) { // Return Only
			buffer[7] = 1 << 6;
		} else if (buffer[7] == 1) { // Tab Only
			buffer[7] = 1 << 7;
		} else if (buffer[7] == 3) { // Tab and Return
			buffer[7] = 192;
		}
		mask = 0b11000000;
		buffer[7] = (temp & ~mask) | (buffer[7] & mask);
		okeeprom_eeset_addchar(buffer + 7, slot);
		#ifdef DEBUG
		Serial.print(buffer[7]);
		#endif
		hidprint("Successfully set after OTP Character");
		break;
	case 7:
		//Set value in EEPROM
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing Delay3 to EEPROM...");
		#endif
		if (buffer[7] > '0')
			buffer[7] = (buffer[7] - '0');
		okeeprom_eeset_delay3(buffer + 7, slot);
		hidprint("Successfully set Delay3");
		break;
	case 8:
		//Set value in EEPROM
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing 2FA Type to EEPROM...");
		#endif
		if (Duo_config[0]==1) { // No PIN set
			temp = okeeprom_eeget_password(large_buffer, slot);
			memset(large_buffer, 0, 64);
			if (temp != 0) {
				hidprint("Error password already enabled on this slot, device PIN required");
				blink(1);
				return;
			}
		}
		okeeprom_eeset_2FAtype(buffer + 7, slot);
		hidprint("Successfully set 2FA Type");
		break;
	case 9:
		#ifdef DEBUG
		Serial.println("Writing 2FA Key to Flash...");
		Serial.println("Unencrypted");
		byteprint(buffer + 7, 57);
		Serial.println();
		#endif
		if (Duo_config[0]==1) { // No PIN set
			temp = okeeprom_eeget_password(large_buffer, slot);
			memset(large_buffer, 0, 64);
			if (temp != 0) {
				hidprint("Error password already enabled on this slot, device PIN required");
				blink(1);
				return;
			}
		}
		okcore_aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
		okcore_flashset_2fa_key(buffer + 7, length, slot);
		temp = MFAGOOGLEAUTH;
		okeeprom_eeset_2FAtype(&temp, slot);
		#ifdef DEBUG
		Serial.println("Encrypted");
		byteprint(buffer + 7, 57);
		Serial.println();
		#endif
		hidprint("Successfully set 2FA Key");
		break;
	case 29:
		#ifdef DEBUG
		Serial.println("Writing 2FA Key to Flash...");
		Serial.println("Unencrypted");
		byteprint(buffer + 7, 57);
		Serial.println();
		#endif
		if (Duo_config[0]==1) { // No PIN set
			temp = okeeprom_eeget_password(large_buffer, slot);
			memset(large_buffer, 0, 64);
			if (temp != 0) {
				hidprint("Error password already enabled on this slot, device PIN required");
				blink(1);
				return;
			}
		}
		uint8_t tempbuf[21];
		okeeprom_eeget_2FAtype(&temp, slot);
		okcore_aes_gcm_encrypt((buffer + 7), slot, 29, profilekey, 21);
		memmove(tempbuf, buffer + 7, 21);
		okcore_flashget_2fa_key(buffer, slot);
		memmove(buffer + 43, tempbuf, 21);
		if (temp == MFAYUBIOTPandHMACSHA1 || temp == MFAYUBIOTP) {
			temp = MFAYUBIOTPandHMACSHA1;
			okeeprom_eeset_2FAtype(&temp, slot);
		}
		else {
			temp = MFAHMACSHA1;
			okeeprom_eeset_2FAtype(&temp, slot);
			memset(buffer, 0, 43);
		}
		okcore_flashset_2fa_key(buffer, 0, slot);
		#ifdef DEBUG
		Serial.println("Encrypted");
		byteprint(buffer + 7, 57);
		Serial.println();
		#endif
		hidprint("Successfully set 2FA Key");
		break;
	case 10:
		if (mode != NONENCRYPTEDPROFILE)
		{
			//Encrypt and Set value in Flash
			#ifdef DEBUG
			Serial.println("Writing AES Key, Private ID, and Public ID to EEPROM...");
			#endif
			if (slot == 0) {
				okcore_aes_gcm_encrypt((buffer + 7), slot, value, profilekey, (EElen_public+EElen_private+EElen_aeskey));	
				okeeprom_eeset_public_DEPRICATED(buffer + 7);
				okeeprom_eeset_private_DEPRICATED((buffer + 7 + EElen_public));
				okeeprom_eeset_aeskey_DEPRICATED(buffer + 7 + EElen_public + EElen_private);
			} else if (slot >= 1 && slot <= 24) {
				if (Duo_config[0]==1) { // No PIN set
					temp = okeeprom_eeget_password(large_buffer, slot);
					memset(large_buffer, 0, 64);
					if (temp != 0) {
						hidprint("Error password already enabled on this slot, device PIN required");
						blink(1);
						return;
					}
				}
				okeeprom_eeget_2FAtype(&temp, slot);
				uint8_t tempbuf[38];
				okcore_aes_gcm_encrypt((buffer + 7), slot, 10, profilekey, (16+EElen_private+EElen_aeskey));
				memmove(tempbuf, buffer + 7, 38);
				okcore_flashget_2fa_key(buffer, slot);
				memmove(buffer, tempbuf, 38);
				if (temp == MFAYUBIOTPandHMACSHA1 || temp == MFAHMACSHA1) {
					temp = MFAYUBIOTPandHMACSHA1;
					okeeprom_eeset_2FAtype(&temp, slot);
					okcore_flashset_2fa_key(buffer, 0, slot);
				}
				else {
					temp = MFAYUBIOTP;
					okeeprom_eeset_2FAtype(&temp, slot);
					memset(buffer+43, 0, 21);
					okcore_flashset_2fa_key(buffer, 0, slot);
				}
			}
			uint8_t ctr[2] = {0};
			yubikey_eeset_counter(ctr, slot);
			hidprint("Successfully set AES Key, Private ID, and Public ID");
		}
		break;
	case 11:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing idle timeout to EEPROM...");
		#endif
		okeeprom_eeset_timeout(buffer + 7);
		TIMEOUT[0] = buffer[7];
		hidprint("Successfully set idle timeout");
		break;
	case 12:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing wipemode to EEPROM...");
		#endif
		if (buffer[7] == 2 && (configmode == true || !initcheck || profilemode == NONENCRYPTEDPROFILE))
		{
			okeeprom_eeset_wipemode(buffer + 7);
			hidprint("Successfully set Wipe Mode to Full Wipe");
		}
		else if (!initcheck)
		{ //Only permit changing this on first use on a clean device
			okeeprom_eeset_wipemode(buffer + 7);
			hidprint("Successfully set Wipe Mode to default setting");
		}
		else
		{
			hidprint("Error Wipe Mode may not be changed");
		}
		break;
	case 20:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing backupkeymode to EEPROM...");
		#endif
		if (buffer[7] == 1 && (configmode == true || !initcheck))
		{
			okeeprom_eeset_backupkeymode(buffer + 7);
			hidprint("Successfully set Backup Key Mode to Locked");
		}
		else if (!initcheck)
		{ //Only permit changing this on first use on a clean device
			okeeprom_eeset_backupkeymode(buffer + 7);
			hidprint("Successfully set Backup Key Mode to Permit Future Changes");
		}
		else
		{
			hidprint("Error Backup Key Mode may not be changed");
		}
		break;
	case 21:

		if (configmode == true || !initcheck)
		{ //Only permit changing this on first use or while in config mode
			#ifdef DEBUG
			Serial.println(); //newline
			Serial.println("Writing derived_key_challenge_mode to EEPROM...");
			#endif
			okeeprom_eeset_derived_key_challenge_mode(buffer + 7);
			hidprint("Successfully set derived key challenge mode");
		}
		else
		{
			hidprint("Error not in config mode");
		}
		break;
	case 22:

		if (configmode == true || !initcheck)
		{ //Only permit changing this on first use or while in config mode
			#ifdef DEBUG
			Serial.println(); //newline
			Serial.println("Writing stored_key_challenge_mode to EEPROM...");
			#endif
			okeeprom_eeset_stored_key_challenge_mode(buffer + 7);
			hidprint("Successfully set stored key challenge mode");
		}
		else
		{
			hidprint("Error not in config mode");
		}
		break;
	case 26:

		if (configmode == true || !initcheck)
		{ //Only permit changing this on first use or while in config mode
			#ifdef DEBUG
			Serial.println(); //newline
			Serial.println("Writing hmac_challengemode to EEPROM...");
			#endif
			okeeprom_eeset_hmac_challengemode(buffer + 7);
			hidprint("Successfully set HMAC Challenge Mode");
		}
		else
		{
			hidprint("Error not in config mode");
		}
		break;
	case 27:

		if (configmode == true || !initcheck)
		{ //Only permit changing this on first use or while in config mode
			#ifdef DEBUG
			Serial.println(); //newline
			Serial.println("Writing sysadmin mode to EEPROM...");
			#endif
			okeeprom_eeset_modkey(buffer + 7);
			hidprint("Successfully set Sysadmin Mode");
		}
		else
		{
			hidprint("Error not in config mode");
		}
		break;
	case 23:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing 2ndprofilemode to EEPROM...");
		#endif
		if (mode == NONENCRYPTEDPROFILE)
			return;
		#ifdef STD_VERSION
		if (!initcheck)
		{ //Only permit changing this on first use
			okeeprom_eeset_2ndprofilemode(buffer + 7);
			//hidprint("Successfully set 2nd profile mode");
		}
		else
		{
			hidprint("Second Profile Mode may only be changed on first use");
		}
		#endif
		break;
	case 24:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing LED brightness to EEPROM...");
		#endif
		okeeprom_eeset_ledbrightness(buffer + 7);
		NEO_Brightness[0] = buffer[7];
		pixels.setBrightness(NEO_Brightness[0] * 22);
		hidprint("Successfully set LED brightness");
		break;
	case 28:
		if (configmode == true || !initcheck)
		{ //Only permit changing this on first use or while in config mode
			#ifdef DEBUG
			Serial.println(); //newline
			Serial.println("Writing Touch Sensitivity to EEPROM...");
			#endif
			if (buffer[7] > 1 && buffer[7] <= 100) {
				okeeprom_eeset_touchoffset(buffer + 7);
				touchoffset = buffer[7];
				hidprint("Successfully set Touch Sensitivity");
			} else {
				hidprint("Error touchsense value out of range");
			}
		}
		else
		{
			hidprint("Error not in config mode");
		}
		break;
	case 25:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing lock button to EEPROM...");
		#endif
		uint8_t temp;
		okeeprom_eeget_autolockslot(&temp);
		if (profilemode) {
			temp &= 0x0F;
			temp += (buffer[7] << 4);
			okeeprom_eeset_autolockslot(&temp);
		} else {
			temp &= 0xF0;
			temp += buffer[7];
			okeeprom_eeset_autolockslot(&temp);
		}
		hidprint("Successfully set lock button");
		break;
	case 13:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing keyboard type speed to EEPROM...");
		#endif

		if (buffer[7] <= 10)
		{
			buffer[7] = 11 - buffer[7];
			okeeprom_eeset_typespeed(buffer + 7, slot);
			if (buffer[8] == 0) {
				TYPESPEED[0] = buffer[7];
			}
		}
		hidprint("Successfully set typespeed");
		break;
	case 14:
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.println("Writing keyboard layout to EEPROM...");
		#endif
		KeyboardLayout[0] = buffer[7];
		okeeprom_eeset_keyboardlayout(buffer + 7);
		update_keyboard_layout();
		hidprint("Successfully set keyboard layout");

	default:
		return;
	}
	if (buffer[0] != 0xBA)
		blink(1);
	return;
}

void wipe_slot(uint8_t *buffer)
{
	int slot = buffer[5];
	int value = buffer[6];
	char cmd = buffer[4]; //cmd or continuation
	#ifdef DEBUG
	Serial.print("OKWIPESLOT MESSAGE RECEIVED:");
	Serial.println((int)cmd - 0x80, HEX);
	Serial.print("Wiping Slot #");
	Serial.println((int)slot, DEC);
	Serial.print("Value #");
	Serial.println((int)value, DEC);
	#endif

	memset(buffer, 0, 64);
	#ifdef DEBUG
	byteprint(buffer, 64);
	Serial.print("Overwriting slot with 0s");
	#endif
	if (value == 10 && slot == 0)
	{
	#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping OnlyKey AES Key, Private ID, and Public ID...");
	#endif
		okeeprom_eeset_aeskey_DEPRICATED(buffer + 7);
		okeeprom_eeset_private_DEPRICATED(buffer + 7 + EElen_aeskey);
		okeeprom_eeset_public_DEPRICATED(buffer + 7 + EElen_aeskey + EElen_private);
	}
	else if (slot >= 1 && slot <= 24)
	{
		if (profilemode && slot <= 12)
			slot = slot + 12;
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping Label Value...");
		#endif
		okcore_flashset_label((buffer + 7), slot);
		hidprint("Successfully wiped Label");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping URL Value...");
		#endif
		okcore_flashset_url((buffer + 7), 0, slot);
		hidprint("Successfully wiped URL");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping Additional Character1 Value...");
		#endif
		okeeprom_eeset_addchar((buffer + 7), slot);
		hidprint("Successfully wiped Additional Characters");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing Delay1 to EEPROM...");
		#endif
		okeeprom_eeset_delay1((buffer + 7), slot);
		hidprint("Successfully wiped Delay 1");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping Username Value...");
		#endif
		okcore_flashset_username((buffer + 7), 0, slot);
		hidprint("Successfully wiped Username");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Writing Delay2 to EEPROM...");
		#endif
		okeeprom_eeset_delay2((buffer + 7), slot);
		hidprint("Successfully wiped Delay 2");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping Password Value...");
		#endif
		okeeprom_eeset_password((buffer + 7), 0, slot);
		hidprint("Successfully wiped Password");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping Delay3 Value...");
		#endif
		okeeprom_eeset_delay3((buffer + 7), slot);
		hidprint("Successfully wiped Delay 3");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping 2FA Type Value...");
		#endif
		okeeprom_eeset_2FAtype((buffer + 7), slot);
		hidprint("Successfully wiped 2FA Type");
		#ifdef DEBUG
		Serial.println(); //newline
		Serial.print("Wiping 2FA Key from Flash...");
		#endif
		okcore_flashset_2fa_key((buffer + 7), 0, slot);
		hidprint("Successfully wiped 2FA Key");
 		okeeprom_eeset_2FAtype(0, slot); 
		yubikey_eeset_counter(0, slot);
	}
	blink(1);
	return;
}

void digitalClockDisplay()
{
	// digital clock display of the time
#ifdef DEBUG
	Serial.print(hour());
	printDigits(minute());
	printDigits(second());
	Serial.print(" ");
	Serial.print(day());
	Serial.print(" ");
	Serial.print(month());
	Serial.print(" ");
	Serial.print(year());
	Serial.println();
#endif
}

void printDigits(int digits)
{
	// utility function for digital clock display: prints preceding colon and leading 0
#ifdef DEBUG
	Serial.print(":");
	if (digits < 10)
		Serial.print('0');
	Serial.print(digits);
#endif
}

void blink(int times)
{

	int i;
	for (i = 0; i < times; i++)
	{
#ifdef OK_Color
		setcolor(NEO_Color);
#else
		analogWrite(BLINKPIN, 255);
#endif
		delay(100);
#ifdef OK_Color
		setcolor(0);
#else
		analogWrite(BLINKPIN, 0);
#endif
		delay(100);
	}
}

void fadein()
{
	// fade in from min to max in increments of 5 points:
	for (int fadeValue = 0; fadeValue <= 255; fadeValue += 5)
	{
		// sets the value (range from 0 to 255):
		analogWrite(BLINKPIN, fadeValue);
		delay(9);
	}
}

void fadeout()
{
	// fade out from max to min in increments of 5 points:
	for (int fadeValue = 255; fadeValue >= 0; fadeValue -= 5)
	{
		// sets the value (range from 0 to 255):
		analogWrite(BLINKPIN, fadeValue);
		delay(9);
	}
}

int touch_sense_loop () {

	static int key_on=0;
	static int key_off=0;
	static int key_press=0;
	static int button_3_on=0;
	static int button_3_off=0;

	//Uncomment to test RNG
	//RNG2(data, 32);
	//printHex(data, 32);

	rngloop(); //Perform regular housekeeping on the random number generator.

	if (touchoffset == 0) touchoffset = 12; // DEFAULT

	// Any Button reads 20% lower than ref, recalibrate
	//if (touchread1+(touchread1/5)<touchread1ref || touchread2+(touchread2/5)<touchread2ref || touchread3+(touchread3/5)<touchread3ref || touchread4+(touchread4/5)<touchread4ref || touchread5+(touchread5/5)<touchread5ref || touchread6+(touchread6/5)<touchread6ref) {
	//	key_on = 0;
	//	key_press = 0;
	//	rainbowCycle();
	//	return 0;
	//}

	// All Buttons read 5% higher than ref, recalibrate
	if (onlykeyhw!=OK_HW_DUO && (touchread1ref+(touchread1ref/20)<touchread1 && touchread2ref+(touchread2ref/20)<touchread2 && touchread3ref+(touchread3ref/20)<touchread3 && touchread4ref+(touchread4ref/20)<touchread4 && touchread5ref+(touchread5ref/20)<touchread5 && touchread6ref+(touchread6ref/20)<touchread6)) {
		key_on = 0;
		key_press = 0;
		rainbowCycle();
		return 0;
	}

	/*
	Serial.println("touchread1");
	Serial.println(touchread1);
	Serial.println("touchread2");
	Serial.println(touchread2);
	Serial.println("touchread3");
	Serial.println(touchread3);
	Serial.println("touchread4");
	Serial.println(touchread4);
	Serial.println("touchread5");
	Serial.println(touchread5);
	Serial.println("touchread6");
	Serial.println(touchread6);
	Serial.println("AnalogreadA12");
	Serial.println(analogRead(A12));
	*/

	// Button reads ~348 (default 12) higher than ref, which is ~25%, register touch
	if (onlykeyhw!=OK_HW_DUO && touchread1 > (touchread1ref+(touchoffset*(touchread1ref/50)))) {
		key_off = 0;
		key_press = 0;
		key_on += 1;
		button_selected = '5';

	}
	else if (touchread2 > (touchread2ref+(touchoffset*(touchread2ref/50)))) {
		key_off = 0;
		key_press = 0;
		key_on += 1;
		button_selected = '2';
		if (onlykeyhw==OK_HW_DUO) {
			if (touchread3 > (touchread3ref+(touchoffset*(touchread3ref/50)))) {
				button_3_on++;
				button_3_off=0;
			} else {
				button_3_off++;
				if (button_3_off>2) button_3_on=0;
			}
		}
	}
	else if (touchread3 > (touchread3ref+(touchoffset*(touchread3ref/50)))) {
		key_off = 0;
		key_press = 0;
		key_on += 1;
		button_selected = '1';
		if (onlykeyhw==OK_HW_DUO) {
			if (touchread2 > (touchread2ref+(touchoffset*(touchread2ref/50)))) {
				button_3_on++;
				button_3_off=0;
			} else {
				button_3_off++;
				if (button_3_off>2) button_3_on=0;
			}
		}
	}
	else if (onlykeyhw!=OK_HW_DUO && touchread4 > (touchread4ref+(touchoffset*(touchread4ref/50)))) {
		key_off = 0;
		key_press = 0;
		key_on += 1;
		button_selected = '3';
	}
	else if (onlykeyhw!=OK_HW_DUO && touchread5 > (touchread5ref+(touchoffset*(touchread5ref/50)))) {
		key_off = 0;
		key_press = 0;
		key_on += 1;
		button_selected = '4';
	}
	else if (onlykeyhw!=OK_HW_DUO && touchread6 > (touchread6ref+(touchoffset*(touchread6ref/50)))) {
		key_off = 0;
		key_press = 0;
		key_on += 1;
		button_selected = '6';
	} else {
		if (key_on > THRESHOLD) key_press = key_on;
		key_off += 1;
		if (!unlocked){
		#ifdef OK_Color
		setcolor(0); // NEO Pixel OFF
		#else
		analogWrite(BLINKPIN, 0); //LED OFF
		#endif
		} else if (!isfade && initcheck) {
		#ifdef OK_Color
		setcolor(85); // NEO Pixel ON Green
		#else
		analogWrite(BLINKPIN, 255); //LED ON
		#endif
		}
	}

	if (!initcheck && key_off > 2) {
		#ifdef OK_Color
		setcolor(85); // NEO Pixel ON Green
		#else
		analogWrite(BLINKPIN, 255); //LED ON
		#endif
	}

	if ((key_press > 0) && (key_off > 2)) {
		if (onlykeyhw==OK_HW_DUO && button_3_on) {
			button_selected = '3';
		}
		button_3_on = 0;
		button_3_off = 0;
		key_on = 0;
		int duration = key_press;
		key_press = 0;
		
		return duration;
	}

	return 0;
}



/*************************************/
// RNG Loop 
// Stir in entropy from internal chip temperature, touchRead, and analogRead
/*************************************/
void rngloop()
{
	// Stir temperature into entropy pool
	unsigned int internal_temperature1 = internal_temp();
	//Serial.println("internal temp");
	//Serial.println(internal_temperature1);
	//byteprint((uint8_t *)&internal_temperature1, 2);
	// Two bytes, 1 credit
	RNG.stir((uint8_t *)&internal_temperature1, 2, 1);
	// Stir the touchread and analog read values into the entropy pool.
	unsigned int analog1 = analogRead(ANALOGPIN1);
	//byteprint((uint8_t *)&internal_temperature1, 3);
	//Serial.println("analog 1");
	//Serial.println(analog1);
	//byteprint((uint8_t *)&analog1, 2);
	// Two bytes, 2 credits
	RNG.stir((uint8_t *)&analog1, 2, 2);
	touchread1 = touchRead(TOUCHPIN1);
	if(onlykeyhw==OK_HW_DUO) {
		touchread2 = touchRead(TOUCHPIN5);
		touchread5 = touchRead(TOUCHPIN2);
	} else {
		touchread2 = touchRead(TOUCHPIN2);
		touchread5 = touchRead(TOUCHPIN5);
	}
	delay((analog1 % 3) + ((touchread1 + touchread2) % 3)); //delay 0 - 4 ms
	integrityctr1++;
	touchread3 = touchRead(TOUCHPIN3);
	touchread4 = touchRead(TOUCHPIN4);
	touchread6 = touchRead(TOUCHPIN6);
	unsigned int analog2 = analogRead(ANALOGPIN2);
	//Serial.println("analog 2");
	//Serial.println(analog2);
	//byteprint((uint8_t *)&analog2, 2);
	// Two bytes, 2 credits
	RNG.stir((uint8_t *)&analog2, 2, 2);
	sumofall = (analog2 + touchread6 + touchread5 + touchread4 + analog1 + touchread3 + touchread2 + touchread1);
	//Serial.println("sumofall");
	//Serial.println(sumofall);
	//byteprint((uint8_t *)&sumofall, 3);
	// Three bytes, 4 credits
	RNG.stir((uint8_t *)&sumofall, 3, 4);
	// Perform regular housekeeping on the random number generator.
	RNG.loop();
	delay((analog2 % 3) + ((touchread6 + touchread5 + touchread4) % 3)); //delay 0 - 4 ms
	integrityctr2++;
	if (integrityctr1 != integrityctr2 )
	{ //Integrity check failed, reboot
		unlocked = false;
		CPU_RESTART();
		return;
	}
}

void printHex(const uint8_t *data, unsigned len)
{
#ifdef DEBUG
	static char const hexchars[] = "0123456789ABCDEF";
	while (len > 0)
	{
		int b = *data++;

		Serial.print(hexchars[(b >> 4) & 0x0F]);
		Serial.print(hexchars[b & 0x0F]);

		--len;
	}

	Serial.println();
#endif
}

void hidprint(char const *chars)
{
	int i = 0;
	memset(resp_buffer, 0, sizeof(resp_buffer));
	while (*chars && i < 64)
	{
		if (*chars == 0xFF)
			resp_buffer[i] = 0x00; //Empty flash sector is 0xFF
		else
			resp_buffer[i] = (uint8_t)*chars;
		chars++;
		i++;
	}
	send_transport_response(resp_buffer, i, false, false);
}

void send_transport_response(uint8_t *data, int len, uint8_t encrypt, uint8_t store)
{
	#ifdef DEBUG
	Serial.println("Sending transport response data");
	byteprint(data, len);
	Serial.println(outputmode);
	#endif
	if (!outputmode)
	{ //USB
		for (int i = 0; i < len; i += 64)
		{
			if (len-i>=64) {
				memcpy(resp_buffer, data+i, 64);
			}
			else {
				memcpy(resp_buffer, data+i, len-i);
			}
			#ifdef DEBUG
			byteprint(resp_buffer, 64);
			#endif
			RawHID.send2(resp_buffer, 0);
		}
	}
	else if (profilemode != NONENCRYPTEDPROFILE && outputmode == WEBAUTHN)
	{ //Webauthn
#ifdef STD_VERSION
  #ifdef DEBUG
      Serial.print ("FIDO Response");
	  byteprint(data, len);
#endif
		store_FIDO_response(data, len, encrypt);
		return;
#endif
	}
	/* This is for sending data in apdu format i.e. Ledger transport, not currently used
  else if (outputmode==2) { //USB HID
    apdu_data(data, len);
    for (int i=0; i<LARGE_RESP_BUFFER_SIZE-64;i+=64) {
      if (large_resp_buffer[i]+large_resp_buffer[i+1]>0) { //We have a channel id
        RawHID.send(large_resp_buffer+i, 0);
      }
    }
  }
  */
	else if (outputmode == KEYBOARD_USB)
	{ //USB Keyboard
		// This is for staging large response over keyboard in apdu format, not currently used, only one 64 byte response used
		//apdu_data(data, len);
		//store_keyboard_response();
		memcpy(keyboard_buffer, data, 7);
		keyboard_buffer[7] = 0xC0; //Part 1
		memcpy(keyboard_buffer + 8, data + 7, 7);
		keyboard_buffer[15] = 0xC1; //Part 2
		memcpy(keyboard_buffer + 16, data + 14, 7);
		keyboard_buffer[23] = 0xC2; //Part 3
		memcpy(keyboard_buffer + 24, data + 21, 7);
		keyboard_buffer[31] = 0xC3; //Part 4
		memcpy(keyboard_buffer + 32, data + 28, 7);
		keyboard_buffer[39] = 0xC4; //Part 5
		memcpy(keyboard_buffer + 40, data + 35, 7);
		keyboard_buffer[47] = 0xC5; //Part 6
		memcpy(keyboard_buffer + 48, data + 42, 7);
		keyboard_buffer[55] = 0xC6; //Part 7
		memcpy(keyboard_buffer + 56, data + 49, 7);
		keyboard_buffer[63] = 0xC7; //Part 8
		memcpy(keyboard_buffer + 64, data + 56, 7);
		keyboard_buffer[71] = 0xC8; //Part 9
		memcpy(keyboard_buffer + 72, data + 63, 1);
		keyboard_buffer[79] = 0xC9; //Part 10
		int crc = yubikey_crc16(data, 64);
		crc ^= 0xFFFF;
		memset(setBuffer, 0, 9);
		memset(data, 0, 64);
		// crc check
		keyboard_buffer[73] = crc & 0xFF;
		keyboard_buffer[74] = crc >> 8;
		keyboard_buffer[76] = 0x4B;
		#ifdef DEBUG
		Serial.println("Sending keyboard response");
		byteprint(keyboard_buffer, 80);
		#endif
		wipedata(); //Wait 5 seconds for this to be retreived
	}
	else if (outputmode == DISCARD)
	{ // Discard, don't send anything
	}
	changeoutputmode(RAW_USB);
	memset(data, 0, len);
}

void changeoutputmode(uint8_t mode)
{
	outputmode = mode;
	memset(resp_buffer, 0, sizeof(resp_buffer));
}

/* This is for formatting response as apdu, i.e. for Ledger transport, not currently used
void apdu_data(uint8_t *data, int len) {
  int blocks;
  int offset;
  while (len>0) {
    if (len<=57) { //First Packet
      memmove(large_resp_buffer+7, data, 57);
      large_resp_buffer[0] = packet_buffer_details[3]; //channelid
      large_resp_buffer[1] = packet_buffer_details[4]; //channelid
      large_resp_buffer[2] = 5;
      large_resp_buffer[3] = 0;
      large_resp_buffer[4] = 0; // no block num first packet
      large_resp_buffer[5] = len >> 8; // total len
      large_resp_buffer[6] = len & 0xFF;
      len = len-52;
      Serial.println("Storing first packet");
      byteprint(large_resp_buffer, 64);
    } else {
      blocks = (len - 52)/59;
      offset = (blocks*5)+7;
      if (len+offset>LARGE_RESP_BUFFER_SIZE) return;
      uint8_t *ptr = large_resp_buffer+offset+(blocks*59)-59;
      memmove(ptr, data+(blocks*59)-59, 59);
      ptr--;
      *ptr = blocks;
      ptr--;
      *ptr = 0;
      ptr--;
      *ptr = 5;
      ptr--;
      *ptr = packet_buffer_details[4]; //channelid
      ptr--;
      *ptr = packet_buffer_details[3]; //channelid
      large_resp_buffer[0] = packet_buffer_details[3]; //channelid
      Serial.println("Storing 2nd+ packet");
      byteprint(ptr, 64);
      len = len-59;
    }
  }
}
*/

// This is for sending multiple chunks of data as response via keyboard, currently not using this
// It may be needed in the future
/*
int store_keyboard_response() {
  int offset = 0;
  int ret = 0;
  if (outputmode==3) {
    for (int i=0; i<LARGE_RESP_BUFFER_SIZE-64;i+=64) {
      if (large_resp_buffer[i]+large_resp_buffer[i+1]>0) { //We have a channel id
        offset=i;
        ret = 1;
      }
      if (ret) break;
    }
    if (ret) {
      memcpy(keyboard_buffer, large_resp_buffer+offset, 7);
      keyboard_buffer[7] = 0xC0; //Part 1
      memcpy(keyboard_buffer+8, large_resp_buffer+offset+7, 7);
      keyboard_buffer[15] = 0xC1; //Part 2
      memcpy(keyboard_buffer+16, large_resp_buffer+offset+14, 7);
      keyboard_buffer[23] = 0xC2; //Part 3
      memcpy(keyboard_buffer+24, large_resp_buffer+offset+21, 7);
      keyboard_buffer[31] = 0xC3; //Part 4
      memcpy(keyboard_buffer+32, large_resp_buffer+offset+28, 7);
      keyboard_buffer[39] = 0xC4; //Part 5
      memcpy(keyboard_buffer+40, large_resp_buffer+offset+35, 7);
      keyboard_buffer[47] = 0xC5; //Part 6
      memcpy(keyboard_buffer+48, large_resp_buffer+offset+42, 7);
      keyboard_buffer[55] = 0xC6; //Part 7
      memcpy(keyboard_buffer+56, large_resp_buffer+offset+49, 7);
      keyboard_buffer[63] = 0xC7; //Part 8
      memcpy(keyboard_buffer+64, large_resp_buffer+offset+56, 7);
      keyboard_buffer[71] = 0xC8; //Part 9
      memcpy(keyboard_buffer+72, large_resp_buffer+offset+63, 1);
      keyboard_buffer[79] = 0xC9; //Part 10
      //int crc = yubikey_crc16 (data, 64);
      //crc ^= 0xFFFF;
      memset(setBuffer, 0, 9);
      memset(large_resp_buffer+offset, 0, 64);
      //Todo add crc check
      //keyboard_buffer[22] = crc & 0xFF;
      //keyboard_buffer[24] = crc >> 8;
      //keyboard_buffer[31] = 0xC3;
      //keyboard_buffer[28] = 0x4B;
      Serial.println("Storing keyboard response");
      byteprint(keyboard_buffer, 80);
    }
  }
  return ret;
}
*/

void keytype(char const *chars)
{
	while (*chars)
	{
		if (*chars == 0xFF)
			chars++; //Empty flash sector is 0xFF
		else
		{
			//Serial.print(*chars);
			Keyboard.press(*chars);
			delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
			Keyboard.releaseAll();
			delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
			chars++;
		}
	}
	Keyboard.println();
}

void byteprint(uint8_t *bytes, int size)
{
#ifdef DEBUG
	Serial.println();
	for (int i = 0; i < size; i++)
	{
		Serial.print(bytes[i], HEX);
		Serial.print(" ");
	}
	Serial.println();
#endif
}

void factorydefault()
{
	uint8_t mode;
	okeeprom_eeget_wipemode(&mode);
	wipeEEPROM(); //Wipe data and go to bootloader after factory default
	if (mode <= 1)
	{
		//Just wipe data
		wipeflashdata();
	}
	else
	{
		//FULLWIPE Mode wipe data and firmware
		wipeflashdata(); //wipe data
		//wipe firmware hash forcing firmware to fail integrity check and be wiped on next boot
		for (int i = 2; i < 67; i++)
		{
			eeprom_write_byte((unsigned char *)i, 0);
		}
#ifdef DEBUG
		uintptr_t adr = 0x0;
		for (int i = 0; i < 65536; i += 4)
		{
			Serial.println(adr, HEX);
			Serial.println(*((unsigned int *)adr), HEX);
			adr = adr + 4;
		}
#endif
		eeprom_write_byte((unsigned char *)0x01, 1); //Firmware ready to load
		eeprom_write_byte(0x00, 1);					 //Go to bootloader
	}
	initialized = false;
	unlocked = true;
#ifdef DEBUG
	Serial.println("factory reset has been completed");
#endif
	hidprint("factory reset has been completed");
	delay(100);
	CPU_RESTART();
}

void wipeEEPROM()
{
	//Erase all EEPROM values
	uint8_t value;
#ifdef DEBUG
	Serial.println("Current EEPROM Values");
	for (int i = 0; i < 2048; i++)
	{
		value = EEPROM.read(i);
		Serial.print(i);
		Serial.print("\t");
		Serial.print(value, DEC);
		Serial.println();
	}
#endif
	value = 0x00;
	for (int i = 66; i < 2048; i++)
	{
		EEPROM.write(i, value);
	}
#ifdef DEBUG
	Serial.println("EEPROM set to 0s");
#endif
	for (int i = 0; i < 2048; i++)
	{
		value = EEPROM.read(i);
#ifdef DEBUG
		Serial.print(i);
		Serial.print("\t");
		Serial.print(value, DEC);
		Serial.println();
#endif
	}
#ifdef DEBUG
	Serial.println("EEPROM erased"); //TODO remove debug
#endif
}

void wipeflashdata()
{
	uintptr_t adr;
	adr = (unsigned long)flashstorestart;
	uintptr_t endadr = flashend;
	while (adr <= endadr - 2048)
	{
#ifdef DEBUG
		Serial.println("Erase Sector");
#endif
		if (flashEraseSector((unsigned long *)adr))
		{
#ifdef DEBUG
			Serial.println("NOT ");
#endif
		}
#ifdef DEBUG
		Serial.println("successful\r\n");
#endif
		adr = adr + 2048; //Next Sector 2048
	}
#ifdef DEBUG
	Serial.println("successful\r\n");
	Serial.println("Flash Sectors erased");
#endif
}


/*************************************/
void okcore_flashget_common(uint8_t *ptr, unsigned long *adr, int len)
{
	for (int z = 0; z <= len - 4; z = z + 4)
	{
		//Serial.println(" 0x%X", (adr));
		*ptr = (uint8_t)((*(adr) >> 24) & 0xFF);
		//Serial.println(" 0x%X", *ptr);
		ptr++;
		*ptr = (uint8_t)((*(adr) >> 16) & 0xFF);
		//Serial.println(" 0x%X", *ptr);
		ptr++;
		*ptr = (uint8_t)((*(adr) >> 8) & 0xFF);
		//Serial.println(" 0x%X", *ptr);
		ptr++;
		*ptr = (uint8_t)((*(adr)&0xFF));
		//Serial.println(" 0x%X", *ptr);
		//Serial.println();
		ptr++;
		adr++;
	}
	return;
}

void okcore_flashset_common(uint8_t *ptr, unsigned long *adr, int len)
{
	for (int z = 0; z <= len - 4; z = z + 4)
	{
		unsigned long data = (uint8_t) * (ptr + z + 3) | ((uint8_t) * (ptr + z + 2) << 8) | ((uint8_t) * (ptr + z + 1) << 16) | ((uint8_t) * (ptr + z) << 24);
		//Write long to sector
		//Serial.println();
		//Serial.println("Writing to Sector 0x%X, value 0x%X ", adr, data);
		if (flashProgramWord((unsigned long *)adr, &data))
		{
#ifdef DEBUG
			Serial.println("NOT ");
#endif
		}
		adr++;
	}
	return;
}


void okcore_flashsector(uint8_t *ptr, unsigned long *adr, int len)
{
//Erase flash sector
#ifdef DEBUG
	Serial.println("Erase Sector");
#endif
	if (flashEraseSector((unsigned long *)adr))
	{
#ifdef DEBUG
		Serial.println("NOT ");
#endif
	}
#ifdef DEBUG
	Serial.println("successful\r\n");
#endif
	//Write buffer to flash
	okcore_flashset_common(ptr, (unsigned long *)adr, len);
}

/*********************************/

int okcore_flashget_noncehash(uint8_t *ptr, int size)
{
	int set = 0;
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
#ifdef DEBUG
	Serial.println("Reading nonce");
#endif
	okcore_flashget_common(ptr, (unsigned long *)adr, size);
	for (int i = 0; i < 32; i++)
	{
		set = *(ptr + i) + set;
	}
#ifdef DEBUG
	Serial.println(set);
#endif
	if (set == 8160)
	{ //0xFF * 32
#ifdef DEBUG
		Serial.println("There is no Nonce hash set");
#endif
		return 0;
	}
	else
	{
		return 1;
	}
}

void okcore_flashset_noncehash(uint8_t *ptr)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	uint8_t temp[255];
	uint8_t *tptr;
	tptr = temp;
	initialized = true;
	//Get current flash contents
	okcore_flashget_common(tptr, (unsigned long *)adr, 254);
	memcpy(nonce, ptr, 32);
	//Add new flash contents
	for (int z = 0; z <= 31; z++)
	{
		temp[z] = ((uint8_t) * (ptr + z));
	}
#ifdef DEBUG
	Serial.print("Nonce hash address =");
	Serial.println(adr, HEX);
	Serial.print("Nonce hash value =");
#endif
	okcore_flashsector(tptr, (unsigned long *)adr, 254);
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_noncehash);
}

int okcore_flashget_pinhashpublic(uint8_t *ptr, int size)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	adr = adr + EElen_noncehash;
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_pinhash);
	if (*ptr == 255 && *(ptr + 1) == 255 && *(ptr + 2) == 255)
	{ //pinhash not set
#ifdef DEBUG
		Serial.println("Read Pin hash");
		Serial.println("There is no Pin hash set");
#endif
		return 0;
	}
	else
	{
#ifdef DEBUG
		Serial.println("Read Pin hash");
		Serial.println("Pin hash has been set");
#endif
		return 1;
	}
}

void okcore_flashset_pinhashpublic(uint8_t *ptr)
{
	uint8_t p2mode;
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	uint8_t temp[255];
	uint8_t secret[32];
	uint8_t *tptr;
	tptr = temp;
	ptr[0] &= 0xF8;
	ptr[31] = (ptr[31] & 0x7F) | 0x40;
	//Generate public key of pinhash 
	Curve25519::eval(p1hash, ptr, 0);
#ifdef DEBUG
	Serial.print("Storing public key of PIN hash =");
	byteprint(p1hash, 32);
#endif
	//Generate shared secret 
	okeeprom_eeget_2ndprofilemode(&p2mode);
	if (p2mode==STDPROFILE2) {
		Curve25519::eval(secret, ptr, p2hash);
	}
	else {
		Curve25519::eval(secret, ptr, p1hash);
	}
	okcore_flashset_profilekey((uint8_t*)secret);
	//Copy public key to ptr for writing to flash
	memcpy(ptr, p1hash, 32);
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 254);
	//Add new flash contents to buffer
	for (int z = 0; z <= 31; z++)
	{
		temp[z + EElen_noncehash] = ((uint8_t) * (ptr + z));
	}
	okcore_flashsector(tptr, (unsigned long *)adr, 254);
#ifdef DEBUG
	Serial.print("Pin hash address =");
	Serial.println(adr, HEX);
#endif
	if (!initcheck) { // First time use
		// Generate and encrypt default key
		recv_buffer[4] = OKSETPRIV;
		recv_buffer[5] = RESERVED_KEY_DERIVATION;
		recv_buffer[6] = 0x61;
		RNG2(recv_buffer + 7, 32);
		set_private(recv_buffer); //set RESERVED_KEY_DERIVATION slot 132
		recv_buffer[5] = RESERVED_KEY_WEB_DERIVATION;
		RNG2(recv_buffer + 7, 32);
		set_private(recv_buffer); //set RESERVED_KEY_WEB_DERIVATION slot 128
		memset(recv_buffer, 0, sizeof(recv_buffer));
	}
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_pinhash);
}
/*********************************/
/*********************************/

int okcore_flashget_selfdestructhash(uint8_t *ptr)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	adr = adr + EElen_noncehash + EElen_pinhash;
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_selfdestructhash);

	if (*ptr == 255 && *(ptr + 1) == 255 && *(ptr + 2) == 255)
	{ //pinhash not set
#ifdef DEBUG
		Serial.println("Read Self-Destruct PIN hash");
		Serial.println("There is no Self-Destruct PIN hash set");
#endif
		return 0;
	}
	else
	{
#ifdef DEBUG
		Serial.println("Read Self-Destruct PIN hash");
		Serial.print("Self-Destruct PIN hash value =");
		byteprint(ptr, 32);
#endif
		return 1;
	}
}

void okcore_flashset_selfdestructhash(uint8_t *ptr)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	uint8_t temp[255];
	uint8_t *tptr;
	tptr = temp;
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 254);
	//Add new flash contents to buffer
	for (int z = 0; z <= 31; z++)
	{
		temp[z + EElen_noncehash + EElen_pinhash] = ((uint8_t) * (ptr + z));
	}
	okcore_flashsector(tptr, (unsigned long *)adr, 254);
#ifdef DEBUG
	Serial.print("Self-Destruct PIN hash address =");
	Serial.println(adr, HEX);
	Serial.print("Self-Destruct PIN hash value =");
	byteprint(ptr, 32);
#endif
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_selfdestructhash);
}

/*********************************/
/*********************************/

int okcore_flashget_2ndpinhashpublic(uint8_t *ptr)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	adr = adr + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash;
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_2ndpinhash);

	if (*ptr == 255 && *(ptr + 1) == 255 && *(ptr + 2) == 255)
	{ //pinhash not set
#ifdef DEBUG
		Serial.println("Read PIN hash");
		Serial.println("There is no PIN hash set");
#endif
		return 0;
	}
	else
	{
#ifdef DEBUG
		Serial.println("Read PIN hash");
		Serial.println("PIN hash has been set");
#endif
		return 1;
	}
}

void okcore_flashset_2ndpinhashpublic(uint8_t *ptr)
{

	uint8_t p2mode;
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	uint8_t temp[255];
	uint8_t secret[32];
	uint8_t *tptr;
	tptr = temp;
	ptr[0] &= 0xF8;
	ptr[31] = (ptr[31] & 0x7F) | 0x40;
	//Generate public key of pinhash
	Curve25519::eval(p2hash, ptr, 0);
	#ifdef DEBUG
	Serial.print("Storing public key of PIN 2 hash =");
	byteprint(p2hash, 32);
	#endif
	okeeprom_eeget_2ndprofilemode(&p2mode);
	if (p2mode != NONENCRYPTEDPROFILE)
	{ //profile key not used for plausible deniability mode or international fw
	#ifdef STD_VERSION
		if (!initcheck) {
			// Default to standard profile
			p2mode = STDPROFILE2;
			okeeprom_eeset_2ndprofilemode(&p2mode);
		}
		okcore_flashget_pinhashpublic(p1hash, 32);	//store PIN hash

		Curve25519::eval(secret, ptr, p1hash); //Generate shared secret of p2hash private key and p1hash public key
		okcore_flashset_profilekey((uint8_t*)secret);
	#endif
	}
	//Copy public key to ptr for writing to flash
	memcpy(ptr, p2hash, 32);
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 254);

	//Add new flash contents to buffer
	for (int z = 0; z <= 31; z++)
	{
		temp[z + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash] = ((uint8_t) * (ptr + z));
	}
	okcore_flashsector(tptr, (unsigned long *)adr, 254);
	#ifdef DEBUG
	Serial.print("PIN hash address =");
	Serial.println(adr, HEX);
	Serial.print("PIN hash value =");
	#endif
	if (p2mode != NONENCRYPTEDPROFILE && !initcheck) // First time use
	{
	#ifdef STD_VERSION
		// Generate and encrypt default key
		recv_buffer[4] = OKSETPRIV;
		recv_buffer[5] = RESERVED_KEY_DERIVATION;
		recv_buffer[6] = 0x61;
		RNG2(recv_buffer + 7, 32);
		set_private(recv_buffer); //set RESERVED_KEY_DERIVATION slot 132
		recv_buffer[5] = RESERVED_KEY_WEB_DERIVATION;
		RNG2(recv_buffer + 7, 32);
		set_private(recv_buffer); //set RESERVED_KEY_WEB_DERIVATION slot 128
		memset(recv_buffer, 0, sizeof(recv_buffer));
	#endif
	}
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_2ndpinhash);
}

int okcore_flashget_profilekey(uint8_t *ptr)
{
	int set = 0;
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	adr = adr + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash + EElen_2ndpinhash;

#ifdef DEBUG
	Serial.println("Reading profilekey");
#endif
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_profilekey);
	for (int i = 0; i < 32; i++)
	{
		set = *(ptr + i) + set;
	}
#ifdef DEBUG
	Serial.println(set);
#endif
	if (set == 8160)
	{ //0xFF * 32
#ifdef DEBUG
		Serial.println("There is no Profilekey hash set");
#endif
		return 0;
	}
	else
	{
		return 1;
	}
}

void okcore_flashset_profilekey(uint8_t *secret)
{
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	uint8_t temp[255];
	uint8_t nonce2[32];
	uint8_t *ptr;
	uint8_t *tptr;
	tptr = temp;

	SHA256_CTX pinhash;
	sha256_init(&pinhash); 
	okeeprom_eeget_nonce2((uint8_t*)nonce2);
	sha256_update(&pinhash, nonce2, sizeof(nonce2)); //Add mask (eeprom)
	sha256_update(&pinhash, (uint8_t*)ID, 16); //Add chip ID (ROM)
	sha256_update(&pinhash, secret, 32); //Add generated shared secret
	sha256_update(&pinhash, nonce, 32); //Add nonce to hash
	sha256_final(&pinhash, temp); //Create hash and store in temp
	if (!okcore_flashget_pinhashpublic(secret,32)) { //first time use, set random profilekey
		RNG2(profilekey, 32);
	} 
	
	memcpy(secret, profilekey, 32);
	if (profilemode != NONENCRYPTEDPROFILE)
	{
	#ifdef STD_VERSION
	okcrypto_aes_gcm_encrypt2(secret, (uint8_t*)ID, temp, 32, true);
	#endif
	}
	ptr=secret;
	
	//Get current flash contents
	okcore_flashget_common(tptr, (unsigned long *)adr, 254);
	//Add new flash contents
	//Add new flash contents to buffer
	for (int z = 0; z <= 31; z++)
	{
		temp[z + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash + EElen_2ndpinhash] = ((uint8_t) * (ptr + z));
	}
	#ifdef DEBUG
	Serial.print("profilekey hash address =");
	Serial.println(adr, HEX);
	Serial.print("profilekey hash value =");
	#endif
	okcore_flashsector(tptr, (unsigned long *)adr, 254);
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_profilekey);
}

int okcore_flashget_url(uint8_t *ptr, int slot)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 4096; //3rd free sector
	switch (slot)
	{
		uint8_t length;
		int size;
	case 1:
		okeeprom_eeget_urllen1(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 2:
		okeeprom_eeget_urllen2(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 3:
		okeeprom_eeget_urllen3(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 4:
		okeeprom_eeget_urllen4(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 5:
		okeeprom_eeget_urllen5(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 6:
		okeeprom_eeget_urllen6(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 7:
		okeeprom_eeget_urllen7(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 8:
		okeeprom_eeget_urllen8(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 9:
		okeeprom_eeget_urllen9(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 10:
		okeeprom_eeget_urllen10(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 11:
		okeeprom_eeget_urllen11(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 12:
		okeeprom_eeget_urllen12(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 13:
		okeeprom_eeget_urllen13(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 14:
		okeeprom_eeget_urllen14(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 15:
		okeeprom_eeget_urllen15(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 16:
		okeeprom_eeget_urllen16(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 17:
		okeeprom_eeget_urllen17(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 18:
		okeeprom_eeget_urllen18(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 19:
		okeeprom_eeget_urllen19(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 20:
		okeeprom_eeget_urllen20(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 21:
		okeeprom_eeget_urllen21(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 22:
		okeeprom_eeget_urllen22(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 23:
		okeeprom_eeget_urllen23(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	case 24:
		okeeprom_eeget_urllen24(&length);
		size = (int)length;
		if (size > EElen_url)
			size = EElen_url;
		adr = adr + ((EElen_url * slot) - EElen_url);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_url);
		return size;
	}

	return 0;
}

void okcore_flashset_url(uint8_t *ptr, int size, int slot)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 4096; //3rd free sector
	uint8_t temp[2048];
	uint8_t *tptr;
	tptr = temp;
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
	//Add new flash contents to buffer
	for (int z = 0; z < EElen_url; z++)
	{
		temp[z + ((EElen_url * slot) - EElen_url)] = ((uint8_t) * (ptr + z));
	}
	//Erase flash sector
#ifdef DEBUG
	Serial.println("Erase Sector");
#endif
	if (flashEraseSector((unsigned long *)adr))
	{
#ifdef DEBUG
		Serial.println("NOT ");
#endif
	}
#ifdef DEBUG
	Serial.println("successful\r\n");
#endif
	switch (slot)
	{
		uint8_t length;
	case 1:
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen1(&length);
		return;
	case 2:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen2(&length);
		return;
	case 3:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen3(&length);
		return;
	case 4:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen4(&length);
		return;
	case 5:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen5(&length);
		return;
	case 6:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen6(&length);
		return;
	case 7:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen7(&length);
		return;
	case 8:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen8(&length);
		return;
	case 9:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen9(&length);
		return;
	case 10:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen10(&length);
		return;
	case 11:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen11(&length);
		return;
	case 12:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen12(&length);
		return;
	case 13:
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen13(&length);
		return;
	case 14:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen14(&length);
		return;
	case 15:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen15(&length);
		return;
	case 16:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen16(&length);
		return;
	case 17:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen17(&length);
		return;
	case 18:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen18(&length);
		return;
	case 19:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen19(&length);
		return;
	case 20:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen20(&length);
		return;
	case 21:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen21(&length);
		return;
	case 22:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen22(&length);
		return;
	case 23:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen23(&length);
		return;
	case 24:
		if (size > EElen_url)
			size = EElen_url;
		if (size > EElen_url)
			size = EElen_url;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_urllen24(&length);
		return;
	}
	return;
}

/*********************************/

int okcore_flashget_username(uint8_t *ptr, int slot)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 6144; //4th free sector
	switch (slot)
	{
		uint8_t length;
		int size;
	case 1:
		okeeprom_eeget_usernamelen1(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;
	case 2:
		okeeprom_eeget_usernamelen2(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;
	case 3:
		okeeprom_eeget_usernamelen3(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;
	case 4:
		okeeprom_eeget_usernamelen4(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 5:
		okeeprom_eeget_usernamelen5(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 6:
		okeeprom_eeget_usernamelen6(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 7:
		okeeprom_eeget_usernamelen7(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 8:
		okeeprom_eeget_usernamelen8(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 9:
		okeeprom_eeget_usernamelen9(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 10:
		okeeprom_eeget_usernamelen10(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 11:
		okeeprom_eeget_usernamelen11(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 12:
		okeeprom_eeget_usernamelen12(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 13:
		okeeprom_eeget_usernamelen13(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 14:
		okeeprom_eeget_usernamelen14(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 15:
		okeeprom_eeget_usernamelen15(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 16:
		okeeprom_eeget_usernamelen16(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 17:
		okeeprom_eeget_usernamelen17(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 18:
		okeeprom_eeget_usernamelen18(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 19:
		okeeprom_eeget_usernamelen19(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 20:
		okeeprom_eeget_usernamelen20(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 21:
		okeeprom_eeget_usernamelen21(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 22:
		okeeprom_eeget_usernamelen22(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 23:
		okeeprom_eeget_usernamelen23(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;

	case 24:
		okeeprom_eeget_usernamelen24(&length);
		size = (int)length;
		if (size > EElen_username)
			size = EElen_username;
		adr = adr + ((EElen_username * slot) - EElen_username);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_username);
		return size;
	}

	return 0;
}

void okcore_flashset_username(uint8_t *ptr, int size, int slot)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 6144; //4th free sector
	uint8_t temp[2048];
	uint8_t *tptr;
	tptr = temp;
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
	//Add new flash contents to buffer
	for (int z = 0; z < EElen_username; z++)
	{
		temp[z + ((EElen_username * slot) - EElen_username)] = ((uint8_t) * (ptr + z));
	}
	//Erase flash sector
#ifdef DEBUG
	Serial.println("Erase Sector");
#endif
	if (flashEraseSector((unsigned long *)adr))
	{
#ifdef DEBUG
		Serial.println("NOT ");
#endif
	}
#ifdef DEBUG
	Serial.println("successful\r\n");
#endif
	switch (slot)
	{
		uint8_t length;
	case 1:
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen1(&length);
		return;
	case 2:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen2(&length);
		return;
	case 3:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen3(&length);
		return;
	case 4:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen4(&length);
		return;
	case 5:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen5(&length);
		return;
	case 6:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen6(&length);
		return;
	case 7:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen7(&length);
		return;
	case 8:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen8(&length);
		return;
	case 9:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen9(&length);
		return;
	case 10:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen10(&length);
		return;
	case 11:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen11(&length);
		return;
	case 12:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen12(&length);
		return;
	case 13:
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen13(&length);
		return;
	case 14:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen14(&length);
		return;
	case 15:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen15(&length);
		return;
	case 16:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen16(&length);
		return;
	case 17:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen17(&length);
		return;
	case 18:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen18(&length);
		return;
	case 19:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen19(&length);
		return;
	case 20:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen20(&length);
		return;
	case 21:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen21(&length);
		return;
	case 22:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen22(&length);
		return;
	case 23:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen23(&length);
		return;
	case 24:
		if (size > EElen_username)
			size = EElen_username;
		if (size > EElen_username)
			size = EElen_username;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_usernamelen24(&length);
		return;
	}
	return;
}

/*********************************/

void okcore_flashget_label(uint8_t *ptr, uint8_t slot)
{
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 8192; //5th free sector
	if (slot > 127) // Only 24 + 4 + 32 in use for slot and key labels
		return;
	adr = adr + ((EElen_label * slot) - EElen_label);
	okcore_flashget_common(ptr, (unsigned long *)adr, EElen_label);
}

void okcore_flashset_label(uint8_t *ptr, uint8_t slot)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 8192; //5th free sector
	uint8_t temp[2048];
	uint8_t *tptr;
	tptr = temp;
	if (slot > 127)
		return;
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
	//Add new flash contents to buffer
	for (int z = 0; z < EElen_label; z++)
	{
		temp[z + ((EElen_label * slot) - EElen_label)] = ((uint8_t) * (ptr + z));
	}

	//Erase flash sector
	if (*ptr != 0x00)
	{ //No need to erase sector if wiping slot
#ifdef DEBUG
		Serial.println("Erase Sector");
#endif
		if (flashEraseSector((unsigned long *)adr))
		{
#ifdef DEBUG
			Serial.println("NOT ");
#endif
		}
#ifdef DEBUG
		Serial.println("successful\r\n");
#endif
	}
	okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
	return;
}

/*********************************/

int okcore_flashget_2fa_key(uint8_t *ptr, int slot)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 10240; //6th flash sector
	switch (slot)
	{
		uint8_t length;
		int size;
	case 1:
		okeeprom_eeget_totpkeylen1(&length);
		size = (int)length;
		if (size > EElen_totpkey) 
			size = EElen_totpkey;
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 2:
		okeeprom_eeget_totpkeylen2(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 3:
		okeeprom_eeget_totpkeylen3(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 4:
		okeeprom_eeget_totpkeylen4(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 5:
		okeeprom_eeget_totpkeylen5(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 6:
		okeeprom_eeget_totpkeylen6(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 7:
		okeeprom_eeget_totpkeylen7(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 8:
		okeeprom_eeget_totpkeylen8(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 9:
		okeeprom_eeget_totpkeylen9(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 10:
		okeeprom_eeget_totpkeylen10(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 11:
		okeeprom_eeget_totpkeylen11(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 12:
		okeeprom_eeget_totpkeylen12(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 13:
		okeeprom_eeget_totpkeylen13(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 14:
		okeeprom_eeget_totpkeylen14(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 15:
		okeeprom_eeget_totpkeylen15(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 16:
		okeeprom_eeget_totpkeylen16(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 17:
		okeeprom_eeget_totpkeylen17(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 18:
		okeeprom_eeget_totpkeylen18(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 19:
		okeeprom_eeget_totpkeylen19(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 20:
		okeeprom_eeget_totpkeylen20(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 21:
		okeeprom_eeget_totpkeylen21(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 22:
		okeeprom_eeget_totpkeylen22(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 23:
		okeeprom_eeget_totpkeylen23(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;

	case 24:
		okeeprom_eeget_totpkeylen24(&length);
		size = (int)length;
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		adr = adr + ((EElen_totpkey * slot) - EElen_totpkey);
		okcore_flashget_common(ptr, (unsigned long *)adr, EElen_totpkey);
		return size;
	}

	return 0;
}

void okcore_flashset_2fa_key(uint8_t *ptr, int size, int slot)
{

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 10240; //6th flash sector
	uint8_t temp[2048];
	uint8_t *tptr;
	tptr = temp;
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
	//Add new flash contents to buffer
	for (int z = 0; z < EElen_totpkey; z++)
	{
		temp[z + ((EElen_totpkey * slot) - EElen_totpkey)] = ((uint8_t) * (ptr + z));
	}
	//Erase flash sector
#ifdef DEBUG
	Serial.println("Erase Sector");
#endif
	if (flashEraseSector((unsigned long *)adr))
	{
#ifdef DEBUG
		Serial.println("NOT ");
#endif
	}
#ifdef DEBUG
	Serial.println("successful\r\n");
#endif
	switch (slot)
	{
		uint8_t length;
	case 1:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen1(&length);
		return;
	case 2:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen2(&length);
		return;
	case 3:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen3(&length);
		return;
	case 4:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen4(&length);
		return;
	case 5:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen5(&length);
		return;
	case 6:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen6(&length);
		return;
	case 7:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen7(&length);
		return;
	case 8:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen8(&length);
		return;
	case 9:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen9(&length);
		return;
	case 10:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen10(&length);
		return;
	case 11:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen11(&length);
		return;
	case 12:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen12(&length);
		return;
	case 13:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen13(&length);
		return;
	case 14:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen14(&length);
		return;
	case 15:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen15(&length);
		return;
	case 16:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen16(&length);
		return;
	case 17:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen17(&length);
		return;
	case 18:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen18(&length);
		return;
	case 19:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen19(&length);
		return;
	case 20:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen20(&length);
		return;
	case 21:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen21(&length);
		return;
	case 22:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen22(&length);
		return;
	case 23:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen23(&length);
		return;
	case 24:
		if (size > EElen_totpkey)
			size = EElen_totpkey;
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		length = (uint8_t)size;
		okeeprom_eeset_totpkeylen24(&length);
		return;
	}
	return;
}

void okcore_flashget_yubiotp(uint8_t *ptr, uint8_t slot) {
	okcore_flashget_2fa_key(ptr, slot);
	memset(ptr+38, 0, 26);
}

uint8_t okcore_flashget_hmac(uint8_t *ptr, uint8_t slot) {
	if (profilemode == NONENCRYPTEDPROFILE) return 0;
	#ifdef STD_VERSION
	uint8_t tempbuf[64];
	okeeprom_eeget_2FAtype(&type, slot);
	if (type == MFAHMACSHA1 || type == MFAYUBIOTPandHMACSHA1) {
		okcore_flashget_2fa_key(tempbuf, slot);
		okcore_aes_gcm_decrypt(tempbuf+43, slot, 29, profilekey, 21);
		memmove(ptr, tempbuf+44, 20);
		type = KEYTYPE_HMACSHA1;
		if (tempbuf[43] == 1) return 1;
	}
	return 0;
	#endif
}

void set_private(uint8_t *buffer)
{
	uint8_t backupkeymode = 0;
	uint8_t backupkeyslot = 0;
	integrityctr2++;
	okeeprom_eeget_backupkey(&backupkeyslot);
	integrityctr1++;
	okeeprom_eeget_backupkeymode(&backupkeymode);
	integrityctr2++;
	//Serial.println("Backup key slot and key mode");
	//Serial.println(backupkeyslot);
	//Serial.println(backupkeymode);
	#ifdef DEBUG
	Serial.print("Profile Key "); 
	byteprint(profilekey, 32);
	#endif
	if ((buffer[6] > 0x80 && backupkeymode && initcheck) || (backupkeymode && backupkeyslot == buffer[5] && initcheck))
	{
		hidprint("Error backup key mode set to locked");
		integrityctr1++;
		return;
	}
	integrityctr1++;
	if (profilemode == NONENCRYPTEDPROFILE)
		return;
#ifdef STD_VERSION
	if (buffer[6] > 0x80)
	{ //Type is Backup key
		buffer[6] = buffer[6] - 0x80;
		okeeprom_eeset_backupkey(buffer + 5); //Set this key slot as the backup key
	}

	if (buffer[5] <= 4 && buffer[5] >= 1)
	{
		rsa_priv_flash(buffer, false);
	}
	else
	{
		ecc_priv_flash(buffer, false);
	}
#endif
}

void wipe_private(uint8_t *buffer, bool response)
{
	if (profilemode == NONENCRYPTEDPROFILE)
		return;
#ifdef STD_VERSION
	if (buffer[5] <= 4 && buffer[5] >= 1)
	{
		rsa_priv_flash(buffer, response);
	}
	else
	{
		for (int i = 6; i <= 38; i++)
		{
			buffer[i] = 0x00;
		}

		ecc_priv_flash(buffer, response);
	}
#endif
}

int okcore_flashget_ECC(uint8_t slot)
{

	if (profilemode == NONENCRYPTEDPROFILE)
		return 0;
#ifdef STD_VERSION
#ifdef DEBUG
	Serial.print("Flashget ECC key from slot # ");
	Serial.println(slot);
#endif
	extern uint8_t type;
	uint8_t features;
	if (slot < 101 || slot > 132)
	{
#ifdef DEBUG
		Serial.println("Error invalid ECC slot");
#endif
		hidprint("Error invalid ECC slot");
		return 0;
	}
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 14336; //8th free flash sector
	okeeprom_eeget_ecckey(&type, slot); //Key Type (1-3) and slot (101-132)
#ifdef DEBUG
	Serial.print("Type of ECC KEY with features is ");
	Serial.println(type);
#endif
	features = type;
	if (type == 0x00)
	{
#ifdef DEBUG
		Serial.println("Error no ECC Private Key set in this slot");
#endif
		hidprint("Error no ECC Private Key set in this slot");
		if (outputmode)
		{
			fadeoff(1);
		}
		else if (NEO_Color != 45 && NEO_Color != 43)
		{
			NEO_Color = 1;
			blink(2);
		}
		return 0;
	}
	else
	{
		type = (type & 0x0F);
	}
	adr = adr + (((slot - 100) * 32) - 32);
	okcore_flashget_common((uint8_t *)ecc_private_key, (unsigned long *)adr, 32);
	okcore_aes_gcm_decrypt(ecc_private_key, slot, features, profilekey, 32);
#ifdef DEBUG
	Serial.println("Read ECC Private Key");
#endif
	okcrypto_compute_pubkey();
#ifdef DEBUG
	Serial.println("Compute of public key complete");
#endif
	return features;
#endif
	return 0;
}

void ecc_priv_flash(uint8_t *buffer, bool wipe)
{

	if (profilemode == NONENCRYPTEDPROFILE)
		return;
#ifdef STD_VERSION
#ifdef DEBUG
	Serial.println("OKSETECCPRIV MESSAGE RECEIVED");
#endif
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 14336; //8th free flash sector
	//Write ID to EEPROM

	if (buffer[5] < 101 || buffer[5] > 132 || ((buffer[5] == RESERVED_KEY_DERIVATION || buffer[5] == RESERVED_KEY_WEB_DERIVATION) && configmode == false && initcheck))
	{
#ifdef DEBUG
		Serial.println("Error invalid ECC slot");
#endif
		hidprint("Error invalid ECC slot");
		return;
	}
	else
	{
#ifdef DEBUG
		Serial.println("Slot = ");
		Serial.println(buffer[5]);
		Serial.println("Type = ");
		Serial.println(buffer[6]);
#endif
	}
	okeeprom_eeset_ecckey(&buffer[6], (int)buffer[5]); //Key Type (1-4) and slot (101-132)
													  //Write buffer to flash
	uint8_t temp[2048];
	uint8_t *tptr;
	tptr = temp;
	int gen_key = buffer[7] + buffer[8] + buffer[9] + buffer[10] + buffer[11] + buffer[12] + buffer[13] + buffer[14];
	if (gen_key == 2040)
	{ //All FFs, trigger to generate a randomly generated key
		okcrypto_generate_random_key(buffer);
	}
#ifdef DEBUG
	Serial.print("ECC Key value =");
	byteprint((uint8_t *)buffer + 7, 32);
#endif
	okcore_aes_gcm_encrypt(buffer + 7, buffer[5], buffer[6], profilekey, 32);
	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
	//Add new flash contents to buffer
	for (int z = 0; z < MAX_ECC_KEY_SIZE; z++)
	{
		temp[z + (((buffer[5] - 100) * MAX_ECC_KEY_SIZE) - MAX_ECC_KEY_SIZE)] = buffer[7 + z];
	}
	//Erase flash sector
#ifdef DEBUG
	Serial.println("Erase Sector");
#endif
	if (flashEraseSector((unsigned long *)adr))
	{
#ifdef DEBUG
		Serial.println("NOT ");
#endif
	}
#ifdef DEBUG
	Serial.println("successful\r\n");
#endif
	//Write buffer to flash
	okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
#ifdef DEBUG
	Serial.println(buffer[5]);
#endif
	if (buffer[5] == 131)
	{ //Designated Backup Passphrase slot
		hidprint("Successfully set Backup Passphrase");
	}
	else if (gen_key != 0 && initcheck)
	{
		hidprint("Successfully set ECC Key");
		if (buffer[0] != 0xBA) 
			blink(2);
	} else if (wipe) {
		hidprint("Successfully wiped ECC Key");
		blink(2);
	}
#endif
	return;
}

int okcore_flashget_RSA(uint8_t slot)
{

	if (profilemode == NONENCRYPTEDPROFILE)
		return 0;
#ifdef STD_VERSION
#ifdef DEBUG
	Serial.print("Flashget RSA key from slot # ");
	Serial.println(slot);
#endif
	extern uint8_t type;
	uint8_t features;
	if (slot < 1 || slot > 4)
	{
#ifdef DEBUG
		Serial.println("Error invalid RSA slot");
#endif
		hidprint("Error invalid RSA slot");
		return 0;
	}
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 16384; //9th free flash sector
	okeeprom_eeget_rsakey(&type, slot); //Key Type (1-4) and slot (1-4)
	features = type;
	if (type == 0x00)
	{
#ifdef DEBUG
		Serial.println("Error no RSA Private Key set in this slot");
#endif
		hidprint("Error no RSA Private Key set in this slot");
		if (outputmode)
		{
			fadeoff(1);
		}
		else if (NEO_Color != 45)
		{
			NEO_Color = 1;
			blink(2);
		}
		return 0;
	}
	else
	{
		type = (type & 0x0F);
	}
#ifdef DEBUG
	Serial.print("Type of RSA KEY is ");
	Serial.println(type, HEX);
#endif
	adr = adr + ((slot * MAX_RSA_KEY_SIZE) - MAX_RSA_KEY_SIZE);
	okcore_flashget_common((uint8_t *)rsa_private_key, (unsigned long *)adr, (type * 128));
	okcore_aes_gcm_decrypt(rsa_private_key, slot, features, profilekey, (type * 128));
#ifdef DEBUG
	Serial.println("Read RSA Private Key");
	byteprint(rsa_private_key, (type * 128));
#endif
	rsa_getpub(type);
	return features;
#endif
	return 0;
}

void rsa_priv_flash(uint8_t *buffer, bool wipe)
{

	if (profilemode == NONENCRYPTEDPROFILE)
		return;
	#ifdef STD_VERSION
	#ifdef DEBUG
	Serial.println("OKSETRSAPRIV MESSAGE RECEIVED");
	#endif
	extern uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
	int keysize;
	uint8_t temp[2048];
	uint8_t *tptr;
	tptr = temp;
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 16384; //9th free flash sector
	if (wipe)
	{
		//Copy current flash contents to buffer
		okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
		//Wipe content from buffer
		flash_modify(buffer[5], temp, buffer, MAX_RSA_KEY_SIZE, 1);
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);
		hidprint("Successfully wiped RSA Private Key");
		blink(2);
		return;
	}
	if (buffer[5] < 1 || buffer[5] > 4)
	{
	#ifdef DEBUG
		Serial.println("Error invalid RSA slot");
	#endif
		hidprint("Error invalid RSA slot");
		return;
	}
	else
	{
	#ifdef DEBUG
		Serial.println("Slot = ");
		Serial.println(buffer[5]);
		Serial.println("Type = ");
		Serial.println(buffer[6]);
	#endif
	}
	if ((buffer[6] & 0x0F) == 1) //Expect 128 Bytes, if buffer[0] != FF we know this is import from backup
	{
		keysize = 128;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 114)
		{
			memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, 57);
			packet_buffer_offset = packet_buffer_offset + 57;
		}
	}
	else if ((buffer[6] & 0x0F) == 2)
	{ //Expect 256 Bytes
		keysize = 256;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 228)
		{
			memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, 57);
			packet_buffer_offset = packet_buffer_offset + 57;
		}
	}
	else if ((buffer[6] & 0x0F) == 3)
	{ //Expect 384 Bytes
		keysize = 384;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 342)
		{
			memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, 57);
			packet_buffer_offset = packet_buffer_offset + 57;
		}
	}
	else if ((buffer[6] & 0x0F) == 4)
	{ //Expect 512 Bytes
		keysize = 512;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 456)
		{
			memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, 57);
			packet_buffer_offset = packet_buffer_offset + 57;
		}
	}
	else
	{
		hidprint("Error invalid RSA type");
		return;
	}
	//Write ID to EEPROM
	if (packet_buffer_offset >= keysize || buffer[0] == 0xBA)
	{ //Then we have the complete RSA key
		if (buffer[0] == 0xBA)
		{
			memcpy(rsa_private_key, buffer + 7, keysize);
		}
		okeeprom_eeset_rsakey(&buffer[6], (int)buffer[5]); //Key Type (1-4) and slot (1-4)
														  //Write buffer to flash
		#ifdef DEBUG
		Serial.print("Received RSA Key of size ");
		Serial.print(keysize * 8);
		Serial.print("RSA Key value =");
		byteprint((uint8_t *)rsa_private_key, keysize);
		#endif
		okcore_aes_gcm_encrypt(rsa_private_key, buffer[5], buffer[6], profilekey, keysize);
		//Copy current flash contents to buffer
		okcore_flashget_common(tptr, (unsigned long *)adr, 2048);
		//Add new flash contents to buffer
		for (int z = 0; z < MAX_RSA_KEY_SIZE; z++)
		{
			temp[z + ((buffer[5] * MAX_RSA_KEY_SIZE) - MAX_RSA_KEY_SIZE)] = rsa_private_key[z];
		}
		//Erase flash sector
		#ifdef DEBUG
		Serial.println("Erase Sector");
		#endif
		if (flashEraseSector((unsigned long *)adr))
		{
		#ifdef DEBUG
			Serial.println("NOT ");
		#endif
		}
		#ifdef DEBUG
		Serial.println("successful\r\n");
		#endif
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, 2048);

		packet_buffer_offset = 0;
		hidprint("Successfully set RSA Key");
		if (buffer[0] != 0xBA)
			blink(2);
	}
#endif
	return;
}

// Store auth state in EEPROM, RKs 1-4 in 7th flash sector, RKs 5-8 in 10th flash sector, RKs 9-12 in 11th flash sector
int ctap_flash(int index, uint8_t *buffer, int size, uint8_t mode)
{
	#ifdef STD_VERSION
	uintptr_t adr = (unsigned long)flashstorestart;
	uint8_t temp[2048]; 
	uint8_t *tptr;
	int slot;
	tptr = temp;
	#ifdef DEBUG
	Serial.print("CTAP Flash mode= ");
	Serial.println(mode);
	Serial.print("Buffer Size= ");
	Serial.println(size);
	#endif
	if (mode == 5)
	{ // wipe RKs
		#ifdef DEBUG
		Serial.print("Wiping all resident keys!");
		#endif
		adr = adr + 12288; //7th free flash sector
		flashEraseSector((unsigned long *)adr); 
		delay(10);
		adr = adr + 6144; //10th free flash sector
		flashEraseSector((unsigned long *)adr);
		delay(10);
		adr = adr + 2048; //11th free flash sector
		flashEraseSector((unsigned long *)adr);
		delay(10);
		return 0;
	}
	else if (mode == 3)
	{ // read auth state from EEPROM
		okeeprom_eeget_ctap_authstate(buffer);
		if (buffer[0]==0 && buffer[1]==0 && buffer[3]==0 && buffer[4]==0 && buffer[5]==0) return 0;
		okcore_aes_gcm_decrypt(buffer, 0, 255, profilekey, size);
		return 1;
	}
	else if (mode == 4)
	{ // write auth state to EEPROM
		okcore_aes_gcm_decrypt(buffer, 0, 255, profilekey, size);
		okeeprom_eeset_ctap_authstate(buffer);
		return 0;
	}
	#ifdef DEBUG
	Serial.print("RK Index = ");
	Serial.println(index);
	#endif
	// Max size RK 512, Solo uses 441
	// Support 12 RKs for now, 0-11
	if (index > 11 || index < 0 || size > 512)
		return 0;
	else 
		index++; // 1-12 instead of 0-11

	slot=index;

	if (index<5) {
		adr = adr + 12288; //7th free flash sector
	} else if (index<9) {
		adr = adr + 18432; //10th free flash sector
		index-=4;
	} else if (index<13) {
		adr = adr + 20480; //11th free flash sector
		index-=8;
	} 

	//Copy current flash contents to buffer
	okcore_flashget_common(tptr, (unsigned long *)adr, sizeof(temp));
	//Add new flash contents to buffer

	memset(rsa_private_key, 0, sizeof(rsa_private_key));
	memcpy(rsa_private_key, buffer, size);
	if (mode == 1)
	{ // read RK
		memcpy(rsa_private_key, tptr + ((index * 512) - 512), 512);
		// Solo checks value in buffer to see if there is resident key (if rk->id.count > 0 && rk->id.count != 0xffffffff)
		memcpy(buffer, tptr + ((index * 512) - 512), size);
		if (rsa_private_key[0]==0xff && rsa_private_key[1]==0xff && rsa_private_key[3]==0xff && rsa_private_key[4]==0xff) return 0;
		if (rsa_private_key[0]==0 && rsa_private_key[1]==0 && rsa_private_key[3]==0 && rsa_private_key[4]==0) return 0;
		okcore_aes_gcm_decrypt(rsa_private_key, 0, (255-slot), profilekey, 512);
		memcpy(buffer, rsa_private_key, size);
		memset(rsa_private_key, 0, sizeof(rsa_private_key));
		#ifdef DEBUG
		Serial.print("CTAP value =");
		//byteprint(buffer, size);
		#endif
		return 0;
	}
	else if (mode == 2)
	{
		okcore_aes_gcm_encrypt(rsa_private_key, 0, (255-slot), profilekey, 512);
		flash_modify(index, temp, rsa_private_key, 512, 0); //write RK
		memset(rsa_private_key, 0, sizeof(rsa_private_key));

		if (flashEraseSector((unsigned long *)adr))
		{
			#ifdef DEBUG
			Serial.println("NOT ");
			#endif
		}
		#ifdef DEBUG
		Serial.println("successful");
		#endif
		//Write buffer to flash
		okcore_flashset_common(tptr, (unsigned long *)adr, sizeof(temp));
		#ifdef DEBUG
		Serial.print("CTAP address =");
		Serial.println(adr, HEX);
		Serial.print("CTAP value =");
		//byteprint(buffer, size);
		#endif
		//hidprint("Successfully set CTAP Value");
	}
	#endif
}

void flash_modify(int index, uint8_t *sector, uint8_t *data, int size, bool wipe)
{
	for (int z = 0; z < size; z++)
	{
		if (wipe == 1)
			sector[z + ((index * size) - size)] = 0;
		else
			sector[z + ((index * size) - size)] = data[z];
	}
}

/*************************************/
//Initialize Yubico OTP
/*************************************/
void yubikeyinit(uint8_t slot)
{
	if (profilemode == NONENCRYPTEDPROFILE)
		return;
	#ifdef STD_VERSION
	uint32_t seed;
	uint8_t *ptr = (uint8_t *)&seed;
	RNG2((uint8_t *)&seed, 4); //Seed with random data

	uint8_t temp[64];
	uint8_t yaeskey[16];
	uint8_t privID[6];
	uint8_t pubID[17] = {0};
	uint8_t ctr[2];
	uint16_t counter;
	uint16_t usage;
	char public_id[32 + 1];
	char private_id[12 + 1];
	uint8_t publen = 16; // Max public size

	#ifdef DEBUG
	Serial.print("Initializing YubiKey OTP for slot ");
	Serial.println(slot);
	#endif
	memset(temp, 0, sizeof(temp)); //Clear temp buffer

	ptr = temp;

	if (slot == 0) {
		okeeprom_eeget_public_DEPRICATED(ptr);
		ptr = (temp + EElen_public);
		okeeprom_eeget_private_DEPRICATED(ptr);
		ptr = (temp + EElen_public + EElen_private);
		okeeprom_eeget_aeskey_DEPRICATED(ptr);
		okcore_aes_gcm_decrypt(temp, slot, 10, profilekey, (EElen_aeskey + EElen_private + EElen_public));
		memcpy(pubID, temp, 6); // Old Yubikey method only supports default 6 len pubkey
		memcpy(privID, temp+EElen_public, 6);
		memcpy(yaeskey, temp+EElen_public+EElen_private, EElen_aeskey);
		yubikey_hex_encode(public_id, (char *)pubID, 6);
	} else if (slot > 0 && slot < 25) {
		okcore_flashget_yubiotp(ptr, slot);
		okcore_aes_gcm_decrypt(temp, slot, 10, profilekey, (EElen_aeskey + EElen_private + 16));
		for (int i = 37; i > 1; i--) { // Public ID 2-16 bytes
			 if (temp[i]!=0) {
				 break;
			 }
			 publen--;
		}
		memcpy(pubID, temp, publen);
		memcpy(privID, temp+publen, 6);
		memcpy(yaeskey, temp+publen+EElen_private, EElen_aeskey);
		yubikey_hex_encode(public_id, (char *)pubID, publen);
		ctx.publen = publen;
	}

	yubikey_hex_encode(private_id, (char *)privID, 6);

	#ifdef DEBUG
	Serial.println("public_id");
	byteprint(pubID, publen);
	Serial.println("private_id");
	byteprint(privID, 6);
	Serial.println("aes key");
	byteprint(yaeskey, 16);
	
	#endif

	memset(temp, 0, sizeof(temp)); //Clear temp buffer

	yubikey_eeget_counter(ctr, slot);
	counter = ctr[0] << 8 | ctr[1];
	uint32_t time = 0x010203;
	usage = ctx.usage;
	
	yubikey_init1(&ctx, yaeskey, public_id, private_id, counter, time, seed);
	ctx.usage = usage + 1;
	#endif
}
/*************************************/
//Generate Yubico OTP
/*************************************/
int yubikeysim(char *ptr, uint8_t slot)
{
	if (profilemode == NONENCRYPTEDPROFILE)
		return 0;
	#ifdef STD_VERSION
	uint8_t ctr[2];
	yubikeyinit(slot);
	yubikey_incr_counter(&ctx, slot);
	ctr[0] = ctx.counter >> 8 & 0xFF;
	ctr[1] = ctx.counter & 0xFF;
	yubikey_eeset_counter(ctr, slot);
	yubikey_simulate1(ptr, &ctx);
	return ctx.publen;
	#endif
}
/*************************************/
//Increment Yubico timestamp
/*************************************/
void yubikey_incr_time()
{
	if (profilemode == NONENCRYPTEDPROFILE)
		return;
	#ifdef STD_VERSION
	yubikey_incr_timestamp(&ctx);
	#endif
}

void increment(Task *me)
{
	#ifndef OK_Color
	analogWrite(BLINKPIN, fade);
	#else
	if (NEO_Color == 1) {
		pixels.setPixelColor(0, pixels.Color(fade, 0, 0)); //Red
		pixels.setPixelColor(1, pixels.Color(fade, 0, 0)); //Red
	} else if (NEO_Color < 44) {
		pixels.setPixelColor(0, pixels.Color((fade / 2), (fade / 2), 0)); //Yellow
		pixels.setPixelColor(1, pixels.Color((fade / 2), (fade / 2), 0)); //Yellow
	} else if (NEO_Color < 86) { 
		pixels.setPixelColor(0, pixels.Color(0, fade, 0)); //Green
		pixels.setPixelColor(1, pixels.Color(0, fade, 0)); //Green
	} else if (NEO_Color < 129) {
		pixels.setPixelColor(0, pixels.Color(0, (fade / 2), (fade / 2))); //Turquoise
		pixels.setPixelColor(1, pixels.Color(0, (fade / 2), (fade / 2))); //Turquoise
	} else if (NEO_Color < 171) {
		pixels.setPixelColor(0, pixels.Color(0, 0, fade)); //Blue
		pixels.setPixelColor(1, pixels.Color(0, 0, fade)); //Blue
	} else if (NEO_Color < 214) {
		pixels.setPixelColor(0, pixels.Color((fade / 2), 0, (fade / 2))); //Purple
		pixels.setPixelColor(1, pixels.Color((fade / 2), 0, (fade / 2))); //Purple
	}
	pixels.show(); // This sends the updated pixel color to the hardware.
	#endif
	fade += 8;
	if (fade == 0)
	{
		// -- Byte value overflows: 240 + 16 = 0
		SoftTimer.remove(&FadeinTask);
		SoftTimer.add(&FadeoutTask);
	}
}

void decrement(Task *me)
{
	fade -= 8;
	#ifndef OK_Color
	analogWrite(BLINKPIN, fade);
	#else
	if (NEO_Color == 1) {
		pixels.setPixelColor(0, pixels.Color(fade, 0, 0)); //Red
		pixels.setPixelColor(1, pixels.Color(fade, 0, 0)); //Red
	} else if (NEO_Color < 44) {
		pixels.setPixelColor(0, pixels.Color((fade / 2), (fade / 2), 0)); //Yellow
		pixels.setPixelColor(1, pixels.Color((fade / 2), (fade / 2), 0)); //Yellow
	} else if (NEO_Color < 86) {
		pixels.setPixelColor(0, pixels.Color(0, fade, 0)); //Green
		pixels.setPixelColor(1, pixels.Color(0, fade, 0)); //Green
	} else if (NEO_Color < 129) {
		pixels.setPixelColor(0, pixels.Color(0, (fade / 2), (fade / 2))); //Turquoise
		pixels.setPixelColor(1, pixels.Color(0, (fade / 2), (fade / 2))); //Turquoise
	} else if (NEO_Color < 171) {
		pixels.setPixelColor(0, pixels.Color(0, 0, fade)); //Blue
		pixels.setPixelColor(1, pixels.Color(0, 0, fade)); //Blue
	} else if (NEO_Color < 214) {
		pixels.setPixelColor(0, pixels.Color((fade / 2), 0, (fade / 2))); //Purple
		pixels.setPixelColor(1, pixels.Color((fade / 2), 0, (fade / 2))); //Purple
	pixels.show();														  // This sends the updated pixel color to the hardware.
	}
	#endif
	if (fade == 0)
	{
		// -- Floor reached.
		SoftTimer.remove(&FadeoutTask);
		SoftTimer.add(&FadeinTask);
		if (getBuffer[7] >= 0xa1 && getBuffer[7] <= 0xaf)
		{ // Waiting for HMACSHA1 button press
			if (getBuffer[7] == 0xa1)
			{ //Out of time to press button for HMACSHA1
				fadeoff(1);
				memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
				getBuffer[1] = 0x02;
				getBuffer[2] = 0x02;
				getBuffer[3] = 0x03;
				getBuffer[4] = 0x03;
				getBuffer[5] = 0x03;
				getBuffer[6] = may_block;
				getBuffer[7] = 0x00;
				getBuffer[8] = 0x00;
				sess_counter = 3;
				packet_buffer_details[0] = 0;
				packet_buffer_details[1] = 0;
			}
			else
			{
				getBuffer[7]--;
			}
		}
	}
}

bool wipebuffersafter5sec(Task *me)
{
	if (pending_operation==CTAP2_ERR_USER_ACTION_PENDING || pending_operation==CTAP2_ERR_DATA_READY){
		fadeoffafter20(); 
		//Wait up to 25 seconds for user to enter challenge, required for Android support
		//Wait up to 25 seconds for encrypted data to be retrived, required for Android support
		pending_operation=CTAP2_ERR_DATA_WIPE;
		return false;
	}

#ifdef DEBUG
	Serial.println("wipe buffers after 5 sec");
#endif

	if (configmode == false)
	{
		wipetasks();
	}
	return false;
}

void wipetasks() {
	packet_buffer_offset = 0;
	memset(ctap_buffer, 0, CTAPHID_BUFFER_SIZE);
	memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
	memset(packet_buffer_details, 0, sizeof(packet_buffer_details));
	setBuffer[7] = 0;
	// Delete any unretrived data in getbuffer
	if (getBuffer[7]>= 0xC0) {
		getBuffer[0] = 0;
		getBuffer[1] = 2;
		getBuffer[2] = 2;
		getBuffer[3] = 3;
		getBuffer[4] = sess_counter;
		getBuffer[5] = 3;
		getBuffer[6] = may_block;
		getBuffer[7] = 0;
		getBuffer[8] = 0;
		memset(setBuffer, 0, 9);
	}
	large_resp_buffer_offset = 0;
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
	derived_key_challenge_mode = 0;
	stored_key_challenge_mode = 0;
	pending_operation = 0;
	if (isfade || CRYPTO_AUTH) {
		fadeoff(1); //Fade Red, failed to complete within 5 seconds
	}
}

bool fadeoffafter20sec(Task *me)
{
#ifdef DEBUG
	Serial.println("wipe buffers after 20 sec");
#endif
	if (isfade || CRYPTO_AUTH || pending_operation==CTAP2_ERR_DATA_WIPE) {
		if (pending_operation==OKDECRYPT_ERR_USER_ACTION_PENDING || pending_operation==OKSIGN_ERR_USER_ACTION_PENDING) {
			hidprint("Timeout occured while waiting for confirmation on OnlyKey");
		}
		fadeoff(1); //Fade Red, failed to enter PIN in 20 Seconds
	}
	//Below used for keyboard OnlyKey setup
	if (!initcheck)
	{
		if (pin_set <= 3)
		{
			set_primary_pin(NULL, KEYBOARD_MANUAL_PIN_SET); //Done PIN entry
		}
		else if (pin_set <= 6)
		{
			set_sd_pin(NULL, KEYBOARD_MANUAL_PIN_SET); //Done PIN entry
		}
		else if (pin_set <= 9)
		{
			if (onlykeyhw!=OK_HW_DUO) {
				set_secondary_pin(NULL, KEYBOARD_MANUAL_PIN_SET); //Done PIN entry
			}
		}
		else
		{
			okcore_quick_setup(KEYBOARD_AUTO_PIN_SET); //Auto
		}
	}
	return false;
}

void fadeoff(uint8_t color)
{
	Endfade.startDelayed(); //run fadeendafter2sec after 2 seconds (prevent accidental button press)
	wipedata();
	if (!color)
	{ //No fade out 2 sec
		SoftTimer.remove(&FadeinTask);
		SoftTimer.remove(&FadeoutTask);
#ifdef OK_Color
		setcolor(85); //Green
#endif
	}
	else
	{
#ifdef OK_Color
		NEO_Color = color;
#endif
	}
}

bool fadeendafter2sec(Task *me)
{
	SoftTimer.remove(&FadeinTask);
	SoftTimer.remove(&FadeoutTask);
	isfade = 0;
	return false;
}

void fadeon(uint8_t color)
{
	NEO_Color = color;
	if (NEO_Color == 170) packet_buffer_details[0] = OKWEBAUTHN;
	SoftTimer.add(&FadeinTask);
	isfade = 1;
}

void wipedata()
{
	SoftTimer.remove(&Wipedata);
	Wipedata.startDelayed();
	if (NEO_Color != 170) packet_buffer_details[0] = 0;
	packet_buffer_details[1] = 0;
}

void fadeoffafter20()
{
	Usertimeout.startDelayed();
}

void cancelfadeoffafter20()
{
	SoftTimer.remove(&Usertimeout); //Cancel this pin was entered
}

#ifdef OK_Color
// Input a value 0 to 255 to get a color value.
// The colours are a transition r - g - b - back to r.
uint32_t Wheel(uint8_t WheelPos)
{
	WheelPos = 255 - WheelPos;
	if (WheelPos < 85)
	{
		return pixels.Color(255 - WheelPos * 3, 0, WheelPos * 3);
	}
	if (WheelPos < 170)
	{
		WheelPos -= 85;
		return pixels.Color(0, WheelPos * 3, 255 - WheelPos * 3);
	}
	WheelPos -= 170;
	return pixels.Color(WheelPos * 3, 255 - WheelPos * 3, 0);
}

void rainbowCycle()
{
	for (uint16_t j = 0; j < 300; j++)
	{
		pixels.setPixelColor(0, Wheel(j & 255));
		pixels.setPixelColor(1, Wheel(j & 255));
		pixels.show();
		if (calibratecaptouch(j))
			j = 20;
	}
}

int calibratecaptouch(uint16_t j)
{
	rngloop();
	if (onlykeyhw==OK_HW_DUO || ((touchread1 + touchread4 + touchread5) * 1.0) / ((touchread2 + touchread3 + touchread6) * 1.0) > .6 && ((touchread1 + touchread4 + touchread5) * 1.0) / ((touchread2 + touchread3 + touchread6) * 1.0) < 1.6)
	{
		if (j >= 200)
		{
			if (j == 200)
			{
				touchread1ref = touchread1;
				touchread2ref = touchread2;
				touchread3ref = touchread3;
				touchread4ref = touchread4;
				touchread5ref = touchread5;
				touchread6ref = touchread6;
			}
			#ifdef DEBUG
				Serial.println("touchread1 and touchread1ref");
				Serial.println(touchread1);
				Serial.println(touchread1ref);
				Serial.println("touchread2 and touchread2ref");
				Serial.println(touchread2);
				Serial.println(touchread2ref);
				Serial.println("touchread3 and touchread3ref");
				Serial.println(touchread3);
				Serial.println(touchread3ref);
				Serial.println("touchread4 and touchread4ref");
				Serial.println(touchread4);
				Serial.println(touchread4ref);
				Serial.println("touchread5 and touchread5ref");
				Serial.println(touchread5);
				Serial.println(touchread5ref);
				Serial.println("touchread6 and touchread6ref");
				Serial.println(touchread6);
				Serial.println(touchread6ref);
			#endif
			// A button reads 50% higher than its ref, start over
			if (touchread1ref+(touchread1ref/2)<touchread1) return 1;
			if (touchread2ref+(touchread2ref/2)<touchread2) return 1;
			if (touchread3ref+(touchread3ref/2)<touchread3) return 1;
			if (touchread4ref+(touchread4ref/2)<touchread4) return 1;
			if (touchread5ref+(touchread5ref/2)<touchread5) return 1;
			if (touchread6ref+(touchread6ref/2)<touchread6) return 1;
			touchread1ref = (touchread1 + touchread1ref) / 2;
			touchread2ref = (touchread2 + touchread2ref) / 2;
			touchread3ref = (touchread3 + touchread3ref) / 2;
			touchread4ref = (touchread4 + touchread4ref) / 2;
			touchread5ref = (touchread5 + touchread5ref) / 2;
			touchread6ref = (touchread6 + touchread6ref) / 2;
			if (j == 299) { //Check how many touch pins connected
				// ~15% greater than pins 
				if (HW_ID==5) {
					onlykeyhw = OK_HW_COLOR; // OK_Color LQFP
				} else if (!avganalog()) {
					// Double check just to make sure in case of glitch
					if (avganalog()) CPU_RESTART();
					if (avganalog()) CPU_RESTART();
					if (avganalog()) CPU_RESTART();
					if (avganalog()) CPU_RESTART();
					onlykeyhw = HW_ID; // OK_HW_DUO
				} else {
					if (onlykeyhw==OK_HW_DUO) {
						// Was detected as OnlyKey DUO previously, this should not happen
						CPU_RESTART();
					}
					// Double check just to make sure in case of glitch
					if (!avganalog()) CPU_RESTART();
					if (!avganalog()) CPU_RESTART();
					if (!avganalog()) CPU_RESTART();
					if (!avganalog()) CPU_RESTART();
					onlykeyhw = OK_HW_COLOR; // OK_Color BGA
				}
				#ifdef DEFINED_HWID
				onlykeyhw = DEFINED_HWID; // override auto hw detection, hardcoded
				#endif
			}
		}
	}
	else
	{ // Detected touching buttons restart
#ifdef DEBUG
		Serial.println(((touchread1 + touchread4 + touchread5) * 1.0) / ((touchread2 + touchread3 + touchread6) * 1.0));
#endif
		return 1;
	}
	return 0;
}

int avganalog() {
	int analogavg = 0;
	for (int i=0; i < 10; i++) {
		analogavg = analogavg + analogRead(A12);
		// OK_Color has PIN connected to 3.3v, OK_HW_DUO has floating PIN
		delay(1);
	}
	analogavg = analogavg/10;
	if (analogavg>62000 && analogavg<67000) {
		return 1;
	} else {
		return 0;
	}
	
}

void initColor()
{
	pixels.begin(); // This initializes the NeoPixel library.
	uint8_t modifier = 22;
	if (onlykeyhw==OK_HW_DUO) modifier=modifier/2;
	if (NEO_Brightness[0] != 0) {
		pixels.setBrightness(NEO_Brightness[0] * modifier);
	} else {
		pixels.setBrightness(modifier*8); //70% Brightness
	}
	pixels.show();
}

void setcolor(uint8_t Color)
{
	if (Color == 0) {
		pixels.setPixelColor(0, pixels.Color(0, 0, 0));
		pixels.setPixelColor(1, pixels.Color(0, 0, 0));
	} else if (Color == 85) {
		pixels.setPixelColor(0, Wheel(Color+Profile_Offset));
		pixels.setPixelColor(1, Wheel(Color+Profile_Offset));
	} else	{
		pixels.setPixelColor(0, Wheel(Color));
		pixels.setPixelColor(1, Wheel(Color));
		NEO_Color = Color;
	}
	pixels.show(); // This sends the updated pixel color to the hardware.
	delay(1);
}
#endif

void backup()
{
	if (profilemode == NONENCRYPTEDPROFILE)
		return;
#ifdef STD_VERSION
	uint8_t temp[MAX_RSA_KEY_SIZE];
	uint8_t large_temp[18000];
	int urllength;
	int usernamelength;
	int passwordlength;
	int otplength;
	uint8_t *ptr;
	unsigned char beginbackup[] = "-----BEGIN ONLYKEY BACKUP-----";
	unsigned char endbackup[] = "-----END ONLYKEY BACKUP-----";
	unsigned char dashes[] = "-----";
	unsigned char nobackupkey[] = "No Backup Key - Follow instructions here https://docs.crp.to/usersguide.html#secure-encrypted-backup-anywhere";
	uint8_t ctr[2];
	uint8_t slot;
	uint8_t addchar1;
	uint8_t addchar2;
	uint8_t addchar3;
	uint8_t addchar4;
	uint8_t addchar5;
	uint8_t addchar6;
	uint8_t p2mode;
	okeeprom_eeget_2ndprofilemode(&p2mode); //get 2nd profile mode
	large_buffer_offset = 0;
	memset(large_temp, 0, sizeof(large_temp)); //Wipe all data from largebuffer
#ifdef OK_Color
	setcolor(45); //Yellow
#endif
	for (uint8_t z = 0; z < sizeof(beginbackup); z++)
	{
		Keyboard.press(beginbackup[z]);
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
	}

	for (slot = 1; slot <= 61; slot++)
	{
#ifdef DEBUG
		Serial.print("Backing up Label Number ");
		Serial.println(slot);
#endif
		memset(temp, 0, sizeof(temp)); //Wipe all data from temp buffer
		ptr = temp;
		okcore_flashget_label(ptr, slot);
		if (temp[0] != 0xFF && temp[0] != 0x00)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 1; //1 - Label
			memcpy(large_temp + large_buffer_offset + 3, temp, EElen_label);
			large_buffer_offset = large_buffer_offset + EElen_label + 3;
		}
	}
	for (slot = 1; slot <= 24; slot++)
	{
#ifdef DEBUG
		Serial.print("Backing up Slot Number ");
		Serial.println(slot);
#endif
		memset(temp, 0, sizeof(temp)); //Wipe all data from temp buffer
		ptr = temp;
		urllength = okcore_flashget_url(ptr, slot);
		if (urllength > 0)
		{
#ifdef DEBUG
			Serial.println("Reading URL from Flash...");
			Serial.print("URL Length = ");
			Serial.println(urllength);
#endif

#ifdef DEBUG
			Serial.println("Encrypted");
			byteprint(temp, urllength);
			Serial.println();
#endif
#ifdef STD_VERSION
			if (slot <= 12 || (slot > 12 && p2mode != NONENCRYPTEDPROFILE))
				okcore_aes_gcm_decrypt(temp, slot, 15, profilekey, urllength);
#endif
#ifdef DEBUG
			Serial.println("Unencrypted");
			byteprint(temp, urllength);
			Serial.println();
#endif
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 15; //15 - URL
			memcpy(large_temp + large_buffer_offset + 3, temp, urllength);
			large_buffer_offset = large_buffer_offset + urllength + 3;
		}
		okeeprom_eeget_addchar(&addchar5, slot);
		addchar1 = addchar5 & 0x3;		  //After Username
		addchar2 = (addchar5 >> 4) & 0x3; //After Password
		addchar3 = (addchar5 >> 6) & 0x1; //After OTP
		addchar6 = (addchar5 >> 7) & 0x1; //After OTP 2
		addchar4 = (addchar5 >> 2) & 0x1; //Before Username
		addchar5 = (addchar5 >> 3) & 0x1; //Before OTP
		if (addchar1 > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 16; //16 - Add Char 1
			large_temp[large_buffer_offset + 3] = addchar1;
			large_buffer_offset = large_buffer_offset + 4;
		}
		if (addchar2 > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 3; //3 - Add Char 2
			large_temp[large_buffer_offset + 3] = addchar2;
			large_buffer_offset = large_buffer_offset + 4;
		}
		if (addchar3 > 0 || addchar6 > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 6; //6 - Add Char 3
			large_temp[large_buffer_offset + 3] = (addchar3+1) + addchar6;
			large_buffer_offset = large_buffer_offset + 4;
		}
		if (addchar4 > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 18; //18 - Add Char 4
			large_temp[large_buffer_offset + 3] = addchar4;
			large_buffer_offset = large_buffer_offset + 4;
		}
		if (addchar5 > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 19; //19 - Add Char 5
			large_temp[large_buffer_offset + 3] = addchar5;
			large_buffer_offset = large_buffer_offset + 4;
		}
		okeeprom_eeget_delay1(ptr, slot);
		if (temp[0] > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 17; //17 - Delay 1
			large_temp[large_buffer_offset + 3] = temp[0];
			large_buffer_offset = large_buffer_offset + 4;
		}
		usernamelength = okcore_flashget_username(ptr, slot);
		if (usernamelength > 0)
		{
#ifdef DEBUG
			Serial.println("Reading Username from Flash...");
			Serial.print("Username Length = ");
			Serial.println(usernamelength);
#endif
			if (slot <= 12 || (slot > 12 && p2mode != NONENCRYPTEDPROFILE))
			{
#ifdef DEBUG
				Serial.println("Encrypted");
				byteprint(temp, usernamelength);
				Serial.println();
#endif
				okcore_aes_gcm_decrypt(temp, slot, 2, profilekey, usernamelength);
			}
#ifdef DEBUG
			Serial.println("Unencrypted");
			byteprint(temp, usernamelength);
			Serial.println();
#endif
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 2; //2 - Username
			memcpy(large_temp + large_buffer_offset + 3, temp, usernamelength);
			large_buffer_offset = large_buffer_offset + usernamelength + 3;
		}
		okeeprom_eeget_delay2(ptr, slot);
		if (temp[0] > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 4; //4 - Delay 2
			large_temp[large_buffer_offset + 3] = temp[0];
			large_buffer_offset = large_buffer_offset + 4;
		}
		passwordlength = okeeprom_eeget_password(ptr, slot);
		if (passwordlength > 0)
		{
#ifdef DEBUG
			Serial.println("Reading Password from EEPROM...");
			Serial.print("Password Length = ");
			Serial.println(passwordlength);
#endif
			if (slot <= 12 || (slot > 12 && p2mode != NONENCRYPTEDPROFILE))
			{
#ifdef DEBUG
				Serial.println("Encrypted");
				byteprint(temp, passwordlength);
				Serial.println();
#endif
				okcore_aes_gcm_decrypt(temp, slot, 5, profilekey, passwordlength);
			}
#ifdef DEBUG
			Serial.println("Unencrypted");
			byteprint(temp, passwordlength);
			Serial.println();
#endif
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 5; //5 - Password
			memcpy(large_temp + large_buffer_offset + 3, temp, passwordlength);
			large_buffer_offset = large_buffer_offset + passwordlength + 3;
		}
		okeeprom_eeget_delay3(ptr, slot);
		if (temp[0] > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 7; //7 - Delay 3
			large_temp[large_buffer_offset + 3] = temp[0];
			large_buffer_offset = large_buffer_offset + 4;
		}
		otplength = okeeprom_eeget_2FAtype(ptr, slot);
		if (temp[0] > 0)
		{
			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = 8; //8 - 2FA type
			large_temp[large_buffer_offset + 3] = temp[0];
			large_buffer_offset = large_buffer_offset + 4;
		}
		uint8_t whichtype = temp[0];
		if (whichtype == MFAGOOGLEAUTH || whichtype == MFAYUBIOTPandHMACSHA1 || whichtype == MFAHMACSHA1)
		{ //Google Auth or HMAC
#ifdef DEBUG
			Serial.println("Reading 2FA Key from Flash...");
#endif
			otplength = okcore_flashget_2fa_key(ptr, slot);
#ifdef DEBUG
			Serial.println("Encrypted");
			byteprint(temp, otplength);
			Serial.println();
			Serial.print("Key Length = ");
			Serial.println(otplength);
#endif

			large_temp[large_buffer_offset] = 0xFF; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			if (whichtype == MFAGOOGLEAUTH) {
				if (slot <= 12 || (slot > 12 && p2mode != NONENCRYPTEDPROFILE)) okcore_aes_gcm_decrypt(temp, slot, 9, profilekey, otplength);
				memcpy(large_temp + large_buffer_offset + 4, temp, otplength);
				large_temp[large_buffer_offset + 2] = 9; //9 - TOTP Key
			}
			else { //HMAC
				otplength = 21;
				okcore_aes_gcm_decrypt(temp+43, slot, 29, profilekey, otplength);
				memcpy(large_temp + large_buffer_offset + 4, temp + 43, otplength);
				large_temp[large_buffer_offset + 2] = 29; //29 - HMAC Key
			}
			
			#ifdef DEBUG
			Serial.println("Unencrypted");
			byteprint(temp, otplength);
			Serial.println();
			#endif

			large_temp[large_buffer_offset + 3] = otplength;
			large_buffer_offset = large_buffer_offset + otplength + 4;
		}
		if (whichtype == MFAOLDYUBIOTP || whichtype == MFAYUBIOTP || whichtype == MFAYUBIOTPandHMACSHA1)
		{ //Old yubi otp or new yubi otp
		if (whichtype == MFAOLDYUBIOTP) {
			yubikey_eeget_counter(ctr, 0);
			okeeprom_eeget_public_DEPRICATED(ptr);
			ptr = (temp + EElen_public);
			okeeprom_eeget_private_DEPRICATED(ptr);
			ptr = (temp + EElen_public + EElen_private);
			okeeprom_eeget_aeskey_DEPRICATED(ptr);
			okcore_aes_gcm_decrypt(temp, 0, 10, profilekey, (EElen_aeskey + EElen_private + EElen_public));
			large_temp[large_buffer_offset] = 0xFF;   //delimiter
			large_temp[large_buffer_offset + 1] = 0;  //slot 0
			large_temp[large_buffer_offset + 2] = 10; //10 = Yubikey
			memcpy(large_temp + large_buffer_offset + 3, temp, (EElen_aeskey + EElen_private + EElen_public));
			large_buffer_offset = large_buffer_offset + (EElen_aeskey + EElen_private + EElen_public) + 3;
		} else if ((whichtype == MFAYUBIOTP || whichtype ==MFAYUBIOTPandHMACSHA1) && slot > 0 && slot < 25) {
			yubikey_eeget_counter(ctr, slot);
			okcore_flashget_yubiotp(ptr, slot);
			okcore_aes_gcm_decrypt(temp, slot, 10, profilekey, (EElen_aeskey + EElen_private + 16));
			large_temp[large_buffer_offset] = 0xFF;   //delimiter
			large_temp[large_buffer_offset + 1] = slot;  //slot
			large_temp[large_buffer_offset + 2] = 10; //10 = Yubikey
			memcpy(large_temp + large_buffer_offset + 3, temp, (EElen_aeskey + EElen_private + 16));
			large_buffer_offset = large_buffer_offset + (EElen_aeskey + EElen_private + 16) + 3; 
		}
			large_temp[large_buffer_offset] = ctr[0];	 //first part of counter
			large_temp[large_buffer_offset + 1] = ctr[1]; //second part of counter
			large_buffer_offset = large_buffer_offset + 2;
		}
		okeeprom_eeget_typespeed(ptr, slot);
		if (*ptr != 0)
		{
			*ptr = 11 - *ptr;
			large_temp[large_buffer_offset] = 0xFF;   //delimiter
			large_temp[large_buffer_offset + 1] = slot;  //slot 0
			large_temp[large_buffer_offset + 2] = 13; //13 - Keyboard type speed
			large_temp[large_buffer_offset + 3] = temp[0];
			large_buffer_offset = large_buffer_offset + 4;
		}
	}
	okeeprom_eeget_typespeed(ptr, 0);
	if (*ptr != 0)
	{
		*ptr = 11 - *ptr;
		large_temp[large_buffer_offset] = 0xFF;   //delimiter
		large_temp[large_buffer_offset + 1] = 0;  //slot 0
		large_temp[large_buffer_offset + 2] = 13; //13 - Keyboard type speed
		large_temp[large_buffer_offset + 3] = temp[0];
		large_buffer_offset = large_buffer_offset + 4;
	}

	okeeprom_eeget_keyboardlayout(ptr);
	if (*ptr != 0)
	{
		large_temp[large_buffer_offset] = 0xFF;   //delimiter
		large_temp[large_buffer_offset + 1] = 0;  //slot 0
		large_temp[large_buffer_offset + 2] = 14; //14- Keyboard layout
		large_temp[large_buffer_offset + 3] = temp[0];
		large_buffer_offset = large_buffer_offset + 4;
	}
	okeeprom_eeget_timeout(ptr);
	if (*ptr != 0)
	{
		large_temp[large_buffer_offset] = 0xFF;   //delimiter
		large_temp[large_buffer_offset + 1] = 0;  //slot 0
		large_temp[large_buffer_offset + 2] = 11; //11 - Idle Timeout
		large_temp[large_buffer_offset + 3] = temp[0];
		large_buffer_offset = large_buffer_offset + 4;
	}
	okeeprom_eeget_hmac_challengemode(ptr);
	if (*ptr != 0)
	{
		large_temp[large_buffer_offset] = 0xFF;   //delimiter
		large_temp[large_buffer_offset + 1] = 0;  //slot 0
		large_temp[large_buffer_offset + 2] = 26; //26 - hmac challenge mode
		large_temp[large_buffer_offset + 3] = temp[0];
		large_buffer_offset = large_buffer_offset + 4;
	}
	okeeprom_eeget_modkey(ptr);
	if (*ptr != 0)
	{
		large_temp[large_buffer_offset] = 0xFF;   //delimiter
		large_temp[large_buffer_offset + 1] = 0;  //slot 0
		large_temp[large_buffer_offset + 2] = 27; //27 - modkey mode
		large_temp[large_buffer_offset + 3] = temp[0];
		large_buffer_offset = large_buffer_offset + 4;
	}
	okeeprom_eeget_stored_key_challenge_mode(ptr);
	if (*ptr != 0)
	{
		large_temp[large_buffer_offset] = 0xFF;   //delimiter
		large_temp[large_buffer_offset + 1] = 0;  //slot 0
		large_temp[large_buffer_offset + 2] = 22; //22 - stored challenge mode
		large_temp[large_buffer_offset + 3] = temp[0];
		large_buffer_offset = large_buffer_offset + 4;
	}
	okeeprom_eeget_derived_key_challenge_mode(ptr);
	if (*ptr != 0)
	{
		large_temp[large_buffer_offset] = 0xFF;   //delimiter
		large_temp[large_buffer_offset + 1] = 0;  //slot 0
		large_temp[large_buffer_offset + 2] = 21; //21 - derived challenge mode
		large_temp[large_buffer_offset + 3] = temp[0];
		large_buffer_offset = large_buffer_offset + 4;
	}

#ifdef DEBUG
	Serial.println();
	Serial.println("Unencrypted Slot Backup");
	byteprint(large_temp, large_buffer_offset);
	Serial.println();
#endif

	//Copy RSA keys to buffer
	uint8_t backupslot;
	okeeprom_eeget_backupkey(&backupslot);
	for (uint8_t slot = 1; slot <= 4; slot++)
	{
#ifdef DEBUG
		Serial.print("Backing up RSA Key Number ");
		Serial.println(slot);
#endif
		memset(temp, 0, MAX_RSA_KEY_SIZE); //Wipe all data from temp buffer
		ptr = temp;
		uint8_t features = okcore_flashget_RSA(slot);
		if (slot == backupslot)
			features = features + 0x80;
		if (features != 0x00)
		{
			large_temp[large_buffer_offset] = 0xFE; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = features;
			memcpy(large_temp + large_buffer_offset + 3, rsa_private_key, (type * 128));
			large_buffer_offset = large_buffer_offset + (type * 128) + 3;
#ifdef DEBUG
			byteprint(rsa_private_key, (type * 128));
#endif
		}
		else
		{
#ifdef DEBUG
			Serial.print("No key set to slot");
#endif
		}
	}

	//Copy ECC keys to buffer
	for (uint8_t slot = 101; slot <= 132; slot++)
	{
#ifdef DEBUG
		Serial.print("Backing up ECC Key Number ");
		Serial.println(slot);
#endif
		memset(temp, 0, MAX_RSA_KEY_SIZE); //Wipe all data from temp buffer
		ptr = temp;
		uint8_t features = okcore_flashget_ECC(slot);
		if (slot == backupslot)
			features = features + 0x80;
		if (features != 0x00)
		{
			large_temp[large_buffer_offset] = 0xFE; //delimiter
			large_temp[large_buffer_offset + 1] = slot;
			large_temp[large_buffer_offset + 2] = features;
			memcpy(large_temp + large_buffer_offset + 3, ecc_private_key, MAX_ECC_KEY_SIZE);
			large_buffer_offset = large_buffer_offset + MAX_ECC_KEY_SIZE + 3;
#ifdef DEBUG
			byteprint(ecc_private_key, MAX_ECC_KEY_SIZE);
#endif
		}
		else
		{
#ifdef DEBUG
			Serial.print("No key set to slot");
#endif
		}
	}
	//Copy Authentication State to buffer
	large_temp[large_buffer_offset] = 0xFE; //delimiter
	large_temp[large_buffer_offset + 1] = 0; // Use 0 for auth state 200+index for RKs 
	memcpy(large_temp + large_buffer_offset + 2, &STATE, sizeof(AuthenticatorState));
	large_buffer_offset = large_buffer_offset + sizeof(AuthenticatorState) + 2;
	//Copy Resident Keys to buffer
	CTAP_residentKey rk;
    int index = STATE.rk_stored;
    for (int ii = 0; ii < index; ii++)
    {
        ctap_load_rk(ii, &rk);
        if (rk.user.id_size)
        {
			large_temp[large_buffer_offset] = 0xFE; //delimiter
			large_temp[large_buffer_offset + 1] = ii+200; // Use 0 for auth state 200+index for RKs
			memcpy(large_temp + large_buffer_offset + 2, &rk, sizeof(rk));
			large_buffer_offset = large_buffer_offset + sizeof(rk) + 2;
        }
    }

	//Copy U2F key/Cert to buffer
	//okeeprom_eeget_U2Fcertlen(length);
	//int length2 = length[0] << 8 | length[1];
	//if (length2 != 0)
	//{
		//large_temp[large_buffer_offset] = 0xFD; //delimiter
		//memcpy(large_temp + large_buffer_offset + 1, attestation_key, 32);
		//large_buffer_offset = large_buffer_offset + 32 + 1;
		//large_temp[large_buffer_offset] = 0; //Backward compatability used to backup U2F counter
		//large_buffer_offset++;
		//large_temp[large_buffer_offset] = 0;
		//large_buffer_offset++;
		//large_temp[large_buffer_offset] = length[0];
		//large_buffer_offset++;
		//large_temp[large_buffer_offset] = length[1];
		//large_buffer_offset++;
		//memcpy(large_temp + large_buffer_offset, attestation_cert_der, length2);
		//large_buffer_offset = large_buffer_offset + length2;
#ifdef DEBUG
		//Serial.print("Found U2F Certificate to backup");
#endif
	//}
	//else
	//{
#ifdef DEBUG
		//Serial.print("No U2F Certificate to backup");
#endif
	//}

#ifdef DEBUG
	Serial.println();
	Serial.println("Unencrypted");
	byteprint(large_temp, large_buffer_offset);
	Serial.println();
#endif

	//ENCRYPT
	okeeprom_eeget_backupkey(&slot);
#ifdef DEBUG
	Serial.println();
	Serial.print("Backup Key Assigned to Slot # ");
	Serial.println(slot);
	Serial.println();
#endif
	ptr = temp;
	RNG2(ptr, 32); //Fill temp with random data
	if (slot == 0)
	{
		hidprint("Error no backup key set");
		for (uint8_t z = 0; z < sizeof(nobackupkey); z++)
		{
			Keyboard.press(nobackupkey[z]);
			delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
			Keyboard.releaseAll();
			delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
		}
		return;
	}
	else if (slot > 100)
	{
		uint8_t iv[12];
		uint8_t secret[64];
		memcpy(iv, temp, 12);
		okcore_flashget_ECC(slot);
#ifdef DEBUG
		Serial.println("Slot");
		Serial.println(slot);
		Serial.println("Private = ");
		byteprint(ecc_private_key, 32);
#endif
		if (okcrypto_shared_secret(ecc_public_key, secret))
		{
			hidprint("Error with ECC Shared Secret");
			return;
		}
#ifdef DEBUG
		Serial.println("Secret = ");
		byteprint(secret, 32);
		Serial.println("IV = ");
		byteprint(iv, 12);
#endif
		SHA256_CTX context;
		sha256_init(&context);
		sha256_update(&context, secret, 32);		 //add secret
		sha256_update(&context, ecc_public_key, 32); //Add public key
		sha256_update(&context, iv, 12);			 //add AES GCM IV
		sha256_final(&context, secret);
#ifdef DEBUG
		Serial.println("AES KEY = ");
		byteprint(secret, 32);
#endif
		if (profilemode != NONENCRYPTEDPROFILE)
		{
		#ifdef STD_VERSION
		okcrypto_aes_gcm_encrypt2(large_temp, iv, secret, large_buffer_offset, false);
		#endif
		}
		memcpy(large_temp + large_buffer_offset, iv, 12);
#ifdef DEBUG
		Serial.println("IV = ");
		byteprint(iv, 12);
#endif
		large_buffer_offset = large_buffer_offset + 12;
		large_temp[large_buffer_offset] = type + 100;
#ifdef DEBUG
		Serial.println("Type = ");
		Serial.println(large_temp[large_buffer_offset]);
#endif
		large_buffer_offset++;
	}
	else if (slot <= 4)
	{
		okcore_flashget_RSA(slot);
		uint8_t iv[12] = "BACKUP12345";
		uint8_t temp2[512];
#ifdef DEBUG
		Serial.println("AES KEY = ");
		byteprint(temp, 32);
#endif
		if (profilemode != NONENCRYPTEDPROFILE)
		{
		#ifdef STD_VERSION
		okcrypto_aes_gcm_encrypt2(large_temp, iv, temp, large_buffer_offset, false);
		#endif
		}
		//No need for unique IVs when random key used
		if (rsa_encrypt(32, temp, temp2))
		{
			hidprint("Error with RSA Encryption");
			return;
		}
#ifdef DEBUG
		Serial.println("RSA Encrypted AES KEY = ");
		byteprint(temp2, (type * 128));
#endif
		memcpy(large_temp + large_buffer_offset, temp2, (type * 128));
		large_buffer_offset = large_buffer_offset + (type * 128);
		large_temp[large_buffer_offset] = type;
#ifdef DEBUG
		Serial.println("Type = ");
		Serial.println(large_temp[large_buffer_offset]);
#endif
		large_buffer_offset++;
	}

#ifdef DEBUG
	Serial.println();
	Serial.println("Encrypted");
	//byteprint(large_temp,large_buffer_offset);
	Serial.println();
#endif

	int i = 0;
	uint8_t backuphash[32] = {0};
	SHA256_CTX bhash;
	while (i <= large_buffer_offset && i < (int)sizeof(large_temp))
	{
		Keyboard.press(KEY_RETURN);
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
		int crc = yubikey_crc16 (temp, 20);
		if ((large_buffer_offset - i) < 57)
		{
			sha256_init(&bhash);
			sha256_update(&bhash, backuphash, 32);
			sha256_update(&bhash, large_temp + i, large_buffer_offset - i);
			sha256_final(&bhash, backuphash);

			int enclen = base64_encode(large_temp + i, temp, (large_buffer_offset - i), 0);
			for (int z = 0; z < enclen; z++)
			{
				Keyboard.press(temp[z]);
				delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
				Keyboard.releaseAll();
				delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
			}
		}
		else
		{
			sha256_init(&bhash);
			sha256_update(&bhash, backuphash, 32);
			sha256_update(&bhash, large_temp + i, 57);
			sha256_final(&bhash, backuphash);
			base64_encode(large_temp + i, temp, 57, 0);
			for (int z = 0; z < 4 * (57 / 3); z++)
			{
				Keyboard.press(temp[z]);
				delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
				Keyboard.releaseAll();
				delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
			}
		}
		i = i + 57;
		memset(temp, 0, sizeof(temp));
	}
	Keyboard.press(KEY_RETURN);
	delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
	Keyboard.releaseAll();
	delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
#ifdef DEBUG
	Serial.println("Encoded");
	byteprint(large_temp, large_buffer_offset);
	Serial.println();
#endif

	// backup hash
	int enclen = base64_encode(backuphash, temp, 32, 0);
	for (uint8_t z = 0; z < 2; z++)
	{
		Keyboard.press(dashes[z]);
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
	}
	for (uint8_t z = 0; z < enclen; z++)
	{
		Keyboard.press(temp[z]);
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
	}
	Keyboard.println();
	//End backup footer
	for (uint8_t z = 0; z < sizeof(endbackup); z++)
	{
		Keyboard.press(endbackup[z]);
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0] * TYPESPEED[0] / 3) * 8);
	}
	Keyboard.println();
	large_buffer_offset = 0;
	memset(large_temp, 0, sizeof(large_temp));
#endif
}

void RESTORE(uint8_t *buffer)
{
	if (profilemode == NONENCRYPTEDPROFILE)
		return;
#ifdef STD_VERSION
	static uint8_t *large_temp;
	static unsigned int offset = 0;
	
	if (offset == 0) {
		//free(large_temp);
		large_temp = (uint8_t *)malloc(18000); //Max size for slots 7827 max size for keys 3072 + headers + Max RSA key size + 6144 for RKs + 208 Authenticator state + 24 for new yubiotp counters
		memset(large_temp, 0, 18000);
	}

	//Slot restore
	if (buffer[5] == 0xFF) //Not last packet
	{
		if (offset <= (18000 - 57))
		{
			#ifdef DEBUG
			Serial.print("Restore packet received =");
		    byteprint(buffer + 6, 57);
			#endif
			// Issue with memcpy, MCU can't keep up
			for (int i = 0; i<57; i++) {
				large_temp[offset+i] = buffer[6+i];
			}

			offset = offset + 57;
		}
		else
		{
			hidprint("Error backup file too large");
			NEO_Color = 1;
			blink(6);
			CPU_RESTART();
		}
		return;
	}
	else
	{ //last packet
		if (offset <= (18000 - 57) && buffer[5] <= 57)
		{
			#ifdef DEBUG
			Serial.print("Restore packet received =");
			byteprint(buffer + 6, buffer[5]);
			#endif
			memcpy(large_temp + offset, buffer + 6, buffer[5]);

			offset = offset + buffer[5];
		}
		else
		{
			hidprint("Error backup file too large");
			NEO_Color = 1;
			blink(6);
			CPU_RESTART();
		}
#ifdef DEBUG
		Serial.print("Length of backup file = ");
		Serial.println(offset);
#endif

		uint8_t temp[MAX_RSA_KEY_SIZE + 7];
		uint8_t *ptr;
		uint8_t slot;

		if (offset == 0)
		{
			CPU_RESTART();
		}

		//DECRYPT
		okeeprom_eeget_backupkey(&slot);
		offset--;
#ifdef DEBUG
		Serial.print("Type of Backup Key = ");
		Serial.println(large_temp[offset]);
#endif
		if (slot == 0)
		{
			hidprint("Error no backup key set");
			NEO_Color = 1;
			blink(6);
			CPU_RESTART();
		}
		else if (slot > 100)
		{
			okcore_flashget_ECC(slot);

#ifdef DEBUG
			Serial.println("Slot");
			Serial.println(slot);
			Serial.println("Private = ");
			byteprint(ecc_private_key, 32);
			Serial.println("Type = ");
			Serial.println(type);
#endif
			if (type != (large_temp[offset] - 100))
			{
				hidprint("Error key type used for backup does not match");
				NEO_Color = 1;
				blink(6);
				CPU_RESTART();
			}
			else
			{
				uint8_t iv[12];
				offset = offset - 12;
				memcpy(iv, large_temp + offset, 12);
				okcrypto_shared_secret(ecc_public_key, temp);

#ifdef DEBUG
				Serial.println("Secret = ");
				byteprint(temp, 32);
				Serial.println("IV = ");
				byteprint(iv, 12);
#endif

				byteprint(temp, 32);
				SHA256_CTX context;
				sha256_init(&context);
				sha256_update(&context, temp, 32);			 //add secret
				sha256_update(&context, ecc_public_key, 32); //add public key
				sha256_update(&context, iv, 12);			 //add AES GCM IV
				sha256_final(&context, temp);
				if (profilemode != NONENCRYPTEDPROFILE)
				{
				#ifdef STD_VERSION
				okcrypto_aes_gcm_decrypt2(large_temp, iv, temp, offset, false);
				#endif
				}
			}
		}
		else if (slot <= 4)
		{
			unsigned int len = 0;
			okcore_flashget_RSA(slot);
			if (type != large_temp[offset])
			{
				hidprint("Error key type used for backup does not match");
				NEO_Color = 1;
				blink(6);
				CPU_RESTART();
			}
			else
			{
				uint8_t temp2[512];
				offset = offset - (type * 128);
				memcpy(temp, large_temp + offset, (type * 128));
#ifdef DEBUG
				Serial.println("RSA Encrypted AES Key = ");
				byteprint(temp, (type * 128));
#endif
				rsa_decrypt(&len, temp, temp2);
#ifdef DEBUG
				Serial.println("AES KEY = ");
				byteprint(temp2, 32);
#endif
				uint8_t iv[12] = "BACKUP12345";
				if (profilemode != NONENCRYPTEDPROFILE)
				{
				#ifdef STD_VERSION
				okcrypto_aes_gcm_decrypt2(large_temp, iv, temp2, offset, false);
				#endif
				}
				//No need for unique IVs when random key used
			}
		}

#ifdef DEBUG
		Serial.print("backup file received =");
		byteprint(large_temp, offset);
#endif
		large_temp[offset + 1] = 0xFC;
		ptr = large_temp;
		if (*ptr < 0xFD)
		{
			hidprint("Error incorrect backup key set");
#ifdef DEBUG
			Serial.print("Error incorrect backup key set");
#endif
			blink(6);
			CPU_RESTART();
		}

#ifdef OK_Color
		setcolor(45); //Yellow
#endif
		while (*ptr)
		{
			if (*ptr == 0xFF)
			{
				memset(temp, 0, sizeof(temp));
				temp[0] = 0xBA;
				temp[1] = 0xFF;
				temp[2] = 0xFF;
				temp[3] = 0xFF;
				temp[4] = OKSETSLOT;
				ptr++;
				temp[5] = *ptr; //Slot
				ptr++;
				temp[6] = *ptr; //Value
				ptr++;
				if (temp[6] == 10)
				{ //Yubikey OTP
					uint8_t ctr[2];
					uint8_t ykslot = temp[5];
					if (ykslot == 0) {
						memcpy(temp + 7, ptr, (EElen_aeskey + EElen_private + EElen_public));
						set_slot(temp);					
						ptr = ptr + EElen_aeskey + EElen_private + EElen_public;
					} else { 
						memcpy(temp + 7, ptr, (EElen_aeskey + EElen_private + 16));
						set_slot(temp);
						ptr = ptr + EElen_aeskey + EElen_private + 16;
					} 
					ctr[0] = *ptr;
					ptr++;
					ctr[1] = *ptr;
					uint16_t counter = ctr[0] << 8 | ctr[1];
					counter += 300; //Increment by 300
					ctr[0] = counter >> 8 & 0xFF;
					ctr[1] = counter & 0xFF;

					yubikey_eeset_counter(ctr, ykslot);				
					#ifdef DEBUG
					Serial.print("New Yubikey Counter =");
					byteprint(ctr, 2);
					#endif
					ptr++;
					memset(temp, 0, sizeof(temp));
				}
				else if (temp[6] == 9 || temp[6] == 29)
				{ //TOTP or HMAC
					int len = *ptr;
					ptr++;
					memcpy(temp + 7, ptr, len);
					set_slot(temp);
					memset(temp, 0, sizeof(temp));
					ptr = ptr + len;
				}
				else if (temp[6] == 11)
				{ //lockout time
					temp[7] = *ptr;
					set_slot(temp);
					memset(temp, 0, sizeof(temp));
					ptr++;
				}
				else
				{
					temp[7] = *ptr;
					int i = 8;
					ptr++;
					while (*ptr != 0xFF && *ptr != 0xFE && *ptr != 0xFD && *ptr != 0xFC)
					{
						temp[i] = *ptr;
						ptr++;
						i++;
					}
					set_slot(temp);
				}
			}
			else if (*ptr == 0xFE)
			{ //Finished slot restore
				if (*(ptr+1)== 0) { //Authenticator state
					ptr+=2;
					//set auth state
					#ifdef DEBUG
					Serial.print("Restore auth state");
					byteprint(ptr, sizeof(AuthenticatorState));
					#endif
					ctap_flash (0, ptr, sizeof(AuthenticatorState), 4);
					ptr = ptr + sizeof(AuthenticatorState);
					offset = offset - (sizeof(AuthenticatorState) + 2);
				} else if (*(ptr+1)>= 200) { //Resident Keys
					ptr++;
					//set rk # ptr - 200 
					int rklen;
					#ifdef DEBUG
					Serial.print("Restore rk num = ");
					Serial.println(*ptr);
					byteprint(ptr+1, sizeof(CTAP_residentKey));
					#endif
					if (*(ptr + 392 + 1) == 0xFE && *(ptr + 392 + 2) > *ptr) { // 392 size in beta8 fw
						rklen=392;
					} else if (*(ptr + 441 + 1) == 0xFE && *(ptr + 441 + 2) > *ptr)  { // 441 size after beta8 fw
						rklen=441;
					} else if (*(ptr + 392 + 1) == 0) {
						rklen=392;
					} else {
						rklen=441;
					}
					ctap_flash((*ptr-200), ptr+1, rklen, 2);
					ptr = ptr + rklen + 1;
					offset = offset - rklen + 2;
				}
				else {
					memset(temp, 0, sizeof(temp));
					temp[0] = 0xBA;
					temp[1] = 0xFF;
					temp[2] = 0xFF;
					temp[3] = 0xFF;
					temp[4] = OKSETPRIV;
					ptr++;
					temp[5] = *ptr; //Slot
					ptr++;
					temp[6] = *ptr; //Key type
					if (temp[5] > 100)
					{ //We know its an ECC key
	#ifdef DEBUG
						Serial.print("Restore ECC key");
						Serial.print("Type");
						Serial.print(temp[6]);
						Serial.print("slot");
						Serial.print(temp[5]);
	#endif
						ptr++;									 //Start of Key
						memcpy(temp + 7, ptr, MAX_ECC_KEY_SIZE); //Size of ECC key 32
						set_private(temp);
						ptr = ptr + MAX_ECC_KEY_SIZE;
						offset = offset - (MAX_ECC_KEY_SIZE + 3);
					}
					else if ((temp[6] & 0x0F) == 1)
					{ //Expect 128 Bytes
	#ifdef DEBUG
						Serial.print("Restore RSA 1024 key");
	#endif
						ptr++;
						memcpy(temp + 7, ptr, 128);
						set_private(temp);
						ptr = ptr + 128;
						offset = offset - 131;
					}
					else if ((temp[6] & 0x0F) == 2)
					{ //Expect 256 Bytes
	#ifdef DEBUG
						Serial.print("Restore RSA 2048 key");
	#endif
						ptr++;
						memcpy(temp + 7, ptr, 256);
						set_private(temp);
						ptr = ptr + 256;
						offset = offset - 259;
					}
					else if ((temp[6] & 0x0F) == 3)
					{ //Expect 384 Bytes
	#ifdef DEBUG
						Serial.print("Restore RSA 3072 key");
	#endif
						ptr++;
						memcpy(temp + 7, ptr, 384);
						set_private(temp);
						ptr = ptr + 384;
						offset = offset - 387;
					}
					else if ((temp[6] & 0x0F) == 4)
					{ //Expect 512 Bytes
	#ifdef DEBUG
						Serial.print("Restore RSA 4096 key");
	#endif
						ptr++;
						memcpy(temp + 7, ptr, 512);
						set_private(temp);
						ptr = ptr + 512;
						offset = offset - 515;
					}
					else
					{
	#ifdef DEBUG
						Serial.print("Error key configuration backup file format incorrect");
	#endif
						hidprint("Error key configuration backup file format incorrect");
						NEO_Color = 1;
						blink(6);
						CPU_RESTART();
					}
				}
			}
			else if (*ptr == 0xFD)
			{
				//int temp2;
				//memset(temp, 0, sizeof(temp));
				//temp[0] = 0xBA;
				//temp[1] = 0xFF;
				//temp[2] = 0xFF;
				//temp[3] = 0xFF;
				//temp[4] = OKSETU2FPRIV;
				ptr++;
				offset--;
				//memcpy(temp + 5, ptr, 32);
				//set_u2f_priv(temp);
				ptr = ptr + 32;
				offset = offset - 32;
				// For backward compatability with older versions, used to backup U2F counter
				offset = offset - 2;
				ptr = ptr + 2;
				//memcpy(temp, ptr, 2);
				//temp2 = temp[0] << 8 | temp[1];
				//Set U2F Certificate size
				//okeeprom_eeset_U2Fcertlen(temp);
				offset = offset - 2;
				ptr = ptr + 2;
				//large_temp[0] = 0xBA;
				//large_temp[1] = 0xFF;
				//large_temp[2] = 0xFF;
				//large_temp[3] = 0xFF;
				//large_temp[4] = OKSETU2FCERT;
				//large_temp[5] = 0xBA;
				//if (temp2 < 769)
				//{
				//	memcpy(large_temp + 6, ptr, temp2);
				//	large_buffer_len = temp2;
				//	set_u2f_cert(large_temp);
				//}
			}
			else
			{
				break;
			}
		}
		hidprint("Successfully loaded backup");
#ifdef DEBUG
		Serial.print("Successfully loaded backup");
#endif
		delay(1000);
		hidprint("Remove and Reinsert OnlyKey to complete restore");
		fadeoff(0);
		delay(500);
		CPU_RESTART();
		while (1 == 1)
		{
			blink(3);
		}
	}
#endif
}

void process_packets(uint8_t *buffer, int len, uint8_t *blocknum)
{
	wipedata(); //Wait 5 seconds to receive packets
	pending_operation=CTAP2_ERR_NO_OPERATION_PENDING;
	//Receive APDU Data
	/* Not currently using this, Ledger APDU format 
    if (blocknum[0]) { //Not first packet, up to 59 bytes
      int offset = (blocknum[0]*59)+52;
      if (offset <= (int)(LARGE_BUFFER_SIZE - 59)) {
      memcpy(large_buffer+offset-59, buffer+5, 59);
      Serial.print("Received block: ");
      Serial.println(blocknum[0]);
      byteprint(large_buffer, offset);
      if (offset >= large_buffer_len) {
        Serial.print("Received final block");
        if (large_buffer_len<=57) {
          done_process_single();
          return;
        }
        large_buffer_offset=large_buffer_len;
        done_process_packets ();
        }
      }
    } else if (len) { //first block 52 bytes
      large_buffer_len=len-5; //Total len to expect minus head
      packet_buffer_details[0] = buffer[7]; //CID
      packet_buffer_details[1] = buffer[8]; //opt1
      packet_buffer_details[2] = buffer[9]; //opt2
      packet_buffer_details[3] = buffer[0]; //channelid
      packet_buffer_details[4] = buffer[1]; //chanelid
      if (large_buffer_len<=52) {
        memcpy(large_buffer, buffer+9, large_buffer_len);
        done_process_single ();
        return;
      }
      // Todo store CRC and then check when complete message arrives
      memcpy(large_buffer, buffer+9, 52);
      Serial.println("Received first block");
      byteprint(large_buffer, 52);
    }
	*/
	// Not APDU, Single 64 byte message
	if (!packet_buffer_details[0] && !packet_buffer_details[1])
	{
		packet_buffer_details[0] = buffer[4]; //CMD
		packet_buffer_details[1] = buffer[5]; // SLOT
		packet_buffer_details[2] = outputmode; // Outputmode
	}
	else if (packet_buffer_details[0] != buffer[4] && packet_buffer_details[1] != buffer[5])
	{
		return; // error, can't parse packets of different type
	}
	if (buffer[6] == 0xFF) //Not last packet
	{
		if (packet_buffer_offset <= (int)(PACKET_BUFFER_SIZE - 57))
		{
			memcpy(packet_buffer + packet_buffer_offset, buffer + 7, 57);
			packet_buffer_offset = packet_buffer_offset + 57;
			byteprint(packet_buffer, packet_buffer_offset);
		}
		else
		{
			hidprint("Error packets received exceeded size limit");
			return;
		}
	}
	else
	{ //Last packet
		if (packet_buffer_offset <= (int)(PACKET_BUFFER_SIZE - 57) && buffer[6] <= 57 && buffer[6] >= 1)
		{
			memcpy(packet_buffer + packet_buffer_offset, buffer + 7, buffer[6]);
			packet_buffer_offset = packet_buffer_offset + buffer[6];
			RNG2(packet_buffer_details + 3, 2);
			byteprint(packet_buffer, packet_buffer_offset);
			done_process_packets();
		}
		else
		{
			hidprint("Error packets received exceeded size limit");
			return;
		}
	}
	return;
}

/* Not currently using Ledger APDU
void done_process_single () {
  SoftTimer.remove(&Wipedata); //Cancel this we got all packets
  memset(recv_buffer, 0xFF, 4);
  recv_buffer[4] = packet_buffer_details[0]; //MSG
  recv_buffer[5] = packet_buffer_details[1]; //Slot
  recv_buffer[6] = packet_buffer_details[2]; //Key type
  memset(recv_buffer+7, 0, 64);
  if (packet_buffer_details[2]) {
    memmove(recv_buffer+7, large_buffer, large_buffer_len);
  } else if (packet_buffer_details[1]) {
    memmove(recv_buffer+6, large_buffer, large_buffer_len);
  } else {
    memmove(recv_buffer+5, large_buffer, large_buffer_len);
  }
  large_buffer_len=0;
  Serial.println("Processing single");
  byteprint(recv_buffer, 64);
  recvmsg(1);
  memset(large_buffer, 0, LARGE_BUFFER_SIZE);
  return;
}

*/

void done_process_packets()
{
	uint8_t temp[32];
	SoftTimer.remove(&Wipedata); //Cancel this we got all packets
	SoftTimer.remove(&Endfade);
	#ifdef DEBUG
	Serial.println("done_process_packets");
	#endif
	isfade = 1;
	derived_key_challenge_mode = 0;
	stored_key_challenge_mode = 0;
	CRYPTO_AUTH = 1;
	fadeoffafter20(); //Wipe and fadeoff after 20 seconds
	if (packet_buffer_details[1] > 200) { 
		okeeprom_eeget_derived_key_challenge_mode(&derived_key_challenge_mode);
	}
	if (packet_buffer_details[1] < 5 || (packet_buffer_details[1] > 100 && packet_buffer_details[1] <= 116)) { 
		okeeprom_eeget_stored_key_challenge_mode(&stored_key_challenge_mode);
	}
	#ifdef STD_VERSION
	if ((is_bit_set(derived_key_challenge_mode, 0))  || stored_key_challenge_mode) {
		CRYPTO_AUTH = 3;
	} else {
		SHA256_CTX msg_hash;
		sha256_init(&msg_hash);
		sha256_update(&msg_hash, packet_buffer, packet_buffer_offset); //add data to sign
		sha256_final(&msg_hash, temp);					//Temporarily store hash
        if (onlykeyhw==OK_HW_DUO) {
            Challenge_button1 = (temp[0] % 3) + '0' + 1;	//Get value 1-6 for challenge 1
            Challenge_button2 = (temp[15] % 3) + '0' + 1;	//Get value 1-6 for challenge 2
            Challenge_button3 = (temp[31] % 3) + '0' + 1;	//Get value 1-6 for challenge 3	
        } else {
            Challenge_button1 = (temp[0] % 6) + '0' + 1;	//Get value 1-6 for challenge 1
            Challenge_button2 = (temp[15] % 6) + '0' + 1;	//Get value 1-6 for challenge 2
            Challenge_button3 = (temp[31] % 6) + '0' + 1;	//Get value 1-6 for challenge 3	
        }
	}
	#endif
	#ifdef DEBUG
	Serial.println("Received Message");
	byteprint(packet_buffer, packet_buffer_offset);
	#endif
	okcore_aes_gcm_encrypt(packet_buffer, packet_buffer_details[0], packet_buffer_details[1], profilekey, packet_buffer_offset);
	// Just in case there is still a response stored
	large_resp_buffer_offset = 0;
	memset(large_resp_buffer, 0, large_resp_buffer_offset);
	// Move encrypted data to large_buffer
	large_buffer_offset = packet_buffer_offset;
	memmove(large_buffer, packet_buffer, packet_buffer_offset);
	packet_buffer_offset=0;
	#ifdef DEBUG
	Serial.println("Encrypted Buffer");
	byteprint(large_buffer, large_buffer_offset);
	#endif
	fadeon(NEO_Color);
}

int internal_temp () {
	//unsigned int temp;
	#ifdef DEBUG
	//Serial.println("VREF");
	//for (int i=0; i<8; i++) {
	//	temp = analogRead(39) + i;
	//}
	//temp = temp/8;
	//Serial.println(temp);
	//Serial.println("TEMP SENSOR");
	//for (int i=0; i<8; i++) {
	//	temp = analogRead(38) + i;
	//}
	//temp = temp/8;
	//return temp;
	#endif
	return analogRead(38);
}

int RNG2(uint8_t *dest, unsigned size)
{
	// Generate output whenever 32 bytes of entropy have been accumulated.
	// The first time through, we wait for 48 bytes for a full entropy pool.
	while (!RNG.available(length))
	{
		//Serial.println("waiting for random number");
		rngloop(); //Gather entropy
	}
	RNG.rand(dest, size);
	length = 32;
#ifdef DEBUG
	Serial.println();
	Serial.print("Generating random number of size = ");
	Serial.print(size);
	byteprint(dest, size);
#endif
	return 1;
}

void process_setreport()
{
	// HMACSHA1 - This is the HMACSHA1 Challenge default size is 32	bytes
#ifdef DEBUG
	Serial.println("Received USB Keyboard Packets");
	byteprint(keyboard_buffer, KEYBOARD_BUFFER_SIZE);
#endif
	uint8_t temp[64];

	if (initialized && !unlocked) {
		memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
		memset(setBuffer, 0, 9);
		getBuffer[7] = 0;
		return;
	}

	uint8_t *ptr;
	uint8_t index = 0;
	ptr = keyboard_buffer + 22;
	if ((keyboard_buffer[64] == 1 || (keyboard_buffer[64] >= 3 && keyboard_buffer[64] <= 27)) && initialized && unlocked)
	{ 
		if (profilemode != NONENCRYPTEDPROFILE)
			{
			#ifdef STD_VERSION
			uint8_t slot = keyboard_buffer[64];
			if (keyboard_buffer[45] == 5 || keyboard_buffer[45] == 0) { // Request to write or wipe
				getBuffer[5] = 0;
				getBuffer[7] = 0x89;
				memset(setBuffer, 0, 9);
				extern int check_crc(uint8_t * buffer);
				if (!check_crc(keyboard_buffer) || CRYPTO_AUTH)
				{
					memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
					return;
				}
				outputmode=RAW_USB;
				if (keyboard_buffer[46] == 0x60 || keyboard_buffer[46] == 0x40) { // Set HMAC Key using Yklib 
					if (slot < 3) slot = 1;
					else slot = slot - 3;
					memmove(recv_buffer+23, keyboard_buffer+16, 4);
					memmove(recv_buffer+7, keyboard_buffer+22, 16); // HMAC key split for some reason
					memset(recv_buffer+27, 0, 37);
					recv_buffer[4] = OKSETPRIV;
					if (keyboard_buffer[64] == 1) recv_buffer[5] = RESERVED_KEY_HMACSHA1_1;
					else if (keyboard_buffer[64] == 3) recv_buffer[5] = RESERVED_KEY_HMACSHA1_2;
					else recv_buffer[5] = slot;
					recv_buffer[6] = KEYTYPE_HMACSHA1;
					byteprint(recv_buffer,64);
					if (recv_buffer[7]+recv_buffer[8]+recv_buffer[9]+recv_buffer[10]+recv_buffer[11] == 0) {
						// Wipe CR slot
						temp[5] = recv_buffer[5];
						okeeprom_eeset_hmac_challengemode(0); // Reset to default both slots require button press
						if (recv_buffer[5] == RESERVED_KEY_HMACSHA1_1 || recv_buffer[5] == RESERVED_KEY_HMACSHA1_2) {
							wipe_private(temp, false);
						} else {
							recv_buffer[4] = OKWIPESLOT;
							recv_buffer[5] = slot;
							recv_buffer[6] = 29; // HMAC
							recv_buffer[7] = 1; // Authlite no button press required
							recvmsg(1);
						}
					}
					else {
						uint8_t mode = 0;	
						uint8_t KEYtype = 0;		
						// Authlite requires no press required
						// Get current mode
						okeeprom_eeget_hmac_challengemode(&mode); 
						delay(100);
						if (mode==1) { // Both CR slots already require no button press
						} else if (mode==recv_buffer[5]) { // Only current CR slot already require no button press
						} else if (mode) { // Only NOT current CR slot already require no button press
							mode = 1; // Now Both CR slots require no button press
						} else { // Niether CR slot already require no button press
							mode = recv_buffer[5]; // Now current CR slot require no button press
						}
						
						if (recv_buffer[5] == RESERVED_KEY_HMACSHA1_1 || recv_buffer[5] == RESERVED_KEY_HMACSHA1_2) {
							set_private(recv_buffer);
							// Check if private set successfully
							if (keyboard_buffer[64] == 1) {
								okeeprom_eeget_ecckey(&KEYtype, RESERVED_KEY_HMACSHA1_1); //Key Type (1-4) and slot (101-132)
							}
							else {
								okeeprom_eeget_ecckey(&KEYtype, RESERVED_KEY_HMACSHA1_2); //Key Type (1-4) and slot (101-132)
							}
							// If private set, write challenge mode
							if (KEYtype == 9) {
								okeeprom_eeset_hmac_challengemode(&mode); 	
							} else {
								// Return CR error?
							}
						} else if (recv_buffer[5]) {
							recv_buffer[4] = OKSETSLOT;
							recv_buffer[5] = slot;
							recv_buffer[6] = 29; // HMAC
							memmove(recv_buffer + 8, recv_buffer + 7, 20);
							recv_buffer[7] = 1; // Authlite no button press required
							recvmsg(1);
						}
					}
					sess_counter++;
				} else if ((keyboard_buffer[46] == 0 && keyboard_buffer[44]) || keyboard_buffer[46] == TKTFLAG_APPEND_CR || keyboard_buffer[46] == TKTFLAG_APPEND_DELAY2 || keyboard_buffer[46] == TKTFLAG_APPEND_DELAY1 || keyboard_buffer[46] == TKTFLAG_APPEND_TAB2 || keyboard_buffer[46] == TKTFLAG_APPEND_TAB1 || keyboard_buffer[46] == TKTFLAG_TAB_FIRST) { // Set Yubi OTP Key
					if (slot < 3) slot = 1;
					else slot = slot - 1;
					recv_buffer[4] = OKSETSLOT;
					// Pacing
					if (keyboard_buffer[47] == CFGFLAG_PACING_10MS) {
						// set speed to medium
						TYPESPEED[0] = 4;
						okeeprom_eeset_typespeed((uint8_t*)TYPESPEED, 0);
					} else if (keyboard_buffer[47] == CFGFLAG_PACING_20MS) {
						// set speed to slow
						TYPESPEED[0] = 5;
						okeeprom_eeset_typespeed((uint8_t*)TYPESPEED, 0);
					} else {
						// set speed to fast
						TYPESPEED[0] = 3;
						okeeprom_eeset_typespeed((uint8_t*)TYPESPEED, 0);
					}
					// After OTP
					uint8_t temp;
					uint8_t temp2;
					uint8_t mask;
					uint8_t addcharslot = slot;
					if (profilemode)
						addcharslot = addcharslot + 12;
					if (keyboard_buffer[46] == 0x04) {
						okeeprom_eeget_addchar(&temp, addcharslot);
						mask = 0b11000000;
						temp2 = 1 << 7;
						temp2 = (temp & ~mask) | (temp2 & mask);
						okeeprom_eeset_addchar(&temp2, addcharslot);
					} else if (keyboard_buffer[46] == 0x20) {
						okeeprom_eeget_addchar(&temp, addcharslot);
						mask = 0b11000000;
						temp2 = 1 << 6;
						temp2 = (temp & ~mask) | (temp2 & mask);
						okeeprom_eeset_addchar(&temp2, addcharslot);
					} else {
						//No after otp
						okeeprom_eeget_addchar(&temp, addcharslot);
						mask = 0b11000000;
						temp2 = 0;
						temp2 = (temp & ~mask) | (temp2 & mask);
						okeeprom_eeset_addchar(&temp2, addcharslot);
					}
					recv_buffer[5] = slot; //OTP_SLOT_1 - OTP_SLOT_12
					recv_buffer[6] = 10; // Yubi OTP
					uint8_t publen = 16; // Max public size
					memset(recv_buffer+7, 0, sizeof(recv_buffer)-7);
					memmove(recv_buffer+7, keyboard_buffer, publen); //Public
					for (publen; publen > 1; publen--) { // Public ID 2-16 bytes
						if (recv_buffer[7+publen-1] != 0) {
							break;
						}
					}
					memmove(recv_buffer+7 + publen, keyboard_buffer+16, 6); //Private
					memmove(recv_buffer+7 + publen + 6, keyboard_buffer+22, 16); //Secret			
					byteprint(recv_buffer,64);
					if (recv_buffer[7]+recv_buffer[8]+recv_buffer[9]+recv_buffer[10]+recv_buffer[11] == 0) {
						wipe_slot(recv_buffer);
						okeeprom_eeget_addchar(&temp, addcharslot);
						mask = 0b11000000;
						temp2 = 0;
						temp2 = (temp & ~mask) | (temp2 & mask);
						okeeprom_eeset_addchar(&temp2, addcharslot);
					}
					else recvmsg(1);
					sess_counter++;
				} 
				getBuffer[4] = sess_counter;
				getBuffer[5] = 3;
				getBuffer[7] = 0;
				byteprint(getBuffer, 8);
				memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
				memset(recv_buffer, 0, sizeof(recv_buffer));
				return;
			}
		#endif
		}
	}

	getBuffer[7] = 0xaf;
	setBuffer[8] = 0;
	while (*ptr && *ptr == 0x3f)
	{
		ptr++;
		index++;
	}
	if (index > 9)
	{ // Test
		memset(setBuffer, 0, 9);
		memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
		#ifdef DEBUG
		Serial.println("Received HMACSHA1 Test");
		#endif
		return;
	} else if ((keyboard_buffer[64] == 0x30 || keyboard_buffer[64] == 0x38 || (keyboard_buffer[64] >= 1 && keyboard_buffer[64] <= 12)) && initialized && unlocked)
	{ //HMACSHA1}
		if (profilemode != NONENCRYPTEDPROFILE)
			{
			#ifdef STD_VERSION
			#ifdef DEBUG
			Serial.println("Received HMACSHA1 Message");
			#endif
			uint8_t hmac_challenge_disabled = 0;
			uint8_t crslot = 1;
			okeeprom_eeget_hmac_challengemode(&hmac_challenge_disabled);
			if (keyboard_buffer[64] == 0x30 ) { // Yklib HMAC Slot 1 selected, 0x00 for slot 1
				crslot = RESERVED_KEY_HMACSHA1_1;
			}
			else if (keyboard_buffer[64] == 0x38 ) { // Yklib HMAC Slot 2 selected, 0x08 for slot 2
				crslot = RESERVED_KEY_HMACSHA1_2;
    		} else { // Use new HMAC slot format (24 slots)
				if (profilemode) keyboard_buffer[64] = keyboard_buffer[64] + 12; // 2nd profile slots 12 -24 
				if (keyboard_buffer[64] >= 1 && keyboard_buffer[64] <= 24) {
					hmac_challenge_disabled = okcore_flashget_hmac(ecc_private_key, keyboard_buffer[64]);
					memset(ecc_private_key, 0, sizeof(ecc_private_key));
				} else {
					return;
				}
    		} 
			#ifdef DEBUG
			Serial.println("Challenge Disabled");
			Serial.println(hmac_challenge_disabled);
			#endif
			if (hmac_challenge_disabled == 1 || hmac_challenge_disabled == crslot) { // 0 = Default physical presence required, 1 = No physical presence required for HMAC
				CRYPTO_AUTH = 4;
				okcrypto_hmacsha1();
				CRYPTO_AUTH = 0;
				memset(setBuffer, 0, 9);
			} else {
				CRYPTO_AUTH = 3;
				packet_buffer_details[0] = OKHMAC;
				SoftTimer.remove(&Wipedata);
				fadeon(43);		  //Yellow
				fadeoffafter20(); //Wipe and fadeoff after 20 seconds
				memset(setBuffer, 0, 9);
			}
			#endif
		}
	} else if ((keyboard_buffer[64] == 0x20 || keyboard_buffer[64] == 0x28) && initialized && unlocked)
	{ //Yubi OTP}
		if (profilemode != NONENCRYPTEDPROFILE)
			{
			#ifdef STD_VERSION
			#ifdef DEBUG
			Serial.println("Received Yubi OTP Message");
			#endif
			#endif
		}
	} 
	else if (keyboard_buffer[0] == 0xFF && keyboard_buffer[1] == 0xFF && keyboard_buffer[2] == 0xFF && keyboard_buffer[3] == 0xFF)
	{ //Other
		extern int check_crc(uint8_t * buffer);
		if (!check_crc(keyboard_buffer) || CRYPTO_AUTH)
		{
			memset(setBuffer, 0, 9);
			memset(keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
			return;
		}
		memmove(recv_buffer, keyboard_buffer, 64);
		if (initialized && !unlocked) hidprint("INITIALIZED");
		else recvmsg(1);
		return;
	}
}

int check_crc(uint8_t* buffer) {
	uint16_t crc;
	uint8_t temp[2];
	//Check CRC of Input
	crc = yubikey_crc16 (buffer, 64);
	temp[0] = crc & 0xFF;
	temp[1] = crc >> 8;
	if (buffer[65] != temp[0] || buffer[66] != temp[1]) {
		//CRC Check failed
	#ifdef DEBUG
			Serial.print("HMACSHA1 Input CRC Check Failed");
			Serial.println(crc);
	#endif
	return 0;
	}
	return 1;
}

void okcore_aes_gcm_encrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len) {
	if (profilemode != NONENCRYPTEDPROFILE)
	{
		#ifdef STD_VERSION
		okcrypto_aes_gcm_encrypt(state, slot, value, key, len);
		#endif
	}
}

void okcore_aes_gcm_decrypt(uint8_t *state, uint8_t slot, uint8_t value, const uint8_t *key, int len)
{
	if (profilemode != NONENCRYPTEDPROFILE)
	{
		#ifdef STD_VERSION
		okcrypto_aes_gcm_decrypt(state, slot, value, key, len);
		#endif
	}
}

void okcore_aes_cbc_encrypt (uint8_t * state, const uint8_t * key, int len)
{
	#ifdef STD_VERSION
	// newPinEnc uses IV=0
	// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.pdf
	uint8_t iv[16] = {0};
	okcrypto_aes_cbc_encrypt (state, iv, key, len);
	#endif
}

void okcore_aes_cbc_decrypt (uint8_t * state, const uint8_t * key, int len)
{
	#ifdef STD_VERSION
	// newPinEnc uses IV=0
	// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.pdf
	uint8_t iv[16] = {0};
	okcrypto_aes_cbc_decrypt (state, iv, key, len);
	#endif
}

char * HW_MODEL(char const * in) {
	// HW_MODEL p=OnlyKey DUO with PIN, n=OnlyKey DUO without PIN, c=OnlyKey LQFP or BGA w/dual LEDs, o=Discontinued OnlyKey Orignal
	char out[strlen(in)+2];
	memcpy(out,in,strlen(in));
	#ifdef OK_Color
	if (onlykeyhw==OK_HW_DUO) {
		if (Duo_config[0]==1) {
			out[sizeof(out)-2] = 'n';
		} else {
			out[sizeof(out)-2] = 'p';	
		}
	} else {
		out[sizeof(out)-2] = 'c';
	}
	#else
	out[sizeof(out)-2] = 'o';
	#endif
	out[sizeof(out)-1] = 0;
	return (char*)out;
}

void okcore_pin_login ()
{
	#ifdef STD_VERSION
	//PIN attempt stored in recv_buffer
	char * ptr = (char *)recv_buffer+5;
	uint8_t index=0;
	while (index<=15 && *ptr >= '0') {
		password.append(*ptr);
		index++;
		ptr++;
	}
	#endif
}

void ByteToChar2(uint8_t *bytes, char *chars, unsigned int count, unsigned int index)
{
	for (unsigned int i = 0; i < count; i++)
		chars[i + index] = (char)bytes[i];
}

void fw_version_changes() {
	uint8_t keytype;
	// todo get key from 128, if empty write key
	okeeprom_eeget_ecckey(&keytype, RESERVED_KEY_WEB_DERIVATION); 
	if (keytype!=0x61) { // Empty no Web Derivation Key, added in fw 2.1.0
		outputmode = DISCARD;
		recv_buffer[4] = OKSETPRIV;
		recv_buffer[5] = RESERVED_KEY_WEB_DERIVATION;
		recv_buffer[6] = 0x61;
		RNG2(recv_buffer + 7, 32);
		set_private(recv_buffer); //set RESERVED_KEY_WEB_DERIVATION slot 128
		memset(recv_buffer, 0, sizeof(recv_buffer));
		// Also wipe FIDO2 resident keys as these are now stored in new location
		ctap_flash(NULL, NULL, NULL, 5);
	}

}
