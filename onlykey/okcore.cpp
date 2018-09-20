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



#include "sha256.h"
#include <string.h>
#include <EEPROM.h>
#include <SoftTimer.h>
#include <DelayRun.h>
#include <password.h>
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include <RNG.h>
#include "T3MacLib.h"
#include "base64.h"
/*************************************/
//Neopixel color LED
/*************************************/
#ifdef OK_Color
#include "Adafruit_NeoPixel.h"
#define NEOPIN            10
#define NUMPIXELS      1
Adafruit_NeoPixel pixels = Adafruit_NeoPixel(NUMPIXELS, NEOPIN, NEO_GRB + NEO_KHZ800);
#endif
uint8_t NEO_Color;
/*************************************/
//Firmware Version Selection
/*************************************/
#ifdef US_VERSION
#include "yksim.h"
#include "uECC.h"
#include "ykcore.h"
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#endif
/*************************************/
uint32_t unixTimeStamp;
int PINSET = 0;
uint8_t profile2mode;
bool unlocked = false;
bool initialized = false;
bool configmode = false;
uint8_t TIMEOUT[1] = {30}; //Default 30 Min
uint8_t TYPESPEED[1] = {100}; //Default 100 Ms
extern uint8_t KeyboardLayout[1];
elapsedMillis idletimer;
/*************************************/
//softtimer
/*************************************/
Task FadeinTask(15, increment);
Task FadeoutTask(10, decrement);
DelayRun Wipedata(5000, wipebuffersafter5sec); //5 second delay to wipe data after last message
DelayRun Usertimeout(20000, fadeoffafter20sec); //20 second delay to wait for user
DelayRun Endfade(2500, fadeendafter2sec); //delay to prevent inadvertent button press after challenge PIN
uint8_t fade = 0;
uint8_t isfade = 0;
/*************************************/
//yubikey
/*************************************/
#ifdef US_VERSION
yubikey_ctx_st ctx;
#endif
/*************************************/
//Password.cpp Assignments
/*************************************/
Password password = Password( (char*) "not used" );
extern uint8_t profilekey[32];
extern uint8_t p1hash[32];
extern uint8_t sdhash[32];
extern uint8_t p2hash[32];
extern uint8_t nonce[32];
extern int integrityctr1;
extern int integrityctr2;
int initcheck;
/*************************************/
//PIN assignments
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
unsigned int touchread3;
unsigned int touchread4;
unsigned int touchread5;
unsigned int touchread6;
unsigned int touchread1ref = 1350;
unsigned int touchread2ref = 1350;
unsigned int touchread3ref = 1350;
unsigned int touchread4ref = 1350;
unsigned int touchread5ref = 1350;
unsigned int touchread6ref = 1450;
/*************************************/
//HID Report Assignments
/*************************************/
uint8_t setBuffer[64] = {0};
uint8_t getBuffer[64] = {0};
/*************************************/
//U2F Assignments
/*************************************/
uint8_t expected_next_packet;
int large_data_len;
int large_data_offset;
int packet_buffer_offset = 0;
uint8_t large_buffer[1024];
uint8_t large_resp_buffer[1024];
uint8_t packet_buffer[768];
uint8_t packet_buffer_details[2];
uint8_t recv_buffer[64];
uint8_t resp_buffer[64];
char attestation_pub[66];
char attestation_priv[33];
char attestation_der[768];
int outputU2F = 0;
/*************************************/
//ECC assignments
/*************************************/
#ifdef US_VERSION
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE*2)+1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
/*************************************/
/*************************************/
//RSA assignments
/*************************************/
extern uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
extern uint8_t type;
#endif
/*************************************/
//Crypto Challenge assignments
/*************************************/
uint8_t Challenge_button1 = 0;
uint8_t Challenge_button2 = 0;
uint8_t Challenge_button3 = 0;
uint8_t CRYPTO_AUTH = 0;
uint8_t sshchallengemode = 0;
uint8_t pgpchallengemode = 0;
/*************************************/
//built-in temperature sensor
/*************************************/
float temperaturev;
/*************************************/
/*************************************/
//RNG Assignments
/*************************************/
size_t length = 48; // First block should wait for the pool to fill up.

void recvmsg() {
  int n;
  n = RawHID.recv(recv_buffer, 0); // 0 timeout = do not wait
  
  //Integrity Check
  if (integrityctr1!=integrityctr2) {
	unlocked = false;
	CPU_RESTART();
	return;
  }
	
  if (n > 0) {
#ifdef DEBUG
	Serial.print(F("\n\nReceived packet"));
	byteprint(recv_buffer,64);
#endif

	  if (configmode==true && recv_buffer[4]!=OKSETSLOT && recv_buffer[4]!=OKSETPRIV && recv_buffer[4]!=OKRESTORE && recv_buffer[4]!=OKFWUPDATE) {
#ifdef DEBUG
	Serial.println("ERROR NOT SUPPORTED IN CONFIG MODE");
#endif
		return;
	  }

	  switch (recv_buffer[4]) {
	  case OKSETPIN:
	  if(profile2mode!=NOENCRYPT) {
	  if (!initcheck) SETPIN(recv_buffer);
	  } else {
	  if (!initcheck) SETPDPIN(recv_buffer);
	  }
	  return;
	  case OKSETSDPIN:
	  SETSDPIN(recv_buffer);
	  return;
	  case OKSETPDPIN:
	  if (!initcheck) SETPDPIN(recv_buffer);
	  return;
	  case OKSETTIME:
	  outputU2F = 0;
	  SETTIME(recv_buffer);
	  return;
	  case OKGETLABELS:
	   if(initialized==false && unlocked==true)
	   {
		hidprint("Error you must set a PIN first on OnlyKey");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
		if (recv_buffer[5] == 'k') GETKEYLABELS(2);
		else GETSLOTLABELS(2);
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKSETSLOT:
	   if(initialized==false && unlocked==true && integrityctr1==integrityctr2)
	   {
		if (recv_buffer[6] == 12 || recv_buffer[6] == 20) { //You can set wipemode and backupkeymode any time but they are set once settings
		if (recv_buffer[0] != 0xBA) SETSLOT(recv_buffer);
		} else {
		hidprint("Error you must set a PIN first on OnlyKey");
		}
		return;
	   }else if ((initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2) || (!initcheck && unlocked==true && initialized==true && integrityctr1==integrityctr2))
	   {
		if (recv_buffer[0] != 0xBA) SETSLOT(recv_buffer);
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKWIPESLOT:
	   if(initialized==false && unlocked==true)
	   {
		hidprint("Error you must set a PIN first on OnlyKey");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
		WIPESLOT(recv_buffer);
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKSETU2FPRIV:
	   if(initialized==false && unlocked==true)
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
		if(profile2mode!=NOENCRYPT) {
		#ifdef US_VERSION
		SETU2FPRIV(recv_buffer);
		#endif
		}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKWIPEU2FPRIV:
	   if(initialized==false && unlocked==true)
	   {
		hidprint("Error you must set a PIN first on OnlyKey");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
		if(profile2mode!=NOENCRYPT) {
		#ifdef US_VERSION
		WIPEU2FPRIV(recv_buffer);
		#endif
		}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKSETU2FCERT:
	   if(initialized==false && unlocked==true)
	   {
		hidprint("Error you must set a PIN first on OnlyKey");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
		if(profile2mode!=NOENCRYPT) {
		#ifdef US_VERSION
		if (recv_buffer[0] != 0xBA) SETU2FCERT(recv_buffer);
		#endif
		}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKWIPEU2FCERT:
	   if(initialized==false && unlocked==true)
	   {
		hidprint("Error you must set a PIN first on OnlyKey");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
		if(profile2mode!=NOENCRYPT) {
		#ifdef US_VERSION
		WIPEU2FCERT(recv_buffer);
		#endif
		}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKSETPRIV:
	   if ((initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && configmode==true) || (initialized==true && unlocked==true && !initcheck)) //Only permit loading keys on first use and while in config mode
	   {
				if(profile2mode!=NOENCRYPT) {
				#ifdef US_VERSION
				if (recv_buffer[0] != 0xBA) SETPRIV(recv_buffer);
				#endif
				}
	   }
	   else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && configmode==false) {
	   hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKWIPEPRIV:
		   if(initialized==false && unlocked==true)
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
				if(profile2mode!=NOENCRYPT) {
				#ifdef US_VERSION
				WIPEPRIV(recv_buffer);
				#endif
				}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKSIGN:
		   if(initialized==false && unlocked==true)
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && !CRYPTO_AUTH)
	   {
		if(profile2mode!=NOENCRYPT) {
		#ifdef US_VERSION
		NEO_Color = 213; //Purple
		fadeon();
		outputU2F = 0;
		SIGN(recv_buffer);
		#endif
		}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKDECRYPT:
		   if(initialized==false && unlocked==true)
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && !CRYPTO_AUTH)
	   {
		if(profile2mode!=NOENCRYPT) {
		#ifdef US_VERSION
		NEO_Color = 128; //Turquoise
		fadeon();
		outputU2F = 0;
		DECRYPT(recv_buffer);
		#endif
		}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKGETPUBKEY:
			if(initialized==false && unlocked==true)
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2)
	   {
				if(profile2mode!=NOENCRYPT) {
				#ifdef US_VERSION
				outputU2F = 0;
				GETPUBKEY(recv_buffer);
				#endif
				}
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKRESTORE:
			if(initialized==false && unlocked==true)
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if ((initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && configmode==true) || (initialized==true && unlocked==true && !initcheck && integrityctr1==integrityctr2)) //Only permit loading backup on first use and while in config mode
	   {
				if(profile2mode!=NOENCRYPT) {
				#ifdef US_VERSION
				RESTORE(recv_buffer);
				#endif
				}
	   }
	   else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && configmode==false) {
	   hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
	   }
	   else {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  case OKFWUPDATE:
			if(initialized==false && unlocked==true)
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if ((initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && configmode==true) || (!initcheck && unlocked==true && integrityctr1==integrityctr2)) //Only permit loading firmware on first use and while in config mode
	   {
			hidprint("SUCCESSFULL FW LOAD REQUEST, REBOOTING...");
			eeprom_write_byte(0x00, 1); //Go to bootloader
			eeprom_write_byte((unsigned char *)0x01, 1); //Firmware ready to load
			delay(100);
			CPU_RESTART();
	   }
	   else if (initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2 && configmode==false) {
	   hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
	   }
	   else {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
	  return;
	  default:
		if(profile2mode!=NOENCRYPT && initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2) {
		#ifdef US_VERSION
			recvu2fmsg(recv_buffer);
		#endif
		}
	  return;
	}
  } else {
	  if(profile2mode!=NOENCRYPT && initialized==true && unlocked==true && FTFL_FSEC==0x44 && integrityctr1==integrityctr2) {
	  #ifdef US_VERSION
	  u2fmsgtimeout(recv_buffer);
	  #endif
	  }
  }
}

int getCounter() {
  unsigned int eeAddress = EEpos_U2Fcounter; //EEPROM address to start reading from
  uint32_t counter;
  EEPROM.get( eeAddress, counter );
  return counter;
}

void setCounter(uint32_t counter)
{
  unsigned int eeAddress = EEpos_U2Fcounter; //EEPROM address to start reading from
  EEPROM.put( eeAddress, counter );
}

void SETPIN (uint8_t *buffer)
{
#ifdef DEBUG
      Serial.println("OKSETPIN MESSAGE RECEIVED");
#endif

if (PINSET > 3) PINSET = 0;


switch (PINSET) {
      case 0:
      password.reset();
#ifdef DEBUG
      Serial.println("Enter PIN");
#endif
      hidprint("OnlyKey is ready, enter your PIN");
      PINSET = 1;
      return;
      case 1:
      PINSET = 2;
      if(strlen(password.guess) > 6 && strlen(password.guess) < 11)
      {
#ifdef DEBUG
        Serial.println("Storing PIN");
#endif
        hidprint("Successful PIN entry");
		static char passguess[10];
      for (unsigned int i =0; i <= strlen(password.guess); i++) {
		passguess[i] = password.guess[i];
      }
		password.set(passguess);
        password.reset();
      }
      else
      {
#ifdef DEBUG
		Serial.println("Error PIN is not between 7 - 10 characters");
#endif
		hidprint("Error PIN is not between 7 - 10 characters");
        password.reset();
		PINSET = 0;
      }

      return;
      case 2:
#ifdef DEBUG
      Serial.println("Confirm PIN");
#endif
      hidprint("OnlyKey is ready, re-enter your PIN to confirm");
      PINSET = 3;
      return;
      case 3:
	  PINSET = 0;
       if(strlen(password.guess) >= 7 && strlen(password.guess) < 11)
      {

          if (password.evaluate()) {
#ifdef DEBUG
            Serial.println("Both PINs Match");
#endif
            //hidprint("Both PINs Match");
			uint8_t temp[32];
			uint8_t *ptr;
			ptr = temp;
			//Copy characters to byte array
			for (unsigned int i =0; i <= strlen(password.guess); i++) {
			temp[i] = (uint8_t)password.guess[i];
			}
			SHA256_CTX pinhash;
			sha256_init(&pinhash);
			sha256_update(&pinhash, temp, strlen(password.guess)); //Add new PIN to hash
			RNG2(ptr, 32); //Fill temp with random data
#ifdef DEBUG
			Serial.println("Generating NONCE");
#endif
			onlykey_flashset_noncehash (ptr); //Store in flash
			memcpy(nonce, ptr, 32);
			initialized=true;

			sha256_update(&pinhash, temp, 32); //Add nonce to hash
			sha256_final(&pinhash, temp); //Create hash and store in temp

			onlykey_flashset_pinhashpublic (ptr);
#ifdef DEBUG
	  		Serial.println();
			Serial.println("Successfully set PIN");
#endif
			hidprint("Successfully set PIN");
          }
          else {
#ifdef DEBUG
            Serial.println("Error PINs Don't Match");
#endif
			hidprint("Error PINs Don't Match");
			PINSET = 0;
          }
      }
      else
      {
#ifdef DEBUG
        Serial.println("Error PIN is not between 7 - 10 characters");
#endif
		hidprint("Error PIN is not between 7 - 10 characters");
		PINSET = 0;
      }
      password.reset();
      blink(3);
      return;
}
}

void SETSDPIN (uint8_t *buffer)
{
#ifdef DEBUG
      Serial.println("OKSETSDPIN MESSAGE RECEIVED");
#endif

	  if (PINSET < 4 || PINSET > 6) PINSET = 0;

      switch (PINSET) {
      case 0:
      password.reset();
#ifdef DEBUG
      Serial.println("Enter PIN");
#endif
      hidprint("OnlyKey is ready, enter your self-destruct PIN");
      PINSET = 4;
      return;
      case 4:
	  PINSET = 5;
      if(strlen(password.guess) >= 7 && strlen(password.guess) < 11)
      {
#ifdef DEBUG
        Serial.println("Storing PIN");
#endif
        hidprint("Successful PIN entry");
		static char passguess[10];
      for (unsigned int i =0; i <= strlen(password.guess); i++) {
		passguess[i] = password.guess[i];
      }
		password.set(passguess);
        password.reset();
      }
      else
      {
#ifdef DEBUG
		Serial.println("Error PIN is not between 7 - 10 characters");
#endif
		hidprint("Error PIN is not between 7 - 10 characters");
        password.reset();
		PINSET = 0;
      }

      return;
      case 5:
#ifdef DEBUG
      Serial.println("Confirm PIN");
#endif
      hidprint("OnlyKey is ready, re-enter your PIN to confirm");
      PINSET = 6;
      return;
      case 6:
	  PINSET = 0;
       if(strlen(password.guess) >= 7 && strlen(password.guess) < 11)
      {

          if (password.evaluate() == true) {
#ifdef DEBUG
            Serial.println("Both PINs Match");
#endif
            //hidprint("Both PINs Match");
		uint8_t temp[32];
		uint8_t *ptr;
		ptr = temp;
		//Copy characters to byte array
		for (unsigned int i =0; i <= strlen(password.guess); i++) {
		temp[i] = (uint8_t)password.guess[i];
		}
		SHA256_CTX pinhash;
		sha256_init(&pinhash);
		sha256_update(&pinhash, temp, strlen(password.guess)); //Add new PIN to hash
#ifdef DEBUG
		Serial.println("Getting NONCE");
#endif
		onlykey_flashget_noncehash (ptr, 32);

		sha256_update(&pinhash, temp, 32); //Add nonce to hash
		sha256_final(&pinhash, temp); //Create hash and store in temp
#ifdef DEBUG
		Serial.println("Hashing SDPIN and storing to Flash");
#endif
		onlykey_flashset_selfdestructhash (ptr);
		hidprint("Successfully set PIN");
          }
          else {
#ifdef DEBUG
            Serial.println("Error PINs Don't Match");
#endif
	    hidprint("Error PINs Don't Match");
          }
      }
      else
      {
#ifdef DEBUG
        Serial.println("Error PIN is not between 7 - 10 characters");
#endif
	hidprint("Error PIN is not between 7 - 10 characters");
      }
      password.reset();
      blink(3);
      return;
}
}

void SETPDPIN (uint8_t *buffer)
{
#ifdef DEBUG
      Serial.println("OKSETPDPIN MESSAGE RECEIVED");
#endif
	if (PINSET < 7) PINSET = 0;

	switch (PINSET) {
      case 0:
      password.reset();
#ifdef DEBUG
      Serial.println("Enter PIN");
#endif
      hidprint("OnlyKey is ready, enter your PIN");
      PINSET = 7;
      return;
      case 7:
      PINSET = 8;
      if(strlen(password.guess) >= 7 && strlen(password.guess) < 11)
      {
#ifdef DEBUG
        Serial.println("Storing PIN");
#endif
        hidprint("Successful PIN entry");
		static char passguess[10];
      for (unsigned int i =0; i <= strlen(password.guess); i++) {
		passguess[i] = password.guess[i];
      }
	password.set(passguess);
        password.reset();
      }
      else
      {
#ifdef DEBUG
	Serial.println("Error PIN is not between 7 - 10 characters");
#endif
	hidprint("Error PIN is not between 7 - 10 characters");
        password.reset();
	PINSET = 0;
      }
      return;
      case 8:
#ifdef DEBUG
      Serial.println("Confirm PIN");
#endif
      hidprint("OnlyKey is ready, re-enter your PIN to confirm");
      PINSET = 9;
      return;
      case 9:
      PINSET = 0;
       if(strlen(password.guess) >= 7 && strlen(password.guess) < 11)
      {

          if (password.evaluate()) {
#ifdef DEBUG
	    Serial.println("Both PINs Match");
#endif
            //hidprint("Both PINs Match");
			uint8_t temp[32];
			uint8_t *ptr;
			ptr = temp;
			//Copy characters to byte array
			for (unsigned int i =0; i <= strlen(password.guess); i++) {
			temp[i] = (uint8_t)password.guess[i];
			}
			SHA256_CTX pinhash;
			sha256_init(&pinhash);
			sha256_update(&pinhash, temp, strlen(password.guess)); //Add new PIN to hash
			if (!onlykey_flashget_noncehash (ptr, 32)) {
			RNG2(ptr, 32); //Fill temp with random data
#ifdef DEBUG
			Serial.println("Generating NONCE");
#endif
			onlykey_flashset_noncehash (ptr); //Store in flash
			}

			sha256_update(&pinhash, temp, 32); //Add nonce to hash
			sha256_final(&pinhash, temp); //Create hash and store in temp
#ifdef DEBUG
			Serial.println("Hashing PIN and storing to Flash");
#endif
			onlykey_flashset_2ndpinhashpublic (ptr);
#ifdef DEBUG
	  		Serial.println();
			Serial.println("Successfully set PIN");
#endif
			hidprint("Successfully set PIN");
          }
          else {
#ifdef DEBUG
            Serial.println("Error PINs Don't Match");
#endif
	    hidprint("Error PINs Don't Match");
	    PINSET = 0;
          }
      }
      else
      {
#ifdef DEBUG
        Serial.println("Error PIN is not between 7 - 10 characters");
#endif
	hidprint("Error PIN is not between 7 - 10 characters");
	PINSET = 0;
      }
      password.reset();
      blink(3);
      return;
}
}

void SETTIME (uint8_t *buffer)
{
#ifdef DEBUG
      	  Serial.println();
	  Serial.println("OKSETTIME MESSAGE RECEIVED");
#endif
	   if(initialized==false && unlocked==true)
	   {
#ifdef DEBUG
		Serial.print("UNINITIALIZED");
#endif
		if (!outputU2F) hidprint(UNINITIALIZED);
		return;
	   } else if (initialized==true && unlocked==true && configmode==true)
	   {
#ifdef DEBUG
		Serial.print("CONFIG_MODE");
#endif
		if (!outputU2F) hidprint(UNLOCKED);
	   }
	   else if (initialized==true && unlocked==true )
	   {
#ifdef DEBUG
		Serial.print("UNLOCKED");
#endif
		if (!outputU2F) hidprint(UNLOCKED);
	if (timeStatus() == timeNotSet) {
    int i, j;
    for(i=0, j=3; i<4; i++, j--){
    unixTimeStamp |= ((uint32_t)buffer[j + 5] << (i*8) );


#ifdef DEBUG
    Serial.println(buffer[j+5], HEX);
#endif
    }
	if (idletimer < 3000) {
#ifdef DEBUG
      Serial.print("Adding time offset");
      Serial.println(millis());
#endif
	unixTimeStamp = unixTimeStamp + ((millis())/1000); //Device was just unlocked add difference in time since app sent settime
	}
      time_t t2 = unixTimeStamp;
#ifdef DEBUG
      Serial.print("Received Unix Epoch Time: ");
      Serial.println(unixTimeStamp, HEX);
#endif
      setTime(t2);
	  setCounter(unixTimeStamp);
#ifdef DEBUG
      Serial.println("Current Time Set to: ");
#endif
      digitalClockDisplay();
	  } else {
	  #ifdef DEBUG
      Serial.println("Time Already Set");
	  #endif
	  }
	  }
      return;
}

uint8_t GETKEYLABELS (uint8_t output)
{
	if (profile2mode==NOENCRYPT) return 0;
	#ifdef US_VERSION
#ifdef DEBUG
      Serial.println();
	  Serial.println("OKGETKEYLABELS MESSAGE RECEIVED");
#endif
	  uint8_t label[EElen_label+3];
	  uint8_t *ptr;
	  char labelchar[EElen_label+3];
	  int offset  = 0;
	  int keyid_match;
	  char labeltype[EElen_label+3+6];
	  ptr=label+2;

	for (uint8_t i = 25; i<=28; i++) { //4 labels for RSA keys
	  onlykey_flashget_label(ptr+8, (offset + i));
	  label[0] = (uint8_t)i; //1-4
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
	  if (output == 1) { //Output via keyboard
			labeltype[0] = 'R';
			labeltype[1] = 'S';
			labeltype[2] = 'A';
			labeltype[3] = ((i-24)+'0');
			labeltype[4] = 0x20;
			memcpy(labeltype+5, labelchar+2, EElen_label+1);
			keytype(labeltype);
			Keyboard.println();
		} else if (!outputU2F && output == 2){//Output via rawhid
			hidprint(labelchar);
			delay(20);
		} else if (output == 3) { //Output slot number of matching label
			keyid_match = memcmp (ptr+8, recv_buffer+6, 8);
			if (keyid_match == 0) return i-24;
		}
	}
	for (uint8_t i = 29; i<=60; i++) { //32 labels for ECC keys
	  onlykey_flashget_label(ptr, (offset + i));
	  label[0] = (uint8_t)i; //101-132
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
		if (output == 1) {
			labeltype[0] = 'E';
			labeltype[1] = 'C';
			labeltype[2] = 'C';
			if ((i-28)<10) {
			labeltype[3] = ((i-28)+'0');
			labeltype[4] = 0x20;
			memcpy(labeltype+5, labelchar+2, EElen_label+1);
			} else if ((i-28)<20) {
			labeltype[3] = ('1');
			labeltype[4] = ((i-28-10)+'0');
			labeltype[5] = 0x20;
			memcpy(labeltype+6, labelchar+2, EElen_label+1);
			} else if ((i-28)<30) {
			labeltype[3] = ('2');
			labeltype[4] = ((i-28-20)+'0');
			labeltype[5] = 0x20;
			memcpy(labeltype+6, labelchar+2, EElen_label+1);
			} else {
			labeltype[3] = ('3');
			labeltype[4] = ((i-28-30)+'0');
			labeltype[5] = 0x20;
			memcpy(labeltype+6, labelchar+2, EElen_label+1);
			}
			keytype(labeltype);
			Keyboard.println();
		} else if (!outputU2F && output == 2) {//Output via rawhid
		  hidprint(labelchar);
		  delay(20);
		} else if (output == 3) { //Output slot number of matching label
		  keyid_match = memcmp (ptr+8, recv_buffer+6, 8);
		  if (keyid_match == 0) return i+103;
		}
	}
	  #endif
      return 0;
}

void GETSLOTLABELS (uint8_t output)
{
#ifdef DEBUG
      	  Serial.println();
	  Serial.println("OKGETSLOTLABELS MESSAGE RECEIVED");
#endif
	  uint8_t label[EElen_label+3];
	  uint8_t *ptr;
	  char labelchar[EElen_label+3];
	  int offset = 0;
	  char labeltype[EElen_label+3+3];
	  labeltype[2] = 0x20;
	  ptr=label+2;
	  if (profile2mode) offset = 12;

	for (int i = 1; i<=12; i++) {
	  onlykey_flashget_label(ptr, (offset + i));
	  if (i<=9) label[0] = i;
	  else label[0] = i+6;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
	if (output == 1) {
		if (i <= 6) {
		labeltype[0] = (i+'0');
		labeltype[1] = 'a';
		} else {
		labeltype[0] = (i-6+'0');
		labeltype[1] = 'b';
		}
		memcpy(labeltype+3, labelchar+2, EElen_label+1);
		keytype(labeltype);
		Keyboard.println();
	} else {
		hidprint(labelchar);
		delay(20);
	}
	}
      return;
}

void SETSLOT (uint8_t *buffer)
{
      int slot = buffer[5];
      int value = buffer[6];
	  uint8_t temp;
	  uint8_t mask;
      int length = 0;
#ifdef DEBUG
      char cmd = buffer[4]; //cmd or continuation
      Serial.print("OKSETSLOT MESSAGE RECEIVED:");
      Serial.println((int)cmd - 0x80, HEX);
      Serial.print("Setting Slot #");
      Serial.println((int)slot, DEC);
      Serial.print("Value #");
      Serial.println((int)value, DEC);
#endif
     for (int z = 0; buffer[z + 7] + buffer[z + 8] + buffer[z + 9] + buffer[z + 10 ] != 0x00; z++) {
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

	if (profile2mode && buffer[0] != 0xBA) slot = slot + 12; // 2nd profile slots 12 -24 0xBA is loading from backup
            switch (value) {
            case 1:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Label Value to Flash...");
#endif
            onlykey_flashset_label(buffer + 7, slot);
			hidprint("Successfully set Label");
			break;
			case 15:
#ifdef DEBUG
            Serial.println("Writing URL Value to Flash...");
#endif
            if (profile2mode!=NOENCRYPT) {
#ifdef DEBUG
            Serial.println("Unencrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
#ifdef US_VERSION
      	    aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
#endif
#ifdef DEBUG
      	    Serial.println("Encrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
            }
            onlykey_flashset_url(buffer + 7, length, slot);
			hidprint("Successfully set URL");
			break;
            case 16:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing after Username Additional Character to EEPROM...");
#endif
			if (buffer[7] >= 0x30) buffer[7] = buffer[7] -'0';
			onlykey_eeget_addchar(&temp, slot);
			mask = 0b00000011;
			buffer[7] = (temp & ~mask) | (buffer[7] & mask);
			onlykey_eeset_addchar(buffer + 7, slot);
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
            if (buffer[7] > '0') buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay1(buffer + 7, slot);
	    hidprint("Successfully set Delay1");
	        break;
            case 18:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing before Username Additional Character to EEPROM...");
#endif
			if (buffer[7] >= 0x30) buffer[7] = buffer[7] -'0';
			onlykey_eeget_addchar(&temp, slot);
			mask = 0b00000100;
			buffer[7] = buffer[7] << 2;
			buffer[7] = (temp & ~mask) | (buffer[7] & mask);
			onlykey_eeset_addchar(buffer + 7, slot);
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
			if (buffer[7] >= 0x30) buffer[7] = buffer[7] -'0';
			onlykey_eeget_addchar(&temp, slot);
			mask = 0b00001000;
			buffer[7] = buffer[7] << 3;
			buffer[7] = (temp & ~mask) | (buffer[7] & mask);
			onlykey_eeset_addchar(buffer + 7, slot);
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
            if (profile2mode!=NOENCRYPT) {
#ifdef DEBUG
            Serial.println("Unencrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
#ifdef US_VERSION
      	    aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
#endif
#ifdef DEBUG
      	    Serial.println("Encrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
            }
            onlykey_flashset_username(buffer + 7, length, slot);
	    hidprint("Successfully set Username");
			break;
            case 3:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Additional after password to EEPROM...");
#endif
			if (buffer[7] >= 0x30) buffer[7] = buffer[7] -'0';
			onlykey_eeget_addchar(&temp, slot);
			mask = 0b00110000;
			buffer[7] = buffer[7] << 4;
			buffer[7] = (temp & ~mask) | (buffer[7] & mask);
			onlykey_eeset_addchar(buffer + 7, slot);
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
            if (buffer[7] > '0') buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay2(buffer + 7, slot);
	    hidprint("Successfully set Delay2");
			break;
            case 5:
            //Encrypt and Set value in EEPROM
#ifdef DEBUG
            Serial.println("Writing Password to EEPROM...");
#endif
            if (profile2mode!=NOENCRYPT) {
#ifdef DEBUG
            Serial.println("Unencrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
#ifdef US_VERSION
            aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
#endif
#ifdef DEBUG
      	    Serial.println("Encrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
            }
            onlykey_eeset_password(buffer + 7, length, slot);
	    hidprint("Successfully set Password");
			break;
            case 6:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing After OTP Additional Character to EEPROM...");
#endif
			if (buffer[7] >= 0x30) buffer[7] = buffer[7] -'0';
			if (buffer[7] == 2) buffer[7]--; //Return only, no tab needed
			onlykey_eeget_addchar(&temp, slot);
			mask = 0b01000000;
			buffer[7] = buffer[7] << 6;
			buffer[7] = (temp & ~mask) | (buffer[7] & mask);
			onlykey_eeset_addchar(buffer + 7, slot);
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
            if (buffer[7] > '0') buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay3(buffer + 7, slot);
	    hidprint("Successfully set Delay3");
			break;
            case 8:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing 2FA Type to EEPROM...");
#endif
            onlykey_eeset_2FAtype(buffer + 7, slot);
	    hidprint("Successfully set 2FA Type");
			break;
            case 9:
            //Encrypt and Set value in EEPROM
#ifdef DEBUG
            Serial.println("Writing TOTP Key to Flash...");
            Serial.println("Unencrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
#ifdef US_VERSION
            if (profile2mode!=NOENCRYPT) {
            aes_gcm_encrypt((buffer + 7), slot, value, profilekey, length);
            }
#endif
#ifdef DEBUG
	    Serial.println("Encrypted");
			byteprint(buffer+7, 64);
            Serial.println();
#endif
            onlykey_flashset_totpkey(buffer + 7, length, slot);
	    hidprint("Successfully set TOTP Key");
			break;
            case 10:
            if (profile2mode!=NOENCRYPT) {
            //Encrypt and Set value in Flash
#ifdef DEBUG
            Serial.println("Writing AES Key, Private ID, and Public ID to EEPROM...");
            Serial.println("Unencrypted Public ID");
			byteprint(buffer+7, 6);
            Serial.println("Unencrypted Private ID");
			byteprint(buffer+7 + 6, 6);
            Serial.println("Unencrypted AES Key");
			byteprint(buffer+7 + 12, 16);
            Serial.println();
#endif
#ifdef US_VERSION
            aes_gcm_encrypt((buffer + 7), 0, value, profilekey, length);
#endif
#ifdef DEBUG
      	    Serial.println("Encrypted");
			byteprint(buffer+7, 32);
            Serial.println();
#endif
            uint16_t counter  = 0x0000;
            uint8_t *ptr;
  	    ptr = (uint8_t *) &counter;
  	    yubikey_eeset_counter(ptr);
            onlykey_eeset_public(buffer + 7);
            onlykey_eeset_private((buffer + 7 + EElen_public));
            onlykey_eeset_aeskey(buffer + 7 + EElen_public + EElen_private);
            yubikeyinit();
	    hidprint("Successfully set AES Key, Private ID, and Public ID");
	    }
			break;
            case 11:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing idle timeout to EEPROM...");
#endif
            onlykey_eeset_timeout(buffer + 7);
            TIMEOUT[0] = buffer[7];
	        hidprint("Successfully set idle timeout");
			break;
            case 12:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing wipemode to EEPROM...");
#endif
			if(buffer[7] == 2) {
            	onlykey_eeset_wipemode(buffer + 7);
            	hidprint("Successfully set Wipe Mode to Full Wipe");
            } else if (!initcheck) { //Only permit changing this on first use on a clean device
				onlykey_eeset_wipemode(buffer + 7);
            	hidprint("Successfully set Wipe Mode to Default Setting");
			}
			else {
	        hidprint("Success");
			}
			break;
			case 20:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing backupkeymode to EEPROM...");
#endif
			if(buffer[7] == 1) {
            	onlykey_eeset_backupkeymode(buffer + 7);
            	hidprint("Successfully set Backup Key Mode to Set Once");
            } else if (!initcheck) { //Only permit changing this on first use on a clean device
				onlykey_eeset_backupkeymode(buffer + 7);
            	hidprint("Successfully set Backup Key Mode to Default Setting");
			}
			else {
	        hidprint("Success");
			}
			break;
			case 21:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing sshchallengemode to EEPROM...");
#endif
            if(configmode==true || !initcheck) { //Only permit changing this on first use or while in config mode
            	onlykey_eeset_sshchallengemode(buffer + 7);
            	hidprint("Successfully set SSH Challenge Mode");
            } else {
	        hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
			}
			break;
			case 22:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing pgpchallengemode to EEPROM...");
#endif
           if(configmode==true || !initcheck) { //Only permit changing this on first use or while in config mode
            	onlykey_eeset_pgpchallengemode(buffer + 7);
            	hidprint("Successfully set PGP Challenge Mode");
            } else {
	        hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
			}
			break;
			case 23:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing 2ndprofilemode to EEPROM...");
#endif
			if (profile2mode==NOENCRYPT) return;
			#ifdef US_VERSION
			if (!initcheck) { //Only permit changing this on first use
            	onlykey_eeset_2ndprofilemode(buffer + 7);
            	hidprint("Successfully set 2nd profile mode");
				profile2mode = buffer[7];
#ifdef DEBUG
				Serial.print("Profile Mode"); 
				Serial.println(profile2mode);
#endif		
            } else {
	        hidprint("ERROR 2ND PROFILE MODE MAY ONLY BE SET ON FIRST USE");
			}
			#endif
			break;
			case 13:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing keyboard type speed to EEPROM...");
#endif

            if(buffer[7] <= 10) {
				buffer[7]=11-buffer[7];
				onlykey_eeset_typespeed(buffer + 7);
				TYPESPEED[0] = buffer[7];
			}
	        hidprint("Successfully set keyboard typespeed");
			break;
            case 14:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing keyboard layout to EEPROM...");
#endif
            KeyboardLayout[0] = buffer[7];
			onlykey_eeset_keyboardlayout(buffer + 7);
			update_keyboard_layout();
	        hidprint("Successfully set keyboard layout");

            default:
            return;
          }
      if (buffer[0] != 0xBA) blink(1);
      return;
}

void WIPESLOT (uint8_t *buffer)
{
      int slot = buffer[5];
      int value = buffer[6];
#ifdef DEBUG
      char cmd = buffer[4]; //cmd or continuation
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
	 if (value==10) {
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping OnlyKey AES Key, Private ID, and Public ID...");
#endif
            onlykey_eeset_aeskey(buffer + 7);
            onlykey_eeset_private(buffer + 7 + EElen_aeskey);
            onlykey_eeset_public(buffer + 7 + EElen_aeskey + EElen_private);
			yubikey_eeset_counter(buffer + 7);
            hidprint("Successfully wiped AES Key, Private ID, and Public ID");
	 } else if (slot >= 1 && slot <=12) {
   	if (profile2mode) slot = slot+12;
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping Label Value...");
#endif
            onlykey_flashset_label((buffer + 7), slot);
            hidprint("Successfully wiped Label");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping URL Value...");
#endif
            onlykey_flashset_url((buffer + 7), 0, slot);
            hidprint("Successfully wiped URL");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping Additional Character1 Value...");
#endif
            onlykey_eeset_addchar((buffer + 7), slot);
            hidprint("Successfully wiped Additional Characters");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Delay1 to EEPROM...");
#endif
            onlykey_eeset_delay1((buffer + 7), slot);
            hidprint("Successfully wiped Delay 1");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping Username Value...");
#endif
            onlykey_flashset_username((buffer + 7), 0, slot);
            hidprint("Successfully wiped Username");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Delay2 to EEPROM...");
#endif
            onlykey_eeset_delay2((buffer + 7), slot);
            hidprint("Successfully wiped Delay 2");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping Password Value...");
#endif
            onlykey_eeset_password((buffer + 7), 0, slot);
            hidprint("Successfully wiped Password");
#ifdef DEBUG
	    Serial.println(); //newline
            Serial.print("Wiping Delay3 Value...");
#endif
            onlykey_eeset_delay3((buffer + 7), slot);
            hidprint("Successfully wiped Delay 3");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping 2FA Type Value...");
#endif
            onlykey_eeset_2FAtype((buffer + 7), slot);
            hidprint("Successfully wiped 2FA Type");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping TOTP Key from Flash...");
#endif
            onlykey_flashset_totpkey((buffer + 7), 0, slot);
            hidprint("Successfully wiped TOTP Key");
	 }
	blink(1);
	return;
}

void digitalClockDisplay(){
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

void printDigits(int digits){
  // utility function for digital clock display: prints preceding colon and leading 0
#ifdef DEBUG
  Serial.print(":");
  if(digits < 10)
    Serial.print('0');
  Serial.print(digits);
#endif
}

void blink(int times){

  int i;
  for(i = 0; i < times; i++){
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

void fadein(){
          // fade in from min to max in increments of 5 points:
          for (int fadeValue = 0 ; fadeValue <= 255; fadeValue += 5) {
          // sets the value (range from 0 to 255):
          analogWrite(BLINKPIN, fadeValue);
          delay(9);
          }
}

void fadeout(){
          // fade out from max to min in increments of 5 points:
          for (int fadeValue = 255 ; fadeValue >= 0; fadeValue -= 5) {
          // sets the value (range from 0 to 255):
          analogWrite(BLINKPIN, fadeValue);
          delay(9);
          }
}


/*************************************/
//RNG Loop
/*************************************/
void rngloop() {
	//Get temperature reading
	//analogReference(INTERNAL);
	//analogReadResolution(12);
	//temperaturev = analogRead(38)+temperaturev;
	//temperaturev = temperaturev/2;
	  //Serial.print(temperaturev);
      //Serial.println (" Internal Temp");
	//Stir in temperature reading
	//RNG.stir((uint8_t *)((int)temperaturev), sizeof(temperaturev), sizeof(temperaturev));
    // Stir the touchread and analog read values into the entropy pool.
	integrityctr1++;
	touchread1 = touchRead(TOUCHPIN1);
    RNG.stir((uint8_t *)touchread1, sizeof(touchread1), sizeof(touchread1));
    touchread2 = touchRead(TOUCHPIN2);
    RNG.stir((uint8_t *)touchread2, sizeof(touchread2), sizeof(touchread2));
    touchread3 = touchRead(TOUCHPIN3);
    RNG.stir((uint8_t *)touchread3, sizeof(touchread3), sizeof(touchread3));
    touchread4 = touchRead(TOUCHPIN4);
    RNG.stir((uint8_t *)touchread4, sizeof(touchread4), sizeof(touchread4));
    touchread5 = touchRead(TOUCHPIN5);
    RNG.stir((uint8_t *)touchread5, sizeof(touchread5), sizeof(touchread5));
    touchread6 = touchRead(TOUCHPIN6);
    RNG.stir((uint8_t *)touchread6, sizeof(touchread6), sizeof(touchread6));
    unsigned int analog1 = analogRead(ANALOGPIN1);
    RNG.stir((uint8_t *)analog1, sizeof(analog1), sizeof(analog1)*4);
    unsigned int analog2 = analogRead(ANALOGPIN2);
    RNG.stir((uint8_t *)analog2, sizeof(analog2), sizeof(analog2)*4);
	// Perform regular housekeeping on the random number generator.
    RNG.loop();
	delay((analog1 % 3) + (analog2 % 3)); //delay 0 - 6 ms
	integrityctr2++;
	if (integrityctr1!=integrityctr2) { //Integrity Check
	unlocked = false;
	CPU_RESTART();
	return;
	}
}

void printHex(const uint8_t *data, unsigned len)
{
#ifdef DEBUG
    static char const hexchars[] = "0123456789ABCDEF";
    while (len > 0) {
        int b = *data++;

        Serial.print(hexchars[(b >> 4) & 0x0F]);
        Serial.print(hexchars[b & 0x0F]);

        --len;
    }

    Serial.println();
#endif
}

void ByteToChar(uint8_t* bytes, char* chars, unsigned int count){
    for(unsigned int i = 0; i < count; i++)
    	 chars[i] = (char)bytes[i];
}

void CharToByte(char* chars, uint8_t* bytes, unsigned int count){
    for(unsigned int i = 0; i < count; i++)
    	bytes[i] = (uint8_t)chars[i];
}

void ByteToChar2(uint8_t* bytes, char* chars, unsigned int count, unsigned int index){
    for(unsigned int i = 0; i < count; i++)
    	 chars[i+index] = (char)bytes[i];
}

void CharToByte2(char* chars, uint8_t* bytes, unsigned int count, unsigned int index){
    for(unsigned int i = 0; i < count; i++)
    	bytes[i+index] = (uint8_t)chars[i];
}

void hidprint(char const * chars)
{
int i=0;
while(*chars) {
	 if (*chars == 0xFF) resp_buffer[i] = 0x00; //Empty flash sector is 0xFF
     else resp_buffer[i] = (uint8_t)*chars;
     chars++;
	 i++;
  }
  RawHID.send(resp_buffer, 0);
  memset(resp_buffer, 0, sizeof(resp_buffer));
}

void keytype(char const * chars)
{
while(*chars) {
	 if (*chars == 0xFF) chars++; //Empty flash sector is 0xFF
	 else {
		Keyboard.press(*chars);
		delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
		chars++;
	 }
  }
}

void byteprint(uint8_t* bytes, int size)
{
#ifdef DEBUG
Serial.println();
for (int i = 0; i < size; i++) {
  Serial.print(bytes[i], HEX);
  Serial.print(" ");
  }
Serial.println();
#endif
}

void factorydefault() {
	uint8_t mode;
	onlykey_eeget_wipemode(&mode);
	wipeEEPROM(); //Wipe data and go to bootloader after factory default
	if (mode <= 1) {
	//Just wipe data
	wipeflash(1);
	} else {
	//FULLWIPE Mode wipe data and firmware
	wipeflash(2);
#ifdef DEBUG
	uintptr_t adr = 0x0;
        for (int i = 0; i < 65536; i+=4)
        {
        Serial.printf("0x%X", adr);
        Serial.printf(" 0x%X", *((unsigned int*)adr));
        Serial.println();
        adr=adr+4;
        }
#endif
eeprom_write_byte((unsigned char *)0x01, 1); //Firmware ready to load
eeprom_write_byte(0x00, 1); //Go to bootloader
}
	initialized = false;
	unlocked = true;
#ifdef DEBUG
	Serial.println("factory reset has been completed");
#endif
	hidprint("factory reset has been completed");
	delay(100);
	CPU_RESTART();
while(1==1) {
	blink(3);
}
}

void wipeEEPROM() {
	//Erase all EEPROM values
	uint8_t value;
#ifdef DEBUG
	Serial.println("Current EEPROM Values");
	for (int i=0; i<2048; i++) {
	value=EEPROM.read(i);
	Serial.print(i);
  	Serial.print("\t");
  	Serial.print(value, DEC);
  	Serial.println();
	}
#endif
	value=0x00;
	for (int i=66; i<2048; i++) {
	EEPROM.write(i, value);
	}
#ifdef DEBUG
	Serial.println("EEPROM set to 0s");
#endif
	for (int i=0; i<2048; i++) {
	value=EEPROM.read(i);
#ifdef DEBUG
	Serial.print(i);
  	Serial.print("\t");
  	Serial.print(value, DEC);
  	Serial.println();
#endif
	}
#ifdef DEBUG
	Serial.println("EEPROM erased");//TODO remove debug
#endif
}

void wipeflash(uint8_t mode) {
	uintptr_t adr;
	if (mode <= 1) {
		adr = (unsigned long)flashstorestart;
	} else { //wipe data and fw
		adr = fwstartadr;
	}
	uintptr_t endadr = flashend;
	while (adr <= endadr-2048) {
#ifdef DEBUG
	Serial.printf("Erase Sector 0x%X ",adr);
#endif
	if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
	Serial.printf("successful\r\n");
#endif
	adr=adr+2048; //Next Sector 2048
	}
#ifdef DEBUG
	Serial.printf("successful\r\n");
	Serial.println("Flash Sectors erased");
#endif
}


void aes_gcm_encrypt (uint8_t * state, uint8_t slot, uint8_t value, const uint8_t * key, int len) {
	#ifdef US_VERSION
	GCM<AES256> gcm;
	uint8_t iv2[12];
	uint8_t aeskey[32];
	uint8_t data[2];
	data[0] = slot;
	data[1] = value;
	uint8_t *ptr;
	ptr = iv2;
	onlykey_flashget_noncehash(ptr, 12);
	
	#ifdef DEBUG
	Serial.print("INPUT KEY ");
	byteprint((uint8_t*)key, 32);
	#endif
	
	#ifdef DEBUG
	Serial.println("SLOT");
	Serial.println(slot);
	#endif
	
	#ifdef DEBUG
	Serial.print("VALUE");
	Serial.print(value);
	#endif

	SHA256_CTX iv;
	sha256_init(&iv);
	sha256_update(&iv, iv2, 12); //add nonce
	sha256_update(&iv, data, 2); //add data
	sha256_update(&iv, (uint8_t*)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&iv, aeskey); //Create hash and store in aeskey temporarily
	memcpy(iv2, aeskey, 12);
	#ifdef DEBUG
	Serial.print("IV ");
	byteprint(iv2, 12);
	#endif

	SHA256_CTX key2;
	sha256_init(&key2);
	sha256_update(&key2, key, 16); //add profilekey
	sha256_update(&key2, data, 2); //add slot
	sha256_update(&key2, (uint8_t*)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&key2, aeskey); //Create hash and store in aeskey

	#ifdef DEBUG
	Serial.print("AES KEY ");
	byteprint(aeskey, 32);
	#endif

	gcm.clear ();
	gcm.setKey(aeskey, 32);
	gcm.setIV(iv2, 12);
	#ifdef DEBUG
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif
	gcm.encrypt(state, state, len);
	#ifdef DEBUG
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif
	//gcm.computeTag(tag, sizeof(tag));
	#endif
}

void aes_gcm_decrypt (uint8_t * state, uint8_t slot, uint8_t value, const uint8_t * key, int len) {
        #ifdef US_VERSION
	GCM<AES256> gcm;
	uint8_t iv2[12];
	uint8_t aeskey[32];
	uint8_t data[2];
	data[0] = slot;
	data[1] = value;
	uint8_t *ptr;
	ptr = iv2;
	onlykey_flashget_noncehash(ptr, 12);
	
	#ifdef DEBUG
	Serial.print("INPUT KEY ");
	byteprint((uint8_t*)key, 32);
	#endif
	
	#ifdef DEBUG
	Serial.println("SLOT");
	Serial.println(slot);
	#endif
	
	#ifdef DEBUG
	Serial.print("VALUE");
	Serial.print(value);
	#endif

	SHA256_CTX iv;
	sha256_init(&iv);
	sha256_update(&iv, iv2, 12); //add nonce
	sha256_update(&iv, data, 2); //add data
	sha256_update(&iv, (uint8_t*)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&iv, aeskey); //Create hash and store in aeskey temporarily
	memcpy(iv2, aeskey, 12);

	#ifdef DEBUG
	Serial.print("IV ");
	byteprint(iv2, 12);
	#endif

	SHA256_CTX key2;
	sha256_init(&key2);
	sha256_update(&key2, key, 16); //add profilekey
	sha256_update(&key2, data, 2); //add data
	sha256_update(&key2, (uint8_t*)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&key2, aeskey); //Create hash and store in aeskey

	#ifdef DEBUG
	Serial.print("AES KEY ");
	byteprint(aeskey, 32);
	#endif

	gcm.clear ();
	gcm.setKey(aeskey, 32);
	gcm.setIV(iv2, 12);
	#ifdef DEBUG
	Serial.print("ENCRYPTED STATE");
	byteprint(state, len);
	#endif
	gcm.decrypt(state, state, len);
	#ifdef DEBUG
	Serial.print("DECRYPTED STATE");
	byteprint(state, len);
	#endif
	//if (!gcm.checkTag(tag, sizeof(tag))) {
	//	return 1;
	//}
	#endif

}

void aes_gcm_encrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
	#ifdef US_VERSION
	GCM<AES256> gcm;
	//uint8_t tag[16];
	gcm.clear ();
	gcm.setKey(key, 32);
	gcm.setIV(iv1, 12);
	gcm.encrypt(state, state, len);
	//gcm.computeTag(tag, sizeof(tag));
	#endif
}

void aes_gcm_decrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
        #ifdef US_VERSION
	GCM<AES256> gcm;
	//uint8_t tag[16];
	gcm.clear ();
	gcm.setKey(key, 32);
	gcm.setIV(iv1, 12);
	gcm.decrypt(state, state, len);
	//if (!gcm.checkTag(tag, sizeof(tag))) {
	//	return 1;
	//}
	#endif
}

/*************************************/
void onlykey_flashget_common (uint8_t *ptr, unsigned long *adr, int len) {
    for( int z = 0; z <= len-4; z=z+4){
        //Serial.printf(" 0x%X", (adr));
        *ptr = (uint8_t)((*(adr) >> 24) & 0xFF);
        //Serial.printf(" 0x%X", *ptr);
        ptr++;
 	*ptr = (uint8_t)((*(adr) >> 16) & 0xFF);
 	//Serial.printf(" 0x%X", *ptr);
 	ptr++;
 	*ptr = (uint8_t)((*(adr) >> 8) & 0xFF);
 	//Serial.printf(" 0x%X", *ptr);
 	ptr++;
 	*ptr = (uint8_t)((*(adr) & 0xFF));
 	//Serial.printf(" 0x%X", *ptr);
 	//Serial.println();
 	ptr++;
 	adr++;
	}
	return;
}

void onlykey_flashset_common (uint8_t *ptr, unsigned long *adr, int len) {
	for( int z = 0; z <= len-4; z=z+4){
	unsigned long data = (uint8_t)*(ptr+z+3) | ((uint8_t)*(ptr+z+2) << 8) | ((uint8_t)*(ptr+z+1) << 16) | ((uint8_t)*(ptr+z) << 24);
	//Write long to sector
	//Serial.println();
	//Serial.printf("Writing to Sector 0x%X, value 0x%X ", adr, data);
	if ( flashProgramWord((unsigned long*)adr, &data) ) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
	adr++;
	}
	return;
}

void onlykey_flashsector (uint8_t *ptr, unsigned long *adr, int len) {
//Erase flash sector
#ifdef DEBUG
	  Serial.printf("Erase Sector 0x%X ",adr);
#endif
	  if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
	  Serial.printf("successful\r\n");
#endif
	  //Write buffer to flash
	  onlykey_flashset_common(ptr, (unsigned long*)adr, len);
}

/*********************************/

int onlykey_flashget_noncehash (uint8_t *ptr, int size) {
	int set = 0;
	uintptr_t adr = (unsigned long)flashstorestart;
	#ifdef DEBUG
	Serial.printf("Reading nonce from Sector 0x%X ",adr);
	#endif
    onlykey_flashget_common(ptr, (unsigned long*)adr, size);
	for (int i=0; i<32; i++) {
		set = *(ptr+i) + set;
	}
#ifdef DEBUG
	Serial.println(set);
#endif
	if (set == 8160) { //0xFF * 32
#ifdef DEBUG
		Serial.printf("There is no Nonce hash set");
#endif
		return 0;
	} else {
	return 1;
	}
}

void onlykey_flashset_noncehash (uint8_t *ptr) {

	uintptr_t adr = (unsigned long)flashstorestart;
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;
	//Get current flash contents
	onlykey_flashget_common(tptr, (unsigned long*)adr, 254);
	//Add new flash contents
	for( int z = 0; z <= 31; z++){
		temp[z] = ((uint8_t)*(ptr+z));
	}
#ifdef DEBUG
	  Serial.print("Nonce hash address =");
	  Serial.println(adr, HEX);
	  Serial.print("Nonce hash value =");
#endif
	  onlykey_flashsector (tptr, (unsigned long*)adr, 254);
	  onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_noncehash);
}


int onlykey_flashget_pinhashpublic (uint8_t *ptr, int size) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + EElen_noncehash;
    onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_pinhash);
    if (*ptr == 255 && *(ptr + 1) == 255 && *(ptr + 2) == 255) { //pinhash not set
		#ifdef DEBUG
		Serial.printf("Read Pin hash from Sector 0x%X ",adr);
		Serial.printf("There is no Pin hash set");
		#endif
    	return 0;
    }
    else {
		#ifdef DEBUG
		Serial.printf("Read Pin hash from Sector 0x%X ",adr);
		Serial.printf("Pin hash has been set");
		#endif
		return 1;
    }

}

void onlykey_flashset_pinhashpublic (uint8_t *ptr) {

	uintptr_t adr = (unsigned long)flashstorestart;
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;
	ptr[0] &= 0xF8;
    ptr[31] = (ptr[31] & 0x7F) | 0x40;
	//Generate public key of pinhash in temp
	Curve25519::eval(temp, ptr, 0); 
#ifdef DEBUG
      Serial.print("Storing public key of PIN hash =");
	  byteprint(temp, 32);
#endif
	//Generate shared secret in profile key
	memcpy(ecc_private_key, ptr, 32);
	type=4; //Curve25519
	shared_secret(temp, profilekey);
	//Copy public key to ptr for writing to flash
	memcpy(ptr, temp, 32);
	//Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 254);
	//Add new flash contents to buffer
	for( int z = 0; z <= 31; z++){
		temp[z + EElen_noncehash] = ((uint8_t)*(ptr+z));
	}
	  onlykey_flashsector (tptr, (unsigned long*)adr, 254);
#ifdef DEBUG
      Serial.print("Pin hash address =");
      Serial.println(adr, HEX);
#endif
	// Generate and encrypt default key
	recv_buffer[4] = 0xEF;
	recv_buffer[5] = 0x84;
	recv_buffer[6] = 0x61;
	RNG2(recv_buffer+7, 32);
	SETPRIV(recv_buffer); //set default ECC key
	memset(ecc_private_key, 0, 32);
    onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_pinhash);

}
/*********************************/
/*********************************/

int onlykey_flashget_selfdestructhash (uint8_t *ptr) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + EElen_noncehash + EElen_pinhash;
    onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_selfdestructhash);

    if (*ptr == 255 && *(ptr + 1) == 255 && *(ptr + 2) == 255) { //pinhash not set
		#ifdef DEBUG
		Serial.printf("Read Self-Destruct PIN hash from Sector 0x%X ",adr);
		Serial.printf("There is no Self-Destruct PIN hash set");
		#endif
    	return 0;
    }
    else {
		#ifdef DEBUG
		Serial.printf("Read Self-Destruct PIN hash from Sector 0x%X ",adr);
		Serial.print("Self-Destruct PIN hash value =");
		byteprint(ptr, 32);
		#endif
		return 1;
    }

}

void onlykey_flashset_selfdestructhash (uint8_t *ptr) {

	uintptr_t adr = (unsigned long)flashstorestart;
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;
	//Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 254);
	//Add new flash contents to buffer
	for( int z = 0; z <= 31; z++){
		temp[z + EElen_noncehash + EElen_pinhash] = ((uint8_t)*(ptr+z));
	}
	onlykey_flashsector (tptr, (unsigned long*)adr, 254);
#ifdef DEBUG
      Serial.print("Self-Destruct PIN hash address =");
      Serial.println(adr, HEX);
      Serial.print("Self-Destruct PIN hash value =");
	  byteprint(ptr, 32);
#endif
      onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_selfdestructhash);
}

/*********************************/
/*********************************/

int onlykey_flashget_2ndpinhashpublic (uint8_t *ptr) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash;
    onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_2ndpinhash);

    if (*ptr == 255 && *(ptr + 1) == 255 && *(ptr + 2) == 255) { //pinhash not set
		#ifdef DEBUG
		Serial.printf("Read PIN hash from Sector 0x%X ",adr);
		Serial.printf("There is no PIN hash set");
		#endif
    	return 0;
    }
    else {
		#ifdef DEBUG
		Serial.printf("Read PIN hash from Sector 0x%X ",adr);
		Serial.printf("PIN hash has been set");
		#endif
		return 1;
    }

}
void onlykey_flashset_2ndpinhashpublic (uint8_t *ptr) {

	uintptr_t adr = (unsigned long)flashstorestart;
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;

	ptr[0] &= 0xF8;
    ptr[31] = (ptr[31] & 0x7F) | 0x40;
	//Generate public key of pinhash in temp
	Curve25519::eval(temp, ptr, 0); 
#ifdef DEBUG
      Serial.print("Storing public key of PIN 2 hash =");
	  byteprint(temp, 32);
#endif
	if (profile2mode!=NOENCRYPT) { //profile key not used for plausible deniability mode
#ifdef US_VERSION
	//Generate shared secret in profile key
	memcpy(ecc_private_key, ptr, 32);
	type=4; //Curve25519
	onlykey_flashget_pinhashpublic (p1hash, 32); //store PIN hash
	shared_secret(p1hash, profilekey);//Generate shared secret of p2hash private key and p1hash public key
#endif	
	}
	//Copy public key to ptr for writing to flash
	memcpy(ptr, temp, 32);
	//Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 254);

	//Add new flash contents to buffer
	for( int z = 0; z <= 31; z++){
		temp[z + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash] = ((uint8_t)*(ptr+z));
	}
	onlykey_flashsector (tptr, (unsigned long*)adr, 254);
#ifdef DEBUG
      Serial.print("PIN hash address =");
      Serial.println(adr, HEX);
      Serial.print("PIN hash value =");
#endif
	if (profile2mode!=NOENCRYPT) { 
#ifdef US_VERSION
	// Generate and encrypt default key
	recv_buffer[4] = 0xEF;
	recv_buffer[5] = 0x84;
	recv_buffer[6] = 0x61;
	RNG2(recv_buffer+7, 32);
	SETPRIV(recv_buffer); //set default ECC key
	memset(ecc_private_key, 0, 32);
#endif	
	}
    onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_2ndpinhash);

}



int onlykey_flashget_url (uint8_t *ptr, int slot) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
	switch (slot) {
		uint8_t length;
		int size;
        	case 1:
			onlykey_eeget_urllen1(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 2:
			onlykey_eeget_urllen2(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 3:
			onlykey_eeget_urllen3(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 4:
			onlykey_eeget_urllen4(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 5:
			onlykey_eeget_urllen5(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 6:
			onlykey_eeget_urllen6(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 7:
			onlykey_eeget_urllen7(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 8:
			onlykey_eeget_urllen8(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 9:
			onlykey_eeget_urllen9(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 10:
			onlykey_eeget_urllen10(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 11:
			onlykey_eeget_urllen11(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 12:
			onlykey_eeget_urllen12(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 13:
			onlykey_eeget_urllen13(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 14:
			onlykey_eeget_urllen14(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 15:
			onlykey_eeget_urllen15(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 16:
			onlykey_eeget_urllen16(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 17:
			onlykey_eeget_urllen17(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 18:
			onlykey_eeget_urllen18(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 19:
			onlykey_eeget_urllen19(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 20:
			onlykey_eeget_urllen20(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 21:
			onlykey_eeget_urllen21(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 22:
			onlykey_eeget_urllen22(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 23:
			onlykey_eeget_urllen23(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
		case 24:
			onlykey_eeget_urllen24(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
	}

return 0;
}

void onlykey_flashset_url (uint8_t *ptr, int size, int slot) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 2048; //2nd free sector
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z < EElen_url; z++){
    temp[z+((EElen_url*slot)-EElen_url)] = ((uint8_t)*(ptr+z));
    }
    //Erase flash sector
#ifdef DEBUG
    Serial.printf("Erase Sector 0x%X ",adr);
#endif
    if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
    Serial.printf("successful\r\n");
#endif
		switch (slot) {
			uint8_t length;
        	case 1:
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen1(&length);
            	return;
		case 2:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen2(&length);
            	return;
		case 3:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen3(&length);
            return;
		case 4:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen4(&length);
            return;
		case 5:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen5(&length);
            return;
		case 6:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen6(&length);
            return;
		case 7:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen7(&length);
            return;
		case 8:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen8(&length);
            return;
		case 9:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen9(&length);
            return;
		case 10:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen10(&length);
            return;
		case 11:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen11(&length);
            return;
		case 12:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen12(&length);
            return;
            	case 13:
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen13(&length);
            	return;
		case 14:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen14(&length);
            	return;
		case 15:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen15(&length);
            return;
		case 16:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen16(&length);
            return;
		case 17:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen17(&length);
            return;
		case 18:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen18(&length);
            return;
		case 19:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen19(&length);
            return;
		case 20:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen20(&length);
            return;
		case 21:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen21(&length);
            return;
		case 22:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen22(&length);
            return;
		case 23:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen23(&length);
            return;
		case 24:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen24(&length);
            return;
	}
return;
}

/*********************************/


int onlykey_flashget_username (uint8_t *ptr, int slot) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 4096; //3rd free sector
	switch (slot) {
		uint8_t length;
		int size;
        	case 1:
			onlykey_eeget_usernamelen1(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
		case 2:
			onlykey_eeget_usernamelen2(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
		case 3:
			onlykey_eeget_usernamelen3(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
		case 4:
			onlykey_eeget_usernamelen4(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 5:
			onlykey_eeget_usernamelen5(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 6:
			onlykey_eeget_usernamelen6(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 7:
			onlykey_eeget_usernamelen7(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 8:
			onlykey_eeget_usernamelen8(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 9:
			onlykey_eeget_usernamelen9(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 10:
			onlykey_eeget_usernamelen10(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 11:
			onlykey_eeget_usernamelen11(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 12:
			onlykey_eeget_usernamelen12(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 13:
			onlykey_eeget_usernamelen13(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 14:
			onlykey_eeget_usernamelen14(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 15:
			onlykey_eeget_usernamelen15(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 16:
			onlykey_eeget_usernamelen16(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 17:
			onlykey_eeget_usernamelen17(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 18:
			onlykey_eeget_usernamelen18(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 19:
			onlykey_eeget_usernamelen19(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 20:
			onlykey_eeget_usernamelen20(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 21:
			onlykey_eeget_usernamelen21(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 22:
			onlykey_eeget_usernamelen22(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 23:
			onlykey_eeget_usernamelen23(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

		case 24:
			onlykey_eeget_usernamelen24(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;

	}

return 0;
}

void onlykey_flashset_username (uint8_t *ptr, int size, int slot) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 4096; //3rd free sector
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z < EElen_username; z++){
    temp[z+((EElen_username*slot)-EElen_username)] = ((uint8_t)*(ptr+z));
    }
    //Erase flash sector
#ifdef DEBUG
    Serial.printf("Erase Sector 0x%X ",adr);
#endif
    if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
    Serial.printf("successful\r\n");
#endif
		switch (slot) {
			uint8_t length;
        	case 1:
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen1(&length);
            	return;
		case 2:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen2(&length);
            	return;
		case 3:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen3(&length);
            return;
		case 4:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen4(&length);
            return;
		case 5:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen5(&length);
            return;
		case 6:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen6(&length);
            return;
		case 7:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen7(&length);
            return;
		case 8:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen8(&length);
            return;
		case 9:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen9(&length);
            return;
		case 10:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen10(&length);
            return;
		case 11:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen11(&length);
            return;
		case 12:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen12(&length);
            return;
            	case 13:
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen13(&length);
            	return;
		case 14:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen14(&length);
            	return;
		case 15:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen15(&length);
            return;
		case 16:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen16(&length);
            return;
		case 17:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen17(&length);
            return;
		case 18:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen18(&length);
            return;
		case 19:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen19(&length);
            return;
		case 20:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen20(&length);
            return;
		case 21:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen21(&length);
            return;
		case 22:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen22(&length);
            return;
		case 23:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen23(&length);
            return;
		case 24:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen24(&length);
            return;
	}
return;
}

/*********************************/


void onlykey_flashget_label (uint8_t *ptr, int slot) {
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 6144; //4th free sector
	adr=adr+((EElen_label*slot)-EElen_label);
	onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
}

void onlykey_flashset_label (uint8_t *ptr, int slot) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 6144; //4th free sector
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z < EElen_label; z++){
    temp[z+((EElen_label*slot)-EElen_label)] = ((uint8_t)*(ptr+z));
    }

    //Erase flash sector
	if (*ptr!=0x00) { //No need to erase sector if wiping slot
#ifdef DEBUG
    Serial.printf("Erase Sector 0x%X ",adr);
#endif
    if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
    Serial.printf("successful\r\n");
#endif
	}
    onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
return;
}

/*********************************/

int onlykey_flashget_totpkey (uint8_t *ptr, int slot) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 8192; //5th free sector
	switch (slot) {
		uint8_t length;
		int size;
        	case 1:
			onlykey_eeget_totpkeylen1(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 2:
			onlykey_eeget_totpkeylen2(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 3:
			onlykey_eeget_totpkeylen3(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 4:
			onlykey_eeget_totpkeylen4(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 5:
			onlykey_eeget_totpkeylen5(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 6:
			onlykey_eeget_totpkeylen6(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 7:
			onlykey_eeget_totpkeylen7(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 8:
			onlykey_eeget_totpkeylen8(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 9:
			onlykey_eeget_totpkeylen9(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 10:
			onlykey_eeget_totpkeylen10(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 11:
			onlykey_eeget_totpkeylen11(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 12:
			onlykey_eeget_totpkeylen12(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 13:
			onlykey_eeget_totpkeylen13(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 14:
			onlykey_eeget_totpkeylen14(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 15:
			onlykey_eeget_totpkeylen15(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 16:
			onlykey_eeget_totpkeylen16(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 17:
			onlykey_eeget_totpkeylen17(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 18:
			onlykey_eeget_totpkeylen18(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 19:
			onlykey_eeget_totpkeylen19(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 20:
			onlykey_eeget_totpkeylen20(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 21:
			onlykey_eeget_totpkeylen21(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 22:
			onlykey_eeget_totpkeylen22(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 23:
			onlykey_eeget_totpkeylen23(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

		case 24:
			onlykey_eeget_totpkeylen24(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;

	}

return 0;
}

void onlykey_flashset_totpkey (uint8_t *ptr, int size, int slot) {

	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 8192;
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z < EElen_totpkey; z++){
    temp[z+((EElen_totpkey*slot)-EElen_totpkey)] = ((uint8_t)*(ptr+z));
    }
    //Erase flash sector
#ifdef DEBUG
    Serial.printf("Erase Sector 0x%X ",adr);
#endif
    if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
    Serial.printf("successful\r\n");
#endif
		switch (slot) {
			uint8_t length;
        	case 1:
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen1(&length);
            return;
		case 2:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen2(&length);
            return;
		case 3:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen3(&length);
            return;
		case 4:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen4(&length);
            return;
		case 5:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen5(&length);
            return;
		case 6:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen6(&length);
            return;
		case 7:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen7(&length);
            return;
		case 8:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen8(&length);
            return;
		case 9:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen9(&length);
            return;
		case 10:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen10(&length);
            return;
		case 11:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen11(&length);
            return;
		case 12:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen12(&length);
            return;
            	case 13:
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen13(&length);
            return;
		case 14:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen14(&length);
            return;;
		case 15:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen15(&length);
            return;
		case 16:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen16(&length);
            return;
		case 17:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen17(&length);
            return;
		case 18:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen18(&length);
            return;
		case 19:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen19(&length);
            return;
		case 20:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen20(&length);
            return;
		case 21:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen21(&length);
            return;
		case 22:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen22(&length);
            return;
		case 23:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen23(&length);
            return;
		case 24:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen24(&length);
            return;
	}
return;
}

/*********************************/
void onlykey_flashget_U2F ()
{

if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("Flashget U2F");
#endif
	uint8_t length[2];
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 10240; //6th flash sector
    onlykey_flashget_common((uint8_t*)attestation_priv, (unsigned long*)adr, 32);
#ifdef DEBUG
    Serial.print("attestation priv =");
#endif
    for (unsigned int i = 0; i< sizeof(attestation_priv); i++) {
#ifdef DEBUG
    Serial.println(attestation_priv[i],HEX);
#endif
    }
    adr=adr+32;
    onlykey_eeget_U2Fcertlen(length);
    int length2 = length[0] << 8 | length[1];
#ifdef DEBUG
    Serial.print("attestation der length=");
    Serial.println(length2);
#endif
    onlykey_flashget_common((uint8_t*)attestation_der, (unsigned long*)adr, length2);
#ifdef DEBUG
    Serial.print("attestation der =");
	byteprint((uint8_t*)attestation_der, sizeof(attestation_der));
#endif
#endif
    return;

}

/*********************************/
void SETU2FPRIV (uint8_t *buffer)
{

if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKSETU2FPRIV MESSAGE RECEIVED");
#endif
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 10240; //6th flash sector
	uint8_t *ptr;
  uint8_t temp[2048];
  uint8_t *tptr;
  tptr=temp;
  ptr=buffer+5;
  //Copy current flash contents to buffer
  onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
  //Add new flash contents to buffer
  for( int z = 0; z < 32; z++){
  temp[z] = ((uint8_t)*(ptr+z));
  }
	//Erase flash sector
#ifdef DEBUG
    Serial.printf("Erase Sector 0x%X ",adr);
#endif
    if (flashEraseSector((unsigned long*)adr))
    {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
    }

#ifdef DEBUG
    Serial.printf("successful\r\n");
#endif

	//Write buffer to flash

    onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
#ifdef DEBUG
    Serial.print("U2F Private address =");
    Serial.println(adr, HEX);
    Serial.print("U2F Private value =");
#endif
    for (int i=0; i<32; i++) {
    attestation_priv[i] = *(buffer + 5 + i);
#ifdef DEBUG
    Serial.print(attestation_priv[i],HEX);
#endif
    }
    hidprint("Successfully set U2F Private");

  if (buffer[0] != 0xBA) blink(2);
#endif
  return;

}


void WIPEU2FPRIV (uint8_t *buffer)
{

if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKWIPEU2FPRIV MESSAGE RECEIVED");
#endif
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 10240; //6th flash sector
	//Erase flash sector
#ifdef DEBUG
		Serial.printf("Erase Sector 0x%X ",adr);
#endif
		if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
		Serial.printf("successful\r\n");
#endif
		hidprint("Successfully wiped U2F Private");
    blink(2);
#endif
    return;

}

void SETU2FCERT (uint8_t *buffer)
{

if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKSETU2FCERT MESSAGE RECEIVED");
#endif
	uint8_t length[2];
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 10240; //6th flash sector
  uint8_t *ptr;
  uint8_t temp[2048];
  uint8_t *tptr;
	if (buffer[5]==0xFF) //Not last packet
	{
		if (packet_buffer_offset <= 710) {
			memcpy(attestation_der+packet_buffer_offset, buffer+6, 58);
			packet_buffer_offset = packet_buffer_offset + 58;
		} else {
			hidprint("Error U2F Cert larger than 768 bytes");
		}
		return;
	} else { //Last packet
		if (packet_buffer_offset <= 710 && buffer[5] <= 58) {
			memcpy(attestation_der+packet_buffer_offset, buffer+6, buffer[5]);
			packet_buffer_offset = packet_buffer_offset + buffer[5];
		} else if (packet_buffer_offset <= 768 && buffer[0] == 0xBA) { //Import from backup
			memcpy(attestation_der, buffer+6, packet_buffer_offset);
		} else{
			hidprint("Error U2F Cert larger than 768 bytes");
		}
		length[0] = packet_buffer_offset >> 8  & 0xFF;
		length[1] = packet_buffer_offset       & 0xFF;
		//Set U2F Certificate size
		onlykey_eeset_U2Fcertlen(length);
    //Copy current flash contents to buffer
    tptr=temp;
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    ptr=(uint8_t*)attestation_der;
    for( int z = 0; z <= packet_buffer_offset; z++){
    temp[z+32] = ((uint8_t)*(ptr+z));
    }
#ifdef DEBUG
		Serial.print("Length of U2F certificate = ");
        Serial.println(packet_buffer_offset);
		//Erase flash sector
		Serial.printf("Erase Sector 0x%X ",adr);
#endif
		if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
		Serial.printf("successful\r\n");
#endif
		//Write buffer to flash
    	onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
	}
#ifdef DEBUG
    Serial.print("U2F Cert value =");
	byteprint((uint8_t*)attestation_der,packet_buffer_offset);
#endif
	packet_buffer_offset = 0;
	hidprint("Successfully set U2F Certificate");
      if (buffer[0] != 0xBA) blink(2);
#endif
      return;

}

void WIPEU2FCERT (uint8_t *buffer)
{

if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKWIPEU2FCERT MESSAGE RECEIVED");
#endif
	uint8_t length[2] = {0x00,0x00};
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 10240; //6th flash sector
	//Erase flash sector
#ifdef DEBUG
		Serial.printf("Erase Sector 0x%X ",adr);
#endif
		if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
		Serial.printf("successful\r\n");

#endif
	onlykey_eeset_U2Fcertlen(length);
	hidprint("Successfully wiped U2F Certificate");
    blink(2);
#endif
    return;

}


void SETPRIV (uint8_t *buffer)
{
	uint8_t backupkeymode = 0;
	uint8_t backupkeyslot = 0;
	integrityctr2++;
	onlykey_eeget_backupkey(&backupkeyslot);
	integrityctr1++;
	onlykey_eeget_backupkeymode(&backupkeymode);
	integrityctr2++;
	if (backupkeymode && backupkeyslot == buffer[5] && initcheck) {
		hidprint("ERROR BACKUP KEY MODE SET TO SET ONCE");
		integrityctr1++;
		return;
	}
	integrityctr1++;
	if (profile2mode==NOENCRYPT) return;
	#ifdef US_VERSION
	if (buffer[6] > 0x80) {//Type is Backup key
	buffer[6] = buffer[6] - 0x80;
	onlykey_eeset_backupkey(buffer+5); //Set this key slot as the backup key
	}

	if (buffer[5] <= 4 && buffer[5] >= 1) {
	SETRSAPRIV(buffer);
	} else {
	SETECCPRIV(buffer);
	}
	#endif
}

void WIPEPRIV (uint8_t *buffer) {
	if (profile2mode==NOENCRYPT) return;
	#ifdef US_VERSION
	if (buffer[5] <= 4 && buffer[5] >= 1) {
	WIPERSAPRIV(buffer);
	} else {
		for(int i=6; i<=32; i++) {
		buffer[i]=0x00;
		}
	SETECCPRIV(buffer);
	}
	#endif
}

int onlykey_flashget_ECC (uint8_t slot)
{

if (profile2mode==NOENCRYPT) return 0;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.print("Flashget ECC key from slot # ");
	Serial.println(slot);
#endif
    extern uint8_t type;
	uint8_t features;
	if (slot<101 || slot>132) {
#ifdef DEBUG
	Serial.printf("Error invalid ECC slot");
#endif
	hidprint("Error invalid ECC slot");
	return 0;
	}
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 12288; //7th flash sector
	onlykey_eeget_ecckey(&type, slot); //Key Type (1-3) and slot (101-132)
	#ifdef DEBUG
    Serial.print("Type of ECC KEY with features is ");
	Serial.println(type);
	#endif
	features=type;
	if(type==0x00) {
		#ifdef DEBUG
		Serial.printf("There is no ECC Private Key set in this slot");
		#endif
		hidprint("There is no ECC Private Key set in this slot");
		if (outputU2F) {
			fadeoff(1);
		} else if (NEO_Color != 45) {
		NEO_Color = 1;
		blink(2);
		}
		return 0;
	}else {
		type = (type & 0x0F);
	}
	adr = adr + (((slot-100)*32)-32);
    onlykey_flashget_common((uint8_t*)ecc_private_key, (unsigned long*)adr, 32);
	aes_gcm_decrypt(ecc_private_key, slot, features, profilekey, 32);
	#ifdef DEBUG
	Serial.printf("Read ECC Private Key from Sector 0x%X ",adr);
	#endif
	if (type==1) Ed25519::derivePublicKey(ecc_public_key, ecc_private_key);
	else if (type==2) {
		const struct uECC_Curve_t * curve = uECC_secp256r1();
		uECC_compute_public_key(ecc_private_key, ecc_public_key, curve);
	}
	else if (type==3) {
	#ifdef DEBUG
	Serial.println("Compute of public key begin");
	#endif
		const struct uECC_Curve_t * curve = uECC_secp256k1();
		uECC_compute_public_key(ecc_private_key, ecc_public_key, curve);
	}
	#ifdef DEBUG
	Serial.println("Compute of public key complete");
	#endif
	return features;
#endif
	return 0;
}

void SETECCPRIV (uint8_t *buffer)
{

if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKSETECCPRIV MESSAGE RECEIVED");
#endif
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 12288; //7th free flash sector
	//Write ID to EEPROM
	if (buffer[5]<101 || buffer[5]>132) {
#ifdef DEBUG
	Serial.printf("Error invalid ECC slot");
#endif
	hidprint("Error invalid ECC slot");
	return;
	} else {
#ifdef DEBUG
	Serial.printf("Slot = %d ",buffer[5]);
	Serial.printf("Type = %d ",buffer[6]);
#endif
	}
	onlykey_eeset_ecckey(&buffer[6], (int)buffer[5]); //Key Type (1-4) and slot (101-132)
	//Write buffer to flash
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
	int gen_key = buffer[7] + buffer[8] + buffer[9] + buffer[10]+ buffer[11];
	if (gen_key == 0) { //All 0s
		GENERATE_KEY(buffer);
	}
#ifdef DEBUG
Serial.print("ECC Key value =");
byteprint((uint8_t*)buffer+7, 32);
#endif
	aes_gcm_encrypt(buffer+7, buffer[5], buffer[6], profilekey, 32);
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z < MAX_ECC_KEY_SIZE; z++){
    temp[z+(((buffer[5]-100)*MAX_ECC_KEY_SIZE)-MAX_ECC_KEY_SIZE)] = buffer[7+z];
    }
    //Erase flash sector
#ifdef DEBUG
    Serial.printf("Erase Sector 0x%X ",adr);
#endif
    if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
    Serial.printf("successful\r\n");
#endif
	//Write buffer to flash
    onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
#ifdef DEBUG
	Serial.println(buffer[5]);
#endif
	if (buffer[5]==131) { //Designated Backup Passphrase slot
	hidprint("Successfully set Backup Passphrase");	
	} else if (gen_key != 0 && initcheck){
	hidprint("Successfully set ECC Key");
      if (buffer[0] != 0xBA) blink(2);
	} 
#endif
      return;

}

int onlykey_flashget_RSA (uint8_t slot)
{

if (profile2mode==NOENCRYPT) return 0;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.print("Flashget RSA key from slot # ");
	Serial.println(slot);
#endif
	extern uint8_t type;
	uint8_t features;
	if (slot<1 || slot>4) {
#ifdef DEBUG
	Serial.printf("Error invalid RSA slot");
#endif
	hidprint("Error invalid RSA slot");
	return 0;
	}
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 14336; //8th free flash sector
	onlykey_eeget_rsakey(&type, slot); //Key Type (1-4) and slot (1-4)
	features=type;
	if (type==0x00) {
	#ifdef DEBUG
	Serial.printf("There is no RSA Private Key set in this slot");
	#endif
	hidprint("There is no RSA Private Key set in this slot");
	if (outputU2F) {
		fadeoff(1);
	} else if (NEO_Color != 45) {
	NEO_Color = 1;
	blink(2);
	}
	return 0;
	} else {
		type = (type & 0x0F);
	}
	#ifdef DEBUG
    Serial.print("Type of RSA KEY is ");
	Serial.println(type, HEX);
	#endif
	adr = adr + ((slot*MAX_RSA_KEY_SIZE)-MAX_RSA_KEY_SIZE);
    onlykey_flashget_common((uint8_t*)rsa_private_key, (unsigned long*)adr, (type*128));
	aes_gcm_decrypt(rsa_private_key, slot, features, profilekey, (type*128));
	#ifdef DEBUG
	Serial.printf("Read RSA Private Key from Sector 0x%X ",adr);
	byteprint(rsa_private_key, (type*128));
	#endif
	rsa_getpub(type);
	return features;
#endif
return 0;
}


void SETRSAPRIV (uint8_t *buffer)
{

if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKSETRSAPRIV MESSAGE RECEIVED");
#endif
	extern uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
	int keysize;
	uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 14336; //8th free flash sector
	if (buffer[5]<1 || buffer[5]>4) {
#ifdef DEBUG
	Serial.printf("Error invalid RSA slot");
#endif
	hidprint("Error invalid RSA slot");
	return;
	} else {
#ifdef DEBUG
	Serial.printf("Slot = %d ",buffer[5]);
	Serial.printf("Type = %d ",buffer[6]);
#endif
	}
	if ((buffer[6] & 0x0F) == 1) //Expect 128 Bytes, if buffer[0] != FF we know this is import from backup
	{
		keysize=128;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 114) {
		memcpy(rsa_private_key+packet_buffer_offset, buffer+7, 57);
		packet_buffer_offset = packet_buffer_offset + 57;
		}
	} else if ((buffer[6] & 0x0F) == 2) { //Expect 256 Bytes
		keysize=256;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 228) {
		memcpy(rsa_private_key+packet_buffer_offset, buffer+7, 57);
		packet_buffer_offset = packet_buffer_offset + 57;
		}
	} else if ((buffer[6] & 0x0F) == 3) { //Expect 384 Bytes
		keysize=384;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 342) {
		memcpy(rsa_private_key+packet_buffer_offset, buffer+7, 57);
		packet_buffer_offset = packet_buffer_offset + 57;
		}
	} else if ((buffer[6] & 0x0F) == 4) { //Expect 512 Bytes
		keysize=512;
		if (buffer[0] != 0xBA && packet_buffer_offset <= 456) {
		memcpy(rsa_private_key+packet_buffer_offset, buffer+7, 57);
		packet_buffer_offset = packet_buffer_offset + 57;
		}
	} else {
		hidprint("Error invalid RSA type");
		return;
	}
	//Write ID to EEPROM
	if (packet_buffer_offset >= keysize || buffer[0] == 0xBA) {		//Then we have the complete RSA key
	if (buffer[0] == 0xBA) {
		memcpy(rsa_private_key, buffer+7, keysize);
	}
	onlykey_eeset_rsakey(&buffer[6], (int)buffer[5]); //Key Type (1-4) and slot (1-4)
	//Write buffer to flash
#ifdef DEBUG
		Serial.print("Received RSA Key of size ");
        Serial.print(keysize*8);
		Serial.print("RSA Key value =");
		byteprint((uint8_t*)rsa_private_key, keysize);
#endif
    aes_gcm_encrypt(rsa_private_key, buffer[5], buffer[6], profilekey, keysize);
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z < MAX_RSA_KEY_SIZE; z++){
     temp[z+((buffer[5]*MAX_RSA_KEY_SIZE)-MAX_RSA_KEY_SIZE)] = rsa_private_key[z];
    }
    //Erase flash sector
#ifdef DEBUG
    Serial.printf("Erase Sector 0x%X ",adr);
#endif
    if (flashEraseSector((unsigned long*)adr)) {
#ifdef DEBUG
	Serial.printf("NOT ");
#endif
	}
#ifdef DEBUG
    Serial.printf("successful\r\n");
#endif
	//Write buffer to flash
    onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);

	packet_buffer_offset = 0;
	hidprint("Successfully set RSA Key");
      if (buffer[0] != 0xBA) blink(2);
	}
#endif
	return;
}


void WIPERSAPRIV (uint8_t *buffer) {
if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKWIPERSAPRIV MESSAGE RECEIVED");
#endif
	uintptr_t adr = (unsigned long)flashstorestart;
	adr = adr + 14336; //8th free flash sector
	//Wipe ID from EEPROM
	onlykey_eeset_rsakey(0, (int)buffer[5]);
	//Wipe flash
	uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Wipe content from buffer
    for( int z = 0; z < MAX_RSA_KEY_SIZE; z++){
    temp[z+((buffer[5]*MAX_RSA_KEY_SIZE)-MAX_RSA_KEY_SIZE)] = 0x00;
    }
	//Write buffer to flash
    onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
	hidprint("Successfully wiped RSA Private Key");
    blink(2);
#endif
    return;
}

/*************************************/
//Initialize Yubico OTP
/*************************************/
void yubikeyinit() {
if (profile2mode==NOENCRYPT) return;
#ifdef US_VERSION
  uint32_t seed;
  uint8_t *ptr = (uint8_t *)&seed;
  RNG2(ptr, 32); //Seed the onlyKey with random data

  uint8_t temp[32];
  uint8_t yaeskey[16];
  uint8_t privID[6];
  uint8_t pubID[16];
  uint8_t ctr[2];
  uint16_t counter;
  char public_id[32+1];
  char private_id[12+1];

#ifdef DEBUG
  Serial.println("Initializing YubiKey OTP...");
#endif
  memset(temp, 0, 32); //Clear temp buffer

  ptr = temp;
  onlykey_eeget_public(ptr);

  ptr = (temp+EElen_public);
  onlykey_eeget_private(ptr);

  ptr = (temp+EElen_public+EElen_private);
  onlykey_eeget_aeskey(ptr);

  aes_gcm_decrypt(temp, 0, 10, profilekey, (EElen_aeskey+EElen_private+EElen_public));
#ifdef DEBUG
  Serial.println("public_id");
#endif
  for (int i = 0; i < EElen_public; i++) {
    pubID[i] = temp[i];
#ifdef DEBUG
    Serial.print(pubID[i],HEX);
#endif
  }
#ifdef DEBUG
  Serial.println("private_id");
#endif
  for (int i = 0; i < EElen_private; i++) {
    privID[i] = temp[i+EElen_public];
#ifdef DEBUG
    Serial.print(privID[i],HEX);
#endif
  }
#ifdef DEBUG
  Serial.println("aes key");
#endif
    for (int i = 0; i < EElen_aeskey; i++) {
    yaeskey[i] = temp[i+EElen_public+EElen_private];
#ifdef DEBUG
    Serial.print(yaeskey[i],HEX);
#endif
  }

  memset(temp, 0, 32); //Clear temp buffer

  yubikey_eeget_counter(ctr);
  counter = ctr[0] << 8 | ctr[1];

  yubikey_hex_encode(private_id, (char *)privID, 6);
  yubikey_hex_encode(public_id, (char *)pubID, 6);
#ifdef DEBUG
    Serial.println("public_id");
  Serial.println(public_id);
    Serial.println("private_id");
  Serial.println(private_id);
    Serial.println("counter");
  Serial.println(counter);
#endif
  uint32_t time = 0x010203;

  yubikey_init1(&ctx, yaeskey, public_id, private_id, counter, time, seed);

  yubikey_incr_counter(&ctx);
  ctr[0] = ctx.counter >> 8  & 0xFF;
  ctr[1] = ctx.counter       & 0xFF;

  yubikey_eeset_counter(ctr);
#endif
}
/*************************************/
//Generate Yubico OTP
/*************************************/
void yubikeysim(char *ptr) {
	if (profile2mode==NOENCRYPT) return;
	#ifdef US_VERSION
	yubikey_simulate1(ptr, &ctx);
        yubikey_incr_usage(&ctx);
        #endif
}
/*************************************/
//Increment Yubico timestamp
/*************************************/
void yubikey_incr_time() {
	if (profile2mode==NOENCRYPT) return;
	#ifdef US_VERSION
	yubikey_incr_timestamp(&ctx);
	#endif
}

void increment(Task* me) {
  #ifndef OK_Color
  analogWrite(BLINKPIN, fade);
  #else
  if (NEO_Color == 1) pixels.setPixelColor(0, pixels.Color(fade,0,0)); //Red
  else if (NEO_Color < 44) pixels.setPixelColor(0, pixels.Color((fade/2),(fade/2),0)); //Yellow
  else if (NEO_Color < 86) pixels.setPixelColor(0, pixels.Color(0,fade,0)); //Green
  else if (NEO_Color < 129) pixels.setPixelColor(0, pixels.Color(0,(fade/2),(fade/2))); //Turquoise
  else if (NEO_Color < 171) pixels.setPixelColor(0, pixels.Color(0,0,fade)); //Blue
  else if (NEO_Color < 214) pixels.setPixelColor(0, pixels.Color((fade/2),0,(fade/2))); //Purple
  pixels.show(); // This sends the updated pixel color to the hardware.
  #endif
  fade += 8;
  if(fade == 0) {
    // -- Byte value overflows: 240 + 16 = 0
    SoftTimer.remove(&FadeinTask);
    SoftTimer.add(&FadeoutTask);
  }
}

void decrement(Task* me) {
  fade -= 8;
  #ifndef OK_Color
  analogWrite(BLINKPIN, fade);
  #else
 if (NEO_Color == 1) pixels.setPixelColor(0, pixels.Color(fade,0,0)); //Red
  else if (NEO_Color < 44) pixels.setPixelColor(0, pixels.Color((fade/2),(fade/2),0)); //Yellow
  else if (NEO_Color < 86) pixels.setPixelColor(0, pixels.Color(0,fade,0)); //Green
  else if (NEO_Color < 129) pixels.setPixelColor(0, pixels.Color(0,(fade/2),(fade/2))); //Turquoise
  else if (NEO_Color < 171) pixels.setPixelColor(0, pixels.Color(0,0,fade)); //Blue
  else if (NEO_Color < 214) pixels.setPixelColor(0, pixels.Color((fade/2),0,(fade/2))); //Purple
  pixels.show(); // This sends the updated pixel color to the hardware.
  #endif
  if(fade == 0) {
    // -- Floor reached.
    SoftTimer.remove(&FadeoutTask);
    SoftTimer.add(&FadeinTask);
  }
}

bool wipebuffersafter5sec(Task* me) {
	#ifdef DEBUG
	Serial.println("wipe buffers after 5 sec");
	#endif
	if (configmode==false) {
	packet_buffer_offset = 0;
	memset(packet_buffer, 0, sizeof(packet_buffer));
	#ifdef US_VERSION
	extern int large_resp_buffer_offset;
	large_resp_buffer_offset = 0;
	memset(large_resp_buffer, 0, sizeof(large_resp_buffer));
	#endif
	CRYPTO_AUTH = 0;
	Challenge_button1 = 0;
	Challenge_button2 = 0;
	Challenge_button3 = 0;
	sshchallengemode = 0;
	pgpchallengemode = 0;
	if (isfade || CRYPTO_AUTH) fadeoff(1); //Fade Red, failed to complete within 5 seconds
	}
	return false;
}

bool fadeoffafter20sec(Task* me) {
	#ifdef DEBUG
	Serial.println("wipe buffers after 20 sec");
	#endif
	if (isfade || CRYPTO_AUTH) fadeoff(1); //Fade Red, failed to enter PIN in 20 Seconds
	return false;
}

void fadeoff(uint8_t color) {
	Endfade.startDelayed(); //run fadeendafter2sec after 2 seconds (prevent accidental button press)
	wipedata();
	if (!color) { //No fade out 2 sec
		SoftTimer.remove(&FadeinTask);
		SoftTimer.remove(&FadeoutTask);
	#ifdef OK_Color
	setcolor(85); //Green
	#endif
	} else {
	#ifdef OK_Color
	NEO_Color = color;
	#endif
	}
}

bool fadeendafter2sec(Task* me) {
  SoftTimer.remove(&FadeinTask);
  SoftTimer.remove(&FadeoutTask);
  isfade=0;
  return false;
}

void fadeon() {
  SoftTimer.add(&FadeinTask);
  isfade=1;
}

void wipedata() {
  Wipedata.startDelayed();
}

void fadeoffafter20() {
  Usertimeout.startDelayed();
}

void cancelfadeoffafter20() {
	SoftTimer.remove(&Usertimeout); //Cancel this pin was entered
}


#ifdef OK_Color
// Input a value 0 to 255 to get a color value.
// The colours are a transition r - g - b - back to r.
uint32_t Wheel(uint8_t WheelPos) {
  WheelPos = 255 - WheelPos;
  if(WheelPos < 85) {
    return pixels.Color(255 - WheelPos * 3, 0, WheelPos * 3);
  }
  if(WheelPos < 170) {
    WheelPos -= 85;
    return pixels.Color(0, WheelPos * 3, 255 - WheelPos * 3);
  }
  WheelPos -= 170;
  return pixels.Color(WheelPos * 3, 255 - WheelPos * 3, 0);
}

void rainbowCycle(uint8_t wait, uint8_t cycle) {
  uint16_t i, j;
  for(j=0; j<256*cycle; j++) {
    for(i=0; i< pixels.numPixels(); i++) {
      pixels.setPixelColor(i, Wheel(((i * 256 / pixels.numPixels()) + j) & 255));
    }
    pixels.show();
    delay(wait);
	if (calibratecaptouch(j)) j=300;
  }
}

int calibratecaptouch (uint16_t j) {
	rngloop();
	if (((touchread1+touchread4+touchread5)*1.0) / ((touchread2+touchread3+touchread6)*1.0) > .6 && ((touchread1+touchread4+touchread5)*1.0) / ((touchread2+touchread3+touchread6)*1.0) < 1.6) {
	if (j>=400) {
			if (j==400) {
			touchread1ref = touchread1;
			touchread2ref = touchread2;
			touchread3ref = touchread3;
			touchread4ref = touchread4;
			touchread5ref = touchread5;
			touchread6ref = touchread6;
#ifdef DEBUG
			Serial.println(touchread1);
			Serial.println(touchread2);
			Serial.println(touchread3);
			Serial.println(touchread4);
			Serial.println(touchread5);
			Serial.println(touchread6);
#endif
			}
		touchread1ref = (touchread1+touchread1ref)/2;
		touchread2ref = (touchread2+touchread2ref)/2;
		touchread3ref = (touchread3+touchread3ref)/2;
		touchread4ref = (touchread4+touchread4ref)/2;
		touchread5ref = (touchread5+touchread5ref)/2;
		touchread6ref = (touchread6+touchread6ref)/2;
		}
	} else {
#ifdef DEBUG
		Serial.println(((touchread1+touchread4+touchread5)*1.0) / ((touchread2+touchread3+touchread6)*1.0));
#endif
	 return 1;
	}
	return 0;
}

void initColor() {
  pixels.begin(); // This initializes the NeoPixel library.
  pixels.setBrightness(204); //80% Brightness
  pixels.show();
}

void setcolor (uint8_t Color) {
	  if (Color == 0) pixels.setPixelColor(0, pixels.Color(0,0,0));
	  else {
		  pixels.setPixelColor(0, Wheel(Color));
		  NEO_Color = Color;
	  }
      pixels.show(); // This sends the updated pixel color to the hardware.
	  delay(1);
}
#endif

void backup() {
  if (profile2mode==NOENCRYPT) return;
  #ifdef US_VERSION
  uint8_t temp[MAX_RSA_KEY_SIZE];
  uint8_t large_temp[12323];
  int urllength;
  int usernamelength;
  int passwordlength;
  int otplength;
  uint8_t *ptr;
  unsigned char beginbackup[] = "-----BEGIN ONLYKEY BACKUP-----";
  unsigned char endbackup[] = "-----END ONLYKEY BACKUP-----";
  unsigned char nobackupkey[] = "No Backup Key - Follow instructions here https://docs.crp.to/usersguide.html#secure-encrypted-backup-anywhere";
  uint8_t ctr[2];
  bool backupyubikey=false;
  uint8_t slot;
  uint8_t length[2];
  uint8_t addchar1;
  uint8_t addchar2;
  uint8_t addchar3;
  uint8_t addchar4;
  uint8_t addchar5;
  large_data_offset = 0;
  memset(large_temp, 0, sizeof(large_temp)); //Wipe all data from largebuffer
  #ifdef OK_Color
  setcolor(45); //Yellow
  #endif
  for (uint8_t z = 0; z < sizeof(beginbackup); z++) {
		Keyboard.press(beginbackup[z]);
		delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
	}

  for (slot=1; slot<=61; slot++)
  {
  #ifdef DEBUG
    Serial.print("Backing up Label Number ");
    Serial.println(slot);
  #endif
    memset(temp, 0, sizeof(temp)); //Wipe all data from temp buffer
    ptr = temp;
	onlykey_flashget_label(ptr, slot);
	if(temp[0] != 0xFF && temp[0] != 0x00)
      {
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 1; //1 - Label
		memcpy(large_temp+large_data_offset+3, temp, EElen_label);
        large_data_offset=large_data_offset+EElen_label+3;
      }
  }
  for (slot=1; slot<=24; slot++)
  {
	#ifdef DEBUG
    Serial.print("Backing up Slot Number ");
    Serial.println(slot);
    #endif
	memset(temp, 0, sizeof(temp)); //Wipe all data from temp buffer
    ptr = temp;
    urllength = onlykey_flashget_url(ptr, slot);
    if(urllength > 0)
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
    #ifdef US_VERSION
		if (profile2mode!=NOENCRYPT) aes_gcm_decrypt(temp, slot, 15, profilekey, urllength);
    #endif
    #ifdef DEBUG
        Serial.println("Unencrypted");
		byteprint(temp, urllength);
        Serial.println();
        #endif
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 15; //15 - URL
		memcpy(large_temp+large_data_offset+3, temp, urllength);
        large_data_offset=large_data_offset+urllength+3;
      }
      onlykey_eeget_addchar(&addchar5, slot);
	  addchar1 = addchar5 & 0x3; //After Username
      addchar2 = (addchar5 >> 4) & 0x3; //After Password
      addchar3 = (addchar5 >> 6) & 0x1; //After OTP
      addchar4 = (addchar5 >> 2) & 0x1; //Before Username
      addchar5 = (addchar5 >> 3) & 0x1; //Before OTP
	  if(addchar1 > 0)
      {
        large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 16; //16 - Add Char 1
		large_temp[large_data_offset+3] = addchar1;
        large_data_offset=large_data_offset+4;
      }
      if(addchar2 > 0)
      {
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 3; //3 - Add Char 2
		large_temp[large_data_offset+3] = addchar2;
        large_data_offset=large_data_offset+4;
      }
      if(addchar3 > 0)
      {
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 6; //6 - Add Char 3
		large_temp[large_data_offset+3] = addchar3;
        large_data_offset=large_data_offset+4;
      }
      if(addchar4 > 0)
      {
        large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 18; //18 - Add Char 4
		large_temp[large_data_offset+3] = addchar4;
        large_data_offset=large_data_offset+4;
      }
      if(addchar5 > 0)
      {
        large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 19; //19 - Add Char 5
		large_temp[large_data_offset+3] = addchar5;
        large_data_offset=large_data_offset+4;
      }
      onlykey_eeget_delay1(ptr, slot);
      if(temp[0] > 0)
      {
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 17; //17 - Delay 1
		large_temp[large_data_offset+3] = temp[0];
        large_data_offset=large_data_offset+4;
      }
      usernamelength = onlykey_flashget_username(ptr, slot);
      if(usernamelength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Username from Flash...");
        Serial.print("Username Length = ");
        Serial.println(usernamelength);
        #endif
        if (profile2mode!=NOENCRYPT) {
        #ifdef DEBUG
        Serial.println("Encrypted");
		byteprint(temp, usernamelength);
        Serial.println();
        #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, slot, 2, profilekey, usernamelength);
        #endif
        }
		#ifdef DEBUG
        Serial.println("Unencrypted");
		byteprint(temp, usernamelength);
        Serial.println();
        #endif
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 2; //2 - Username
		memcpy(large_temp+large_data_offset+3, temp, usernamelength);
        large_data_offset=large_data_offset+usernamelength+3;
      }
      onlykey_eeget_delay2(ptr, slot);
      if(temp[0] > 0)
      {
       	large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 4; //4 - Delay 2
		large_temp[large_data_offset+3] = temp[0];
        large_data_offset=large_data_offset+4;
      }
      passwordlength = onlykey_eeget_password(ptr, slot);
      if(passwordlength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Password from EEPROM...");
        Serial.print("Password Length = ");
        Serial.println(passwordlength);
        #endif
        if (profile2mode!=NOENCRYPT) {
        #ifdef DEBUG
        Serial.println("Encrypted");
		byteprint(temp, passwordlength);
        Serial.println();
          #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, slot, 5, profilekey, passwordlength);
        #endif
        }
		#ifdef DEBUG
        Serial.println("Unencrypted");
		byteprint(temp, passwordlength);
        Serial.println();
        #endif
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 5; //5 - Password
		memcpy(large_temp+large_data_offset+3, temp, passwordlength);
        large_data_offset=large_data_offset+passwordlength+3;
      }
      onlykey_eeget_delay3(ptr, slot);
      if(temp[0] > 0)
      {
       	large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 7; //7 - Delay 3
		large_temp[large_data_offset+3] = temp[0];
        large_data_offset=large_data_offset+4;
      }
      otplength = onlykey_eeget_2FAtype(ptr, slot);
      if(temp[0] > 0)
      {
        large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 8; //8 - 2FA type
		large_temp[large_data_offset+3] = temp[0];
        large_data_offset=large_data_offset+4;
	  }
	  if(temp[0] == 103) { //Google Auth
      #ifdef DEBUG
      Serial.println("Reading TOTP Key from Flash...");
      #endif
      otplength = onlykey_flashget_totpkey(ptr, slot);
	  #ifdef DEBUG
      Serial.println("Encrypted");
	  byteprint(temp, otplength);
      Serial.println();
      Serial.print("TOTP Key Length = ");
      Serial.println(otplength);
      #endif
      if (profile2mode!=NOENCRYPT) aes_gcm_decrypt(temp, slot, 9, profilekey, otplength);
      #ifdef DEBUG
      Serial.println("Unencrypted");
	  byteprint(temp, otplength);
      Serial.println();
	  #endif
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = slot;
	  large_temp[large_data_offset+2] = 9; //9 - TOTP Key
	  large_temp[large_data_offset+3] = otplength;
	  memcpy(large_temp+large_data_offset+4, temp, otplength);
      large_data_offset=large_data_offset+otplength+4;
	  }
	  if(temp[0] == 121) { //Yubikey
	  backupyubikey=true;
	  }
}
      onlykey_eeget_typespeed(ptr);
	  if (*ptr != 0) {
	  *ptr=11-*ptr;
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = 0; //slot 0
	  large_temp[large_data_offset+2] = 13; //13 - Keyboard type speed
	  large_temp[large_data_offset+3] = temp[0];
      large_data_offset=large_data_offset+4;
	  }
	  onlykey_eeget_keyboardlayout(ptr);
	  if (*ptr != 0) {
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = 0; //slot 0
	  large_temp[large_data_offset+2] = 14; //14- Keyboard layout
	  large_temp[large_data_offset+3] = temp[0];
      large_data_offset=large_data_offset+4;
	  }
	  onlykey_eeget_timeout(ptr);
	  if (*ptr != 0) {
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = 0; //slot 0
	  large_temp[large_data_offset+2] = 11; //11 - Idle Timeout
	  large_temp[large_data_offset+3] = temp[0];
      large_data_offset=large_data_offset+4;
	  }
	  yubikey_eeget_counter(ctr);
      if (backupyubikey) {
	  onlykey_eeget_public(ptr);

      ptr = (temp+EElen_public);
      onlykey_eeget_private(ptr);

      ptr = (temp+EElen_public+EElen_private);
      onlykey_eeget_aeskey(ptr);

      aes_gcm_decrypt(temp, 0, 10, profilekey, (EElen_aeskey+EElen_private+EElen_public));

	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = 0; //slot 0
	  large_temp[large_data_offset+2] = 10; //10 - Yubikey
	  memcpy(large_temp+large_data_offset+3, temp, (EElen_aeskey+EElen_private+EElen_public));
      large_data_offset=large_data_offset+(EElen_aeskey+EElen_private+EElen_public)+3;
	  large_temp[large_data_offset] = ctr[0]; //first part of counter
	  large_temp[large_data_offset+1] = ctr[1]; //second part of counter
	  large_data_offset=large_data_offset+2;
	  }

	#ifdef DEBUG
	Serial.println();
    Serial.println("Unencrypted Slot Backup");
	byteprint(large_temp, large_data_offset);
    Serial.println();
    #endif


  //Copy RSA keys to buffer
  uint8_t backupslot;
  onlykey_eeget_backupkey (&backupslot);
  for (uint8_t slot=1; slot<=4; slot++)
  {
	#ifdef DEBUG
    Serial.print("Backing up RSA Key Number ");
    Serial.println(slot);
   #endif
    memset(temp, 0, MAX_RSA_KEY_SIZE); //Wipe all data from temp buffer
    ptr = temp;
	uint8_t features = onlykey_flashget_RSA(slot);
	if (slot == backupslot) features = features + 0x80;
	if(features != 0x00)
      {
		large_temp[large_data_offset] = 0xFE; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = features;
		memcpy(large_temp+large_data_offset+3, rsa_private_key, (type*128));
        large_data_offset=large_data_offset+(type*128)+3;
		#ifdef DEBUG
			byteprint(rsa_private_key, (type*128));
		#endif
      } else {
			#ifdef DEBUG
			Serial.print("No key set to slot");
			#endif
	  }
  }

  //Copy ECC keys to buffer
  for (uint8_t slot=101; slot<=132; slot++)
  {
	#ifdef DEBUG
    Serial.print("Backing up ECC Key Number ");
    Serial.println(slot);
   #endif
    memset(temp, 0, MAX_RSA_KEY_SIZE); //Wipe all data from temp buffer
    ptr = temp;
	uint8_t features = onlykey_flashget_ECC(slot);
	if (slot == backupslot) features = features + 0x80;
	if(features != 0x00)
      {
		large_temp[large_data_offset] = 0xFE; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = features;
		memcpy(large_temp+large_data_offset+3, ecc_private_key, MAX_ECC_KEY_SIZE);
        large_data_offset=large_data_offset+MAX_ECC_KEY_SIZE+3;
		#ifdef DEBUG
			byteprint(ecc_private_key, MAX_ECC_KEY_SIZE);
		#endif
      } else {
			#ifdef DEBUG
			Serial.print("No key set to slot");
			#endif
	  }
  }

//Copy U2F key/Cert to buffer
	onlykey_eeget_U2Fcertlen(length);
	int length2 = length[0] << 8 | length[1];
	if (length2 != 0) {
	large_temp[large_data_offset] = 0xFD; //delimiter
	memcpy(large_temp+large_data_offset+1, attestation_priv, 32);
    large_data_offset=large_data_offset+32+1;
	large_temp[large_data_offset] = 0; //Backward compatability used to backup U2F counter
	large_data_offset++;
	large_temp[large_data_offset] = 0;
	large_data_offset++;
	large_temp[large_data_offset] = length[0];
	large_data_offset++;
	large_temp[large_data_offset] = length[1];
	large_data_offset++;
	memcpy(large_temp+large_data_offset, attestation_der, length2);
    large_data_offset=large_data_offset+length2;
	#ifdef DEBUG
	Serial.print("Found U2F Certificate to backup");
	#endif
	} else {
	#ifdef DEBUG
	Serial.print("No U2F Certificate to backup");
	#endif
	}

	#ifdef DEBUG
	Serial.println();
    Serial.println("Unencrypted");
	byteprint(large_temp, large_data_offset);
    Serial.println();
    #endif


	//ENCRYPT
	onlykey_eeget_backupkey (&slot);
	#ifdef DEBUG
	Serial.println();
    Serial.print("Backup Key Assigned to Slot # ");
    Serial.println(slot);
    Serial.println();
    #endif
	ptr = temp;
	RNG2(ptr, 32); //Fill temp with random data
	if (slot == 0) {
		hidprint("Error no backup key set");
		for (uint8_t z = 0; z < sizeof(nobackupkey); z++) {
			Keyboard.press(nobackupkey[z]);
			delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
			Keyboard.releaseAll();
			delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
		}
		return;
	}
	else if (slot > 100) {
		uint8_t iv[12];
		uint8_t secret[32];
		memcpy(iv, temp, 12);
		onlykey_flashget_ECC (slot);
		if (shared_secret (ecc_public_key, secret)) {
			hidprint("Error with ECC Shared Secret");
			return;
		}
		SHA256_CTX context;
		sha256_init(&context);
		sha256_update(&context, secret, 32); //add secret
		sha256_update(&context, ecc_public_key, 32); //Add public key
		sha256_update(&context, iv, 12); //add AES GCM IV
		sha256_final(&context, secret);
		#ifdef DEBUG
		Serial.println("AES KEY = ");
		byteprint(secret, 32);
		#endif
		aes_gcm_encrypt2 (large_temp, iv, secret, large_data_offset);
		memcpy (large_temp+large_data_offset, iv, 12);
		#ifdef DEBUG
		Serial.println("IV = ");
		byteprint(iv, 12);
		#endif
		large_data_offset=large_data_offset+12;
		large_temp[large_data_offset] = type+100;
		#ifdef DEBUG
		Serial.println("Type = ");
		Serial.println(large_temp[large_data_offset]);
		#endif
		large_data_offset++;
	}
	else if (slot <= 4) {
		onlykey_flashget_RSA (slot);
		uint8_t iv[12] = "BACKUP12345";
		uint8_t temp2[512];
		#ifdef DEBUG
		Serial.println("AES KEY = ");
		byteprint(temp, 32);
		#endif
		aes_gcm_encrypt2 (large_temp, iv, temp, large_data_offset);
		//No need for unique IVs when random key used
		if (rsa_encrypt(32, temp, temp2)) {
			hidprint("Error with RSA Encryption");
			return;
		}
		#ifdef DEBUG
		Serial.println("RSA Encrypted AES KEY = ");
		byteprint(temp2, (type*128));
		#endif
		memcpy (large_temp+large_data_offset, temp2, (type*128));
		large_data_offset=large_data_offset+(type*128);
		large_temp[large_data_offset] = type;
		#ifdef DEBUG
		Serial.println("Type = ");
		Serial.println(large_temp[large_data_offset]);
		#endif
		large_data_offset++;
	}

    #ifdef DEBUG
	Serial.println();
	Serial.println("Encrypted");
	//byteprint(large_temp,large_data_offset);
	Serial.println();
    #endif


	int i = 0;
	while(i <= large_data_offset && i < (int)sizeof(large_temp)) {
		Keyboard.press(KEY_RETURN);
        delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
        Keyboard.releaseAll();
		delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
		if ((large_data_offset - i) < 57) {
			int enclen = base64_encode(large_temp+i, temp, (large_data_offset - i), 0);
			for (int z = 0; z < enclen; z++) {
			Keyboard.press(temp[z]);
			delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
			Keyboard.releaseAll();
			delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
			}
		}
		else {
			base64_encode(large_temp+i, temp, 57, 0);
			for (int z = 0; z < 4*(57/3); z++) {
			Keyboard.press(temp[z]);
			delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
			Keyboard.releaseAll();
			delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
			}
		}
		i = i+57;
		memset(temp, 0, sizeof(temp));
	}
	Keyboard.press(KEY_RETURN);
    delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
    Keyboard.releaseAll();
	delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
	#ifdef DEBUG
        Serial.println("Encoded");
		byteprint(large_temp,large_data_offset);
        Serial.println();
    #endif

	//End backup footer
    for (uint8_t z = 0; z < sizeof(endbackup); z++) {
		Keyboard.press(endbackup[z]);
		delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
		Keyboard.releaseAll();
		delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
	}
	Keyboard.println();
large_data_offset = 0;
memset(large_temp, 0 , sizeof(large_temp));
#endif
}

int freeRam () {
    extern int __heap_start, *__brkval;
    int v;
    return (int) &v - (__brkval == 0 ? (int) &__heap_start : (int) __brkval);
}

void RESTORE(uint8_t *buffer) {
  if (profile2mode==NOENCRYPT) return;
  #ifdef US_VERSION
  uint8_t temp[MAX_RSA_KEY_SIZE+7];
  static uint8_t* large_temp;
  static unsigned int offset = 0;
  if (offset == 0) large_temp = (uint8_t*)malloc(12323); //Max size for slots 7715 max size for keys 3072 + 768 + 32 + headers + Max RSA key size
  uint8_t *ptr;
  uint8_t slot;


  //Slot restore
  if (buffer[5]==0xFF) //Not last packet
	{
	if (offset <= (sizeof(large_temp) - 57)) {
			memcpy(large_temp+offset, buffer+6, 57);
#ifdef DEBUG
			Serial.print("Restore packet received =");
			byteprint(large_temp+offset, 57);
#endif
			offset = offset + 57;
		} else {
			hidprint("Error backup file too large");
			return;
		}
		return;
	} else { //last packet
		if (offset <= (sizeof(large_temp) - 57) && buffer[5] <= 57) {
			memcpy(large_temp+offset, buffer+6, buffer[5]);
#ifdef DEBUG
		Serial.print("Restore packet received =");
		byteprint(large_temp+offset, buffer[5]);
#endif
			offset = offset + buffer[5];
		} else {
			hidprint("Error backup file too large");
			return;
		}
#ifdef DEBUG
		Serial.print("Length of backup file = ");
        Serial.println(offset);
#endif


//DECRYPT
	onlykey_eeget_backupkey (&slot);
	offset--;
	#ifdef DEBUG
	Serial.print("Type of Backup Key = ");
	Serial.println(large_temp[offset]);
	#endif
	if (slot == 0) {
		hidprint("Error no backup key set");
				while (1==1) {
				blink(3);
				}
	}
	else if (slot > 100) {
		onlykey_flashget_ECC (slot);
		#ifdef DEBUG
		Serial.println(type);
		#endif
		if (type != (large_temp[offset]-100)) {
			hidprint("Error key type used for backup does not match");
				while (1==1) {
				blink(3);
				}
		} else {
		uint8_t iv[12];
		offset=offset-12;
		memcpy(iv, large_temp+offset, 12);
		shared_secret (ecc_public_key, temp);

		byteprint(temp, 32);
		SHA256_CTX context;
		sha256_init(&context);
		sha256_update(&context, temp, 32); //add secret
		sha256_update(&context, ecc_public_key, 32); //add public key
		sha256_update(&context, iv, 12); //add AES GCM IV
		sha256_final(&context, temp);
		#ifdef DEBUG
		Serial.println("AES KEY = ");
		byteprint(temp, 32);
		#endif
		aes_gcm_decrypt2 (large_temp, iv, temp, offset);
	}
	}
	else if (slot <= 4) {
		unsigned int len = 0;
		onlykey_flashget_RSA (slot);
		if (type != large_temp[offset]) {
			hidprint("Error key type used for backup does not match");
				while (1==1) {
				blink(3);
				}
		} else {
		uint8_t temp2[512];
		offset=offset-(type*128);
		memcpy(temp, large_temp+offset, (type*128));
		#ifdef DEBUG
		Serial.println("RSA Encrypted AES Key = ");
		byteprint(temp, (type*128));
		#endif
		rsa_decrypt(&len, temp, temp2);
		#ifdef DEBUG
		Serial.println("AES KEY = ");
		byteprint(temp2, 32);
		#endif
		uint8_t iv[12] = "BACKUP12345";
		aes_gcm_decrypt2 (large_temp, iv, temp2, offset);
		//No need for unique IVs when random key used
	}
	}



#ifdef DEBUG
			Serial.print("backup file received =");
			byteprint(large_temp, offset);
#endif
		large_temp[offset+1] = 0xFC;
		ptr = large_temp;
		#ifdef OK_Color
		setcolor(45); //Yellow
		#endif
		while(*ptr) {
			if (*ptr == 0xFF) {
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
				if (temp[6] == 10) { //Yubikey OTP
				memcpy(temp+7, ptr, (EElen_aeskey+EElen_private+EElen_public));
				SETSLOT(temp);
				memset(temp, 0, sizeof(temp));
				uint8_t ctr[2];
				ptr = ptr + EElen_aeskey+EElen_private+EElen_public;
				ctr[0] = *ptr;
				ptr++;
				ctr[1] = *ptr;
				uint16_t counter = ctr[0] << 8 | ctr[1];
				counter += 300; //Increment by 300
				ctr[0] = counter >> 8  & 0xFF;
				ctr[1] = counter       & 0xFF;
				yubikey_eeset_counter(ctr);
				#ifdef DEBUG
							Serial.print("New Yubikey Counter =");
							byteprint(ctr, 2);
				#endif
				ptr++;
				} else if (temp[6] == 9) { //TOTP
				int len = *ptr;
				ptr++;
				memcpy(temp+7, ptr, len);
				SETSLOT(temp);
				memset(temp, 0, sizeof(temp));
				ptr = ptr + len;
				} else if (temp[6] == 11) { //lockout time
				temp[7] = *ptr;
				SETSLOT(temp);
				memset(temp, 0, sizeof(temp));
				ptr++;
				} else {
				temp[7] = *ptr;
				int i = 8;
				ptr++;
				while (*ptr != 0xFF && *ptr != 0xFE && *ptr != 0xFD && *ptr != 0xFC) {
					temp[i] = *ptr;
					ptr++;
					i++;
				}
				SETSLOT(temp);
				}
			}  else if (*ptr == 0xFE) { //Finished slot restore, start key restore
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
				if (temp[5] > 100) { //We know its an ECC key
					#ifdef DEBUG
					Serial.print("Restore ECC key");
					Serial.print("Type");
					Serial.print(temp[6]);
					Serial.print("slot");
					Serial.print(temp[5]);
					#endif
					ptr++; //Start of Key
					memcpy(temp+7, ptr, MAX_ECC_KEY_SIZE); //Size of ECC key 32
					SETPRIV(temp);
					ptr = ptr + MAX_ECC_KEY_SIZE;
					offset = offset - (MAX_ECC_KEY_SIZE+3);
				} else if ((temp[6] & 0x0F) == 1) { //Expect 128 Bytes
					#ifdef DEBUG
					Serial.print("Restore RSA 1024 key");
					#endif
					ptr++;
					memcpy(temp+7, ptr, 128);
					SETPRIV(temp);
					ptr = ptr + 128;
					offset = offset - 131;
				}
				else if ((temp[6] & 0x0F) == 2) { //Expect 256 Bytes
					#ifdef DEBUG
					Serial.print("Restore RSA 2048 key");
					#endif
					ptr++;
					memcpy(temp+7, ptr, 256);
					SETPRIV(temp);
					ptr = ptr + 256;
					offset = offset - 259;
				}
				else if ((temp[6] & 0x0F) == 3) { //Expect 384 Bytes
					#ifdef DEBUG
					Serial.print("Restore RSA 3072 key");
					#endif
					ptr++;
					memcpy(temp+7, ptr, 384);
					SETPRIV(temp);
					ptr = ptr + 384;
					offset = offset - 387;
				}
				else if ((temp[6] & 0x0F) == 4) { //Expect 512 Bytes
					#ifdef DEBUG
					Serial.print("Restore RSA 4096 key");
					#endif
					ptr++;
					memcpy(temp+7, ptr, 512);
					SETPRIV(temp);
					ptr = ptr + 512;
					offset = offset - 515;
				} else {
					#ifdef DEBUG
					Serial.print("Error key configuration backup file format incorrect");
					#endif
					hidprint("Error key configuration backup file format incorrect");
				}
			} else if (*ptr == 0xFD) {
					int temp2;
					memset(temp, 0, sizeof(temp));
					temp[0] = 0xBA;
					temp[1] = 0xFF;
					temp[2] = 0xFF;
					temp[3] = 0xFF;
					temp[4] = OKSETU2FPRIV;
					ptr++;
					offset--;
					memcpy(temp+5, ptr, 32);
					SETU2FPRIV(temp);
					ptr = ptr + 32;
					offset = offset - 32;
					// For backward compatability with older versions, used to backup U2F counter
					offset = offset - 2;
					ptr=ptr+2;
					memcpy(temp, ptr, 2);
					temp2 = temp[0] << 8 | temp[1];
					//Set U2F Certificate size
					onlykey_eeset_U2Fcertlen(temp);
					offset = offset - 2;
					ptr=ptr+2;
					large_temp[0] = 0xBA;
					large_temp[1] = 0xFF;
					large_temp[2] = 0xFF;
					large_temp[3] = 0xFF;
					large_temp[4] = OKSETU2FCERT;
					large_temp[5] = 0xBA;
					if (temp2 < 769) {
						memcpy(large_temp+6, ptr, temp2);
					large_data_len=temp2;
					SETU2FCERT(large_temp);
					}
			} else {
			break;
			}
	}
	hidprint("Successfully loaded backup");
	#ifdef DEBUG
	Serial.print("Successfully loaded backup");
	#endif
	memset(temp, 0, sizeof(temp)); //Wipe all data from temp
	memset(large_temp, 0, 12323); //Wipe all data from largebuffer
	offset = 0;
	free(large_temp);
	delay(1000);
	hidprint("Remove and Reinsert OnlyKey to complete restore");
	fadeoff(0);
	large_data_len = 0;
	#ifdef OK_Color
    NEO_Color = 85; //Green
    #endif
	delay(100);
	CPU_RESTART();
	while (1==1) {
	blink(3);
	}
    }
	#endif
}

void process_packets (uint8_t *buffer) {
	if (profile2mode==NOENCRYPT) return;
    #ifdef US_VERSION
	uint8_t temp[32];
	isfade=1;
	wipedata(); //Wait 5 seconds to receive packets
	sshchallengemode=0;
	pgpchallengemode=0;
	if (CRYPTO_AUTH >= 1) {
		if (outputU2F == 1) {
#ifdef DEBUG
	     Serial.println("Warning, wiping unretrieved data in packet buffer");
		 Serial.println(packet_buffer_offset);
#endif
		CRYPTO_AUTH = 0;
		Challenge_button1 = 0;
		Challenge_button2 = 0;
		Challenge_button3 = 0;
		packet_buffer_offset = 0;
		memset(packet_buffer, 0, sizeof(packet_buffer));
		}
	}
    if (buffer[6]==0xFF) //Not last packet
    {
        if (packet_buffer_offset <= (int)(sizeof(packet_buffer) - 57)) {
            memcpy(packet_buffer+packet_buffer_offset, buffer+7, 57);
            packet_buffer_offset = packet_buffer_offset + 57;
			byteprint(packet_buffer, packet_buffer_offset);
        } else {
              if (!outputU2F) hidprint("Error packets received exceeded size limit");
			  return;
        }
    } else { //Last packet
        if (packet_buffer_offset <= (int)(sizeof(packet_buffer) - 57) && buffer[6] <= 57 && buffer[6] >= 1) {
            memcpy(packet_buffer+packet_buffer_offset, buffer+7, buffer[6]);
            packet_buffer_offset = packet_buffer_offset + buffer[6];
			packet_buffer_details[0] = buffer[4];
			packet_buffer_details[1] = buffer[5];
			byteprint(packet_buffer, packet_buffer_offset);
			CRYPTO_AUTH = 1;
			SoftTimer.remove(&Wipedata); //Cancel this we got all packets
			fadeoffafter20(); //Wipe and fadeoff after 20 seconds
			if (packet_buffer_details[1] > 200) { //SSH request
			onlykey_eeget_sshchallengemode(&sshchallengemode);
			}
			if (packet_buffer_details[1] < 5 || (packet_buffer_details[1] > 100 && packet_buffer_details[1] <= 132)) { //PGP request
			onlykey_eeget_pgpchallengemode(&pgpchallengemode);
			}
			if (sshchallengemode || pgpchallengemode) {
				CRYPTO_AUTH = 3;
			} else {
				
				SHA256_CTX msg_hash;
				sha256_init(&msg_hash);
				sha256_update(&msg_hash, packet_buffer, packet_buffer_offset); //add data to sign
				sha256_final(&msg_hash, temp); //Temporarily store hash
				if (temp[0] < 6) Challenge_button1 = '1'; //Convert first byte of hash
				else {
					Challenge_button1 = temp[0] % 5; //Get the base 5 remainder (0-5)
					Challenge_button1 = Challenge_button1 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
				}
				if (temp[15] < 6) Challenge_button2 = '1'; //Convert middle byte of hash
				else {
					Challenge_button2 = temp[15] % 5; //Get the base 5 remainder (0-5)
					Challenge_button2 = Challenge_button2 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
				}
				if (temp[31] < 6) Challenge_button3 = '1'; //Convert last byte of hash
				else {
					Challenge_button3 = temp[31] % 5; //Get the base 5 remainder (0-5)
					Challenge_button3 = Challenge_button3 + '0' + 1; //Add '0' and 1 so number will be ASCII 1 - 6
				}
			} 
#ifdef DEBUG
    Serial.println("Received Message");
	byteprint(packet_buffer, packet_buffer_offset);
    Serial.printf("Enter challenge code %c%c%c", Challenge_button1,Challenge_button2,Challenge_button3);
	Serial.println();
#endif
		fadeon();
        } else {
            if (!outputU2F) hidprint("Error packets received exceeded size limit");
			return;
        }
	}
	if (outputU2F) custom_error(0); //ACK
	return;
	#endif
}
/*
void temp_voltage () {
	float average = 0;
	analogReference(INTERNAL);
	analogReadResolution(12);
	   for (int i =0;i<255;i++){
		  average = analogRead(38)+average;
		}
	average= average/255;
	float C = 25.0 + 0.17083 * (2454.19 - average);
#ifdef DEBUG
	Serial.print(average);
	Serial.print(' ');
    Serial.print(C);
    Serial.println ("C - Internal Temperature");
#endif
	analogReference(DEFAULT);
	analogReadResolution(12);
	analogReadAveraging(32);
	int mv;
	mv = 1200 * 4096 /analogRead(39);
	#ifdef DEBUG
	  Serial.print(mv);
      Serial.println ("mv - VCC");
	#endif
}
*/
int RNG2(uint8_t *dest, unsigned size) {
	// Generate output whenever 32 bytes of entropy have been accumulated.
    // The first time through, we wait for 48 bytes for a full entropy pool.
    while (!RNG.available(length)) {
      //Serial.println("waiting for random number");
	  rngloop(); //Gather entropy
    }
    RNG.rand(dest, size);
    length = 32;
#ifdef DEBUG
	if (size>1) {
		Serial.println();
		Serial.print("Generating random number of size = ");
		Serial.print(size);
		byteprint(dest, size);
	}
#endif
    return 1;
}
