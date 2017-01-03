/* okcore.cpp
*/

/* Tim Steiner
 * Copyright (c) 2016 , CryptoTrust LLC.
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


#include "sha256.h"
#include <string.h>
#include <EEPROM.h>
#include <SoftTimer.h>
#include <password.h>
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include <RNG.h>
#include "T3MacLib.h"
#include "base64.h"

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
bool PDmode;
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
uint8_t fade = 0;
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
extern uint8_t phash[32];
extern uint8_t sdhash[32];
extern uint8_t pdhash[32];
extern uint8_t nonce[32];
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
/*************************************/
//HID Report Assignments
/*************************************/
uint8_t setBuffer[64] = {0};
uint8_t getBuffer[64] = {0};
/*************************************/
//RNG Assignments
/*************************************/
size_t length = 48; // First block should wait for the pool to fill up.
/*************************************/
//U2F Assignments
/*************************************/
uint8_t expected_next_packet;
int large_data_len;
int large_data_offset;
uint8_t large_buffer[BUFFER_SIZE];
uint8_t large_resp_buffer[1024];
uint8_t recv_buffer[64];
uint8_t resp_buffer[64];
extern uint8_t handle[64];
uint8_t sha256_hash[32];
char attestation_pub[66];
char attestation_priv[33];
char attestation_der[768];
/*************************************/
//ECC assignments
/*************************************/
extern uint8_t ecc_signature[64];
extern uint8_t ecc_public_key[32];
extern uint8_t ecc_private_key[32];
/*************************************/
/*************************************/
//RSA assignments
/*************************************/
extern uint8_t rsa_signature[256];
extern uint8_t rsa_public_key[256];
extern uint8_t rsa_private_key[256];
/*************************************/

void recvmsg() {
  int n;
  n = RawHID.recv(recv_buffer, 0); // 0 timeout = do not wait
  if (n > 0) {
#ifdef DEBUG    
    Serial.print(F("\n\nReceived packet"));
    for (int z=0; z<64; z++) {
        Serial.print(recv_buffer[z], HEX);
    }
	
#endif    
	
	  switch (recv_buffer[4]) {
      case OKSETPIN:
      if(!PDmode) {
      SETPIN(recv_buffer);
      } else {
      SETPDPIN(recv_buffer);
      }
      return;
      break;
      case OKSETSDPIN:
      SETSDPIN(recv_buffer);
      return;
      break;
      case OKSETPDPIN:
      SETPDPIN(recv_buffer);
      return;
      break;
      case OKSETTIME:
      SETTIME(recv_buffer);
      return;
      break;
      case OKGETLABELS:
	   if(initialized==false && unlocked==true) 
	   {
		hidprint("Error No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		GETLABELS(recv_buffer);
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
      case OKSETSLOT:
	   if(initialized==false && unlocked==true) 
	   {
		if (recv_buffer[6] == 12) {
		SETSLOT(recv_buffer);
		} else {
		hidprint("Error No PIN set, You must set a PIN first");
		}
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		SETSLOT(recv_buffer);
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }
      return;
      break;
      case OKWIPESLOT:
	   if(initialized==false && unlocked==true) 
	   {
		hidprint("Error No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		WIPESLOT(recv_buffer);
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
      case OKSETU2FPRIV:
	   if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && configmode==true) 
	   {
		if(!PDmode) {
		#ifdef US_VERSION
		SETU2FPRIV(recv_buffer);
		#endif
		}
	   }
	   else if (initialized==true && unlocked==true && configmode==false) { 
	   hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
      case OKWIPEU2FPRIV:
	   if(initialized==false && unlocked==true) 
	   {
		hidprint("Error No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		if(!PDmode) {
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
      break;
      case OKSETU2FCERT:
	   if(initialized==false && unlocked==true) 
	   {
		hidprint("Error No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		if(!PDmode) {
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
      break;
      case OKWIPEU2FCERT:
	   if(initialized==false && unlocked==true) 
	   {
		hidprint("Error No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		if(!PDmode) {
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
      break;
	  case OKSETPRIV:
           if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && configmode==true) 
	   {
                if(!PDmode) {
                #ifdef US_VERSION
                if (recv_buffer[0] != 0xBA) SETPRIV(recv_buffer);
                #endif
                }
	   }
	   else if (initialized==true && unlocked==true && configmode==false) { 
	   hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
      case OKWIPEPRIV:
           if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
                if(!PDmode) {
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
      break;
      case OKSIGN:
           if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		if(!PDmode) {
		#ifdef US_VERSION
		SoftTimer.add(&FadeinTask);
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
      break;
	  case OKDECRYPT:
           if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
		if(!PDmode) {
		#ifdef US_VERSION
		SoftTimer.add(&FadeinTask);
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
      break;
      case OKGETPUBKEY:
			if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
                if(!PDmode) {
                #ifdef US_VERSION
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
      break;
	  case OKRESTORE:
			if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true && configmode==true) 
	   {
                if(!PDmode) {
                #ifdef US_VERSION
                RESTORE(recv_buffer);
                #endif
                }
	   }
	   else if (initialized==true && unlocked==true && configmode==false) { 
	   hidprint("ERROR NOT IN CONFIG MODE, HOLD BUTTON 6 DOWN FOR 5 SEC");
	   }
	   else {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
      default: 
		if(!PDmode) {
		#ifdef US_VERSION
		SoftTimer.add(&FadeinTask);
	    	recvu2fmsg(recv_buffer);
		#endif
		}
      break;
    }
  } else {
	  if(!PDmode) {
	  #ifdef US_VERSION
	  u2fmsgtimeout(recv_buffer);
	  #endif
	  }
  } 
}

int getCounter() {
  unsigned int eeAddress = EEpos_U2Fcounter; //EEPROM address to start reading from
  unsigned int counter;
  EEPROM.get( eeAddress, counter );
  return counter;
}

void setCounter(int counter)
{
  unsigned int eeAddress = EEpos_U2Fcounter; //EEPROM address to start reading from
  EEPROM.put( eeAddress, counter );
}

void SETPIN (uint8_t *buffer)
{
#ifdef DEBUG
      Serial.println("OKSETPIN MESSAGE RECEIVED");
#endif
	  
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
			if (!initialized) {
			RNG2(ptr, 32); //Fill temp with random data
#ifdef DEBUG
			Serial.println("Generating NONCE");
#endif
			onlykey_flashset_noncehash (ptr); //Store in flash
			}
			else {
#ifdef DEBUG
			Serial.println("Getting NONCE");
#endif
			onlykey_flashget_noncehash (ptr, 32); 
			}
			
			sha256_update(&pinhash, temp, 32); //Add nonce to hash
			sha256_final(&pinhash, temp); //Create hash and store in temp
#ifdef DEBUG
			Serial.println("Hashing PIN and storing to Flash");
#endif
			onlykey_flashset_pinhash (ptr);

	  		initialized = true;
#ifdef DEBUG
	  		Serial.println();
			Serial.println("Successfully set PIN, remove and reinsert OnlyKey");
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
			if (!initialized) {
			RNG2(ptr, 32); //Fill temp with random data
#ifdef DEBUG
			Serial.println("Generating NONCE");
#endif
			onlykey_flashset_noncehash (ptr); //Store in flash
			}
			else {
#ifdef DEBUG
			Serial.println("Getting NONCE");
#endif
			onlykey_flashget_noncehash (ptr, 32); 
			}
			
			sha256_update(&pinhash, temp, 32); //Add nonce to hash
			sha256_final(&pinhash, temp); //Create hash and store in temp
#ifdef DEBUG
			Serial.println("Hashing PIN and storing to Flash");
#endif
			onlykey_flashset_plausdenyhash (ptr);

	  		initialized = true;
#ifdef DEBUG
	  		Serial.println();
			Serial.println("Successfully set PIN, remove and reinsert OnlyKey");
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
		hidprint("UNINITIALIZED");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
#ifdef DEBUG
		Serial.print("UNLOCKED");
#endif
		hidprint("UNLOCKEDv0.2-beta.3");
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
	  else
	  {
#ifdef DEBUG
	    Serial.print("FLASH ERROR");
#endif
		factorydefault();
	  }
      RawHID.send(resp_buffer, 0);
      blink(3);
      return;
}

void GETLABELS (uint8_t *buffer)
{
#ifdef DEBUG
      	  Serial.println();
	  Serial.println("OKGETLABELS MESSAGE RECEIVED");
#endif
	  uint8_t label[EElen_label+3];
	  uint8_t *ptr;
	  char labelchar[EElen_label+3];
	  int offset  = 0;
	  ptr=label+2;
	  if (PDmode) offset = 12;
	  
	  onlykey_flashget_label(ptr, (offset + 1));
	  label[0] = (uint8_t)0x01;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
	  hidprint(labelchar);
	  delay(20);
	  
	  onlykey_flashget_label(ptr, (offset   + 2));
	  label[0] = (uint8_t)0x02;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
      	  hidprint(labelchar);
      	  delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 3));
	  label[0] = (uint8_t)0x03;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 4));
	  label[0] = (uint8_t)0x04;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 5));
	  label[0] = (uint8_t)0x05;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 6));
	  label[0] = (uint8_t)0x06;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 7));
	  label[0] = (uint8_t)0x07;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 8));
	  label[0] = (uint8_t)0x08;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 9));
	  label[0] = (uint8_t)0x09;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 10));
	  label[0] = (uint8_t)0x10;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 11));
	  label[0] = (uint8_t)0x11;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_flashget_label(ptr, (offset  + 12));
	  label[0] = (uint8_t)0x12;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
      blink(3);
      return;
}



void SETSLOT (uint8_t *buffer)
{
      int slot = buffer[5];
      int value = buffer[6];
      int length;
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
	if (PDmode) slot = slot + 12;
            switch (value) {
            case 1:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Label Value to Flash...");
#endif
            onlykey_flashset_label(buffer + 7, slot);
			hidprint("Successfully set Label");
            return;
			case 15:
#ifdef DEBUG
            Serial.println("Writing URL Value to Flash...");
#endif
            if (!PDmode) {
#ifdef DEBUG
            Serial.println("Unencrypted");
            for (int z = 0; z < 32; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif 
#ifdef US_VERSION
      	    aes_gcm_encrypt((buffer + 7), (uint8_t*)('r'+ID[34]+slot), phash, length);
#endif 
#ifdef DEBUG
      	    Serial.println("Encrypted");
            for (int z = 0; z < 32; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif     
            }
            onlykey_flashset_url(buffer + 7, length, slot);
			hidprint("Successfully set URL");
            return;
            case 16:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Additional Character1 to EEPROM...");
#endif
            onlykey_eeset_addchar1(buffer + 7, slot);
#ifdef DEBUG
			Serial.print(buffer[7]);
#endif
	    hidprint("Successfully set Character1");
            return;
            case 17:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Delay1 to EEPROM...");
#endif
            buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay1(buffer + 7, slot);
	    hidprint("Successfully set Delay1");
            return;
            case 2:
            //Encrypt and Set value in EEPROM
#ifdef DEBUG
            Serial.println("Writing Username Value to EEPROM...");
#endif
            if (!PDmode) {
#ifdef DEBUG
            Serial.println("Unencrypted");
            for (int z = 0; z < 32; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif 
#ifdef US_VERSION
      	    aes_gcm_encrypt((buffer + 7), (uint8_t*)('u'+ID[34]+slot), phash, length);
#endif 
#ifdef DEBUG
      	    Serial.println("Encrypted");
            for (int z = 0; z < 32; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif     
            }
            onlykey_flashset_username(buffer + 7, length, slot);
	    hidprint("Successfully set Username");
            return;
            case 3:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Additional Character2 to EEPROM...");
#endif
            onlykey_eeset_addchar2(buffer + 7, slot);
#ifdef DEBUG
			Serial.print(buffer[7]);
#endif
	    hidprint("Successfully set Character2");
            return;
            case 4:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Delay2 to EEPROM...");
#endif
            buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay2(buffer + 7, slot);
	    hidprint("Successfully set Delay2");
            return;
            case 5:
            //Encrypt and Set value in EEPROM
#ifdef DEBUG
            Serial.println("Writing Password to EEPROM...");
#endif
            if (!PDmode) {
#ifdef DEBUG
            Serial.println("Unencrypted");
            for (int z = 0; z < 32; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif  
#ifdef US_VERSION
            aes_gcm_encrypt((buffer + 7), (uint8_t*)('p'+ID[34]+slot), phash, length);
#endif 
#ifdef DEBUG
      	    Serial.println("Encrypted");
            for (int z = 0; z < 32; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif 
            }
            onlykey_eeset_password(buffer + 7, length, slot);
	    hidprint("Successfully set Password");
            return;
            case 6:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Additional Character3 to EEPROM...");
#endif
            onlykey_eeset_addchar3(buffer + 7, slot);
#ifdef DEBUG
			Serial.print(buffer[7]);
#endif
	    hidprint("Successfully set Character3");
            return;
            case 7:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Delay3 to EEPROM...");
#endif
            buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay3(buffer + 7, slot);
	    hidprint("Successfully set Delay3");
            return;
            case 8:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing 2FA Type to EEPROM...");
#endif
            onlykey_eeset_2FAtype(buffer + 7, slot);
	    hidprint("Successfully set 2FA Type");
            return;
            case 9:
            //Encrypt and Set value in EEPROM
#ifdef DEBUG
            Serial.println("Writing TOTP Key to Flash...");
            Serial.println("Unencrypted");
            for (int z = 0; z < 64; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif 
#ifdef US_VERSION
            if (!PDmode) {
            aes_gcm_encrypt((buffer + 7), (uint8_t*)('t'+ID[34]+slot), phash, length);
            }
#endif
#ifdef DEBUG
	    Serial.println("Encrypted");
            for (int z = 0; z < 64; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif    
            onlykey_flashset_totpkey(buffer + 7, length, slot);
	    hidprint("Successfully set TOTP Key");
            return;
            case 10:
            if (!PDmode) {
            //Encrypt and Set value in EEPROM
#ifdef DEBUG
            Serial.println("Writing AES Key, Private ID, and Public ID to EEPROM...");
            Serial.println("Unencrypted Public ID");
            for (int z = 0; z < 6; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println("Unencrypted Private ID");
            for (int z = 0; z < 6; z++) {
      	    Serial.print(buffer[z + 7 + 6], HEX);
            }
            Serial.println("Unencrypted AES Key");
            for (int z = 0; z < 16; z++) {
      	    Serial.print(buffer[z + 7 + 12], HEX);
            }
            Serial.println();
#endif 
#ifdef US_VERSION
            aes_gcm_encrypt((buffer + 7), (uint8_t*)('y'+ID[34]), phash, length);
#endif 
#ifdef DEBUG
      	    Serial.println("Encrypted");
            for (int z = 0; z < 32; z++) {
      	    Serial.print(buffer[z + 7], HEX);
            }
            Serial.println();
#endif
            uint16_t counter  = 0x0000;
            uint8_t *ptr;
  	    ptr = (uint8_t *) &counter;
  	    yubikey_eeset_counter(ptr); 
            onlykey_eeset_public((buffer + 7), EElen_public);
            onlykey_eeset_private((buffer + 7 + EElen_public));
            onlykey_eeset_aeskey((buffer + 7 + EElen_public + EElen_private), EElen_aeskey);
            yubikeyinit();
	    hidprint("Successfully set AES Key, Private ID, and Public ID");
	    }
            return;
            case 11:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing idle timeout to EEPROM...");
#endif 
            onlykey_eeset_timeout(buffer + 7);
            TIMEOUT[0] = buffer[7];
	        hidprint("Successfully set idle timeout");
            return;
            case 12:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing wipemode to EEPROM...");
#endif 
            if(buffer[7] == 2) {
            	onlykey_eeset_wipemode(buffer + 7);
            	hidprint("Successfully set Wipe Mode to Full Wipe");
            } else {
	        hidprint("Successful");
			}
            return;
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
            return;
            case 14:
#ifdef DEBUG
            Serial.println(); //newline
            Serial.println("Writing keyboard layout to EEPROM...");
#endif 
            KeyboardLayout[0] = buffer[7];
			onlykey_eeset_keyboardlayout(buffer + 7);
			update_keyboard_layout();
	        hidprint("Successfully set keyboard layout");
            return;
            default: 
            return;
          }
      blink(3);
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

      for (int z = 7; z < 64; z++) {
        buffer[z] = 0x00;
#ifdef DEBUG
        Serial.print(buffer[z], HEX);
#endif 
        }
#ifdef DEBUG
     Serial.print("Overwriting slot with 0s");
#endif 
	 if (value==13) {
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping OnlyKey AES Key, Private ID, and Public ID...");
#endif 
            onlykey_eeset_aeskey((buffer + 7), 0);
            onlykey_eeset_private((buffer + 7 + EElen_aeskey));
            onlykey_eeset_public((buffer + 7 + EElen_aeskey + EElen_private), 0);
            hidprint("Successfully wiped AES Key, Private ID, and Public ID");
			return;
	 }
   	if (PDmode) slot = slot+12;
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
            onlykey_eeset_addchar1((buffer + 7), slot);
            hidprint("Successfully wiped Additional Character 1");
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
            Serial.print("Wiping Additional Character2 Value...");
#endif 
            onlykey_eeset_addchar2((buffer + 7), slot);
            hidprint("Successfully wiped Additional Character 2");
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
            Serial.print("Wiping Additional Character3 Value...");
#endif 
            onlykey_eeset_addchar3((buffer + 7), slot);
            hidprint("Successfully wiped Additional Character 3");
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

      blink(3);
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
    analogWrite(BLINKPIN, 255);
    delay(100);
    analogWrite(BLINKPIN, 0);
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

int RNG2(uint8_t *dest, unsigned size) {
	// Generate output whenever 32 bytes of entropy have been accumulated.
    // The first time through, we wait for 48 bytes for a full entropy pool.
    while (!RNG.available(length)) {
      //Serial.println("waiting for random number");
	  rngloop(); //Gather entropy
    }
    RNG.rand(dest, size);
    length = 32;
    //Serial.println("Random number =");
    //printHex(dest, size);
    //Serial.println("Size =");
    //Serial.println(size);
    return 1;
}

/*************************************/
//RNG Loop
/*************************************/
void rngloop() {
    // Stir the touchread and analog read values into the entropy pool.
    touchread1 = touchRead(TOUCHPIN1);
    //Serial.println(touchread1);
    RNG.stir((uint8_t *)touchread1, sizeof(touchread1), sizeof(touchread1));
    touchread2 = touchRead(TOUCHPIN2);
    //Serial.println(touchread2);
    RNG.stir((uint8_t *)touchread2, sizeof(touchread2), sizeof(touchread2));
    touchread3 = touchRead(TOUCHPIN3);
    //Serial.println(touchread3);
    RNG.stir((uint8_t *)touchread3, sizeof(touchread3), sizeof(touchread3));
    touchread4 = touchRead(TOUCHPIN4);
    //Serial.println(touchread4);
    RNG.stir((uint8_t *)touchread4, sizeof(touchread4), sizeof(touchread4));
    touchread5 = touchRead(TOUCHPIN5);
    //Serial.println(touchread5);
    RNG.stir((uint8_t *)touchread5, sizeof(touchread5), sizeof(touchread5));
    touchread6 = touchRead(TOUCHPIN6);
    //Serial.println(touchread6);
    RNG.stir((uint8_t *)touchread6, sizeof(touchread6), sizeof(touchread6));
    unsigned int analog1 = analogRead(ANALOGPIN1);
    //Serial.println(analog1);
    RNG.stir((uint8_t *)analog1, sizeof(analog1), sizeof(analog1)*4);
    unsigned int analog2 = analogRead(ANALOGPIN2);
    //Serial.println(analog2);
    RNG.stir((uint8_t *)analog2, sizeof(analog2), sizeof(analog2)*4);
    // Perform regular housekeeping on the random number generator.
    RNG.loop();
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
     resp_buffer[i] = (uint8_t)*chars;
     chars++;
	 i++;
  }
  RawHID.send(resp_buffer, 0);
  memset(resp_buffer, 0, sizeof(resp_buffer));
}

void factorydefault() {
	uint8_t mode;
	onlykey_eeget_wipemode(&mode);
	if (mode <= 1) {
	wipeflash(); //Wipe flash first need eeprom address for flash to wipe
	wipeEEPROM();
	} else {
	//FULLWIPE Mode
	flashEraseAll();
#ifdef DEBUG
	uintptr_t adr = 0x0;
        for (int i = 0; i < 7000; i++)
        {
        Serial.printf("0x%X", adr);
        Serial.printf(" 0x%X", *((unsigned int*)adr));
        Serial.println();
        adr=adr+4;
        }
#endif 
}
	initialized = false;
	unlocked = true;
#ifdef DEBUG
	Serial.println("factory reset has been completed");
#endif 
}

void wipeEEPROM() {
	//Erase all EEPROM values
	uint8_t value;
#ifdef DEBUG
	Serial.println("Current EEPROM Values"); //TODO remove debug
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
	value=0x00;
	for (int i=0; i<2048; i++) {
	EEPROM.write(i, value);
	}
#ifdef DEBUG
	Serial.println("EEPROM set to 0s");//TODO remove debug
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

void wipeflash() {
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	//Erase flash sectors used
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
	adr=adr+2048; //Next Sector
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
	adr=adr+4096; //Next Sector
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
	adr=adr+6144; //Next Sector
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
	adr=adr+8192; //Next Sector
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
	Serial.println("Flash Sectors erased");//TODO remove debug
#endif 
}


void aes_gcm_encrypt (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
	#ifdef US_VERSION
	GCM<AES256> gcm; 
	uint8_t iv2[12];
	//uint8_t tag[16];
	uint8_t *ptr;
	ptr = iv2;
	onlykey_flashget_noncehash(ptr, 12);
		for(int i =0; i<=12; i++) {
		  iv2[i]=iv2[i]^*iv1;
		}
	uint8_t aeskey[32];
	SHA256_CTX key2;
	sha256_init(&key2);
	sha256_update(&key2, key, 32); //add pinhash
	sha256_update(&key2, (uint8_t*)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&key2, aeskey); //Create hash and store in aeskey
	gcm.clear ();
	gcm.setKey(aeskey, 32);
	gcm.setIV(iv2, 12);
	gcm.encrypt(state, state, len);
	//gcm.computeTag(tag, sizeof(tag)); 
	#endif
}

void aes_gcm_decrypt (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
        #ifdef US_VERSION
	GCM<AES256> gcm; 
	uint8_t iv2[12];
	//uint8_t tag[16];
	uint8_t *ptr;
	ptr = iv2;
	onlykey_flashget_noncehash(ptr, 12);
		for(int i =0; i<=12; i++) {
		  iv2[i]=iv2[i]^*iv1;
		}
	uint8_t aeskey[32];
	SHA256_CTX key2;
	sha256_init(&key2);
	sha256_update(&key2, key, 32); //add pinhash
	sha256_update(&key2, (uint8_t*)ID, 32); //add first 32 bytes of Freescale CHIP ID
	sha256_final(&key2, aeskey); //Create hash and store in aeskey
	gcm.clear ();
	gcm.setKey(aeskey, 32);
	gcm.setIV(iv2, 12);
	gcm.decrypt(state, state, len);
	//if (!gcm.checkTag(tag, sizeof(tag))) {
	//	return 1;
	//}
	#endif

}

void aes_gcm_encrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
	#ifdef US_VERSION
	GCM<AES256> gcm; 
	uint8_t tag[16];
	gcm.clear ();
	gcm.setKey(key, sizeof(key));
	gcm.setIV(iv1, 12);
	gcm.encrypt(state, state, len);
	gcm.computeTag(tag, sizeof(tag)); 
	#endif
}

void aes_gcm_decrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
        #ifdef US_VERSION
	GCM<AES256> gcm; 
	//uint8_t tag[16];
	gcm.clear ();
	gcm.setKey(key, sizeof(key));
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
/*********************************/

int onlykey_flashget_noncehash (uint8_t *ptr, int size) {
	
	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	if (flashoffset[0]==255 || flashoffset[0]==0) {
#ifdef DEBUG
		Serial.printf("There is no Nonce hash set");
#endif
		return 0;
	} else {
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	#ifdef DEBUG
	Serial.printf("Reading nonce from Sector 0x%X ",adr);
	#endif
    onlykey_flashget_common(ptr, (unsigned long*)adr, size);
	}
	return 1;
}

void onlykey_flashset_noncehash (uint8_t *ptr) {
	
	uint8_t flashoffset[1];
	uintptr_t adr;
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	if (flashoffset[0] == 0)
	{
	#ifdef DEBUG 
	Serial.printf("There is no Nonce hash set");
	#endif
	adr = flashFirstEmptySector();
	flashoffset[0] = (uint8_t)((adr / (unsigned long)2048)& 0XFF); //number of sectors 
	#ifdef DEBUG
	Serial.printf("Setting First flash Sector to 0x%X ",flashoffset[0]);
	#endif
	onlykey_eeset_flashpos((uint8_t*)flashoffset);
	} else {
	adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	}	
	#ifdef DEBUG 
	Serial.printf("First Empty Flash Sector 0x%X ",adr);
	#endif
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;
	//Get current flash contents
	onlykey_flashget_common(tptr, (unsigned long*)adr, 254);
	//Add new flash contents
	for( int z = 0; z <= 31; z++){
		temp[z] = ((uint8_t)*(ptr+z));
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
	  onlykey_flashset_common(tptr, (unsigned long*)adr, 254);
#ifdef DEBUG 
	  Serial.print("Nonce hash address =");
	  Serial.println(adr, HEX);
	  Serial.print("Nonce hash value =");
#endif 
	  onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_noncehash); 

}


int onlykey_flashget_pinhash (uint8_t *ptr, int size) {
	
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
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

void onlykey_flashset_pinhash (uint8_t *ptr) {
	
	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;
	//Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 254);
	//Add new flash contents to buffer
	for( int z = 0; z <= 31; z++){
		temp[z + EElen_noncehash] = ((uint8_t)*(ptr+z));
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
      onlykey_flashset_common(tptr, (unsigned long*)adr, 254);
#ifdef DEBUG 
      Serial.print("Pin hash address =");
      Serial.println(adr, HEX);
      Serial.print("Pin hash value =");
#endif 
      onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_pinhash);

}
/*********************************/
/*********************************/

int onlykey_flashget_selfdestructhash (uint8_t *ptr) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
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
		Serial.printf("Self-Destruct PIN hash has been set");
		#endif
		return 1;
    }

}

void onlykey_flashset_selfdestructhash (uint8_t *ptr) {

	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;
	//Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 254);
	//Add new flash contents to buffer
	for( int z = 0; z <= 31; z++){
		temp[z + EElen_noncehash + EElen_pinhash] = ((uint8_t)*(ptr+z));
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
      onlykey_flashset_common(tptr, (unsigned long*)adr, 254);
#ifdef DEBUG 
      Serial.print("Self-Destruct PIN hash address =");
      Serial.println(adr, HEX);
      Serial.print("Self-Destruct PIN hash value =");
#endif 
      onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_selfdestructhash);  
}

/*********************************/
/*********************************/

int onlykey_flashget_plausdenyhash (uint8_t *ptr) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash;
    onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_plausdenyhash);
	
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
void onlykey_flashset_plausdenyhash (uint8_t *ptr) {

	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	uint8_t temp[255];
	uint8_t *tptr;
	tptr=temp;
	//Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 254);
	//Add new flash contents to buffer
	for( int z = 0; z <= 31; z++){
		temp[z + EElen_noncehash + EElen_pinhash + EElen_selfdestructhash] = ((uint8_t)*(ptr+z));
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
      onlykey_flashset_common(tptr, (unsigned long*)adr, 254);
#ifdef DEBUG 
      Serial.print("PIN hash address =");
      Serial.println(adr, HEX);
      Serial.print("PIN hash value =");
#endif 
      onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_plausdenyhash);

}  



int onlykey_flashget_url (uint8_t *ptr, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
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
            break;
		case 2:
			onlykey_eeget_urllen2(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 3:
			onlykey_eeget_urllen3(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 4:
			onlykey_eeget_urllen4(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 5:
			onlykey_eeget_urllen5(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 6:
			onlykey_eeget_urllen6(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 7:
			onlykey_eeget_urllen7(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 8:
			onlykey_eeget_urllen8(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 9:
			onlykey_eeget_urllen9(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 10:
			onlykey_eeget_urllen10(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 11:
			onlykey_eeget_urllen11(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 12:
			onlykey_eeget_urllen12(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 13:
			onlykey_eeget_urllen13(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 14:
			onlykey_eeget_urllen14(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 15:
			onlykey_eeget_urllen15(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 16:
			onlykey_eeget_urllen16(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 17:
			onlykey_eeget_urllen17(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 18:
			onlykey_eeget_urllen18(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 19:
			onlykey_eeget_urllen19(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 20:
			onlykey_eeget_urllen20(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 21:
			onlykey_eeget_urllen21(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 22:
			onlykey_eeget_urllen22(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 23:
			onlykey_eeget_urllen23(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;
		case 24:
			onlykey_eeget_urllen24(&length);
			size = (int) length;
			if (size > EElen_url) size = EElen_url;
			adr=adr+((EElen_url*slot)-EElen_url);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_url);
			return size;
            break;	
	}

return 0;
}

void onlykey_flashset_url (uint8_t *ptr, int size, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 2048; //2nd free sector
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z <= EElen_url; z++){
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
            	break;
		case 2:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen2(&length);
            	break;
		case 3:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen3(&length);
            break;
		case 4:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen4(&length);
            break;
		case 5:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen5(&length);
            break;
		case 6:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen6(&length);
            break;
		case 7:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen7(&length);
            break;
		case 8:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen8(&length);
            break;
		case 9:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen9(&length);
            break;
		case 10:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen10(&length);
            break;
		case 11:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen11(&length);
            break;
		case 12:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen12(&length);
            break;
            	case 13:
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen13(&length);
            	break;
		case 14:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen14(&length);
            	break;
		case 15:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen15(&length);
            break;
		case 16:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen16(&length);
            break;
		case 17:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen17(&length);
            break;
		case 18:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen18(&length);
            break;
		case 19:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen19(&length);
            break;
		case 20:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen20(&length);
            break;
		case 21:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen21(&length);
            break;
		case 22:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen22(&length);
            break;
		case 23:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen23(&length);
            break;
		case 24:
		if (size > EElen_url) size = EElen_url;
			if (size > EElen_url) size = EElen_url;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_urllen24(&length);
            break;
	}
return;
}

/*********************************/


int onlykey_flashget_username (uint8_t *ptr, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
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
            break;
		case 2:
			onlykey_eeget_usernamelen2(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 3:
			onlykey_eeget_usernamelen3(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 4:
			onlykey_eeget_usernamelen4(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 5:
			onlykey_eeget_usernamelen5(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 6:
			onlykey_eeget_usernamelen6(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 7:
			onlykey_eeget_usernamelen7(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 8:
			onlykey_eeget_usernamelen8(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 9:
			onlykey_eeget_usernamelen9(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 10:
			onlykey_eeget_usernamelen10(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 11:
			onlykey_eeget_usernamelen11(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 12:
			onlykey_eeget_usernamelen12(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 13:
			onlykey_eeget_usernamelen13(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 14:
			onlykey_eeget_usernamelen14(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 15:
			onlykey_eeget_usernamelen15(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 16:
			onlykey_eeget_usernamelen16(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 17:
			onlykey_eeget_usernamelen17(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 18:
			onlykey_eeget_usernamelen18(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 19:
			onlykey_eeget_usernamelen19(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 20:
			onlykey_eeget_usernamelen20(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 21:
			onlykey_eeget_usernamelen21(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 22:
			onlykey_eeget_usernamelen22(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 23:
			onlykey_eeget_usernamelen23(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;
		case 24:
			onlykey_eeget_usernamelen24(&length);
			size = (int) length;
			if (size > EElen_username) size = EElen_username;
			adr=adr+((EElen_username*slot)-EElen_username);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_username);
			return size;
            break;	
	}

return 0;
}

void onlykey_flashset_username (uint8_t *ptr, int size, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 4096; //3rd free sector
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z <= EElen_username; z++){
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
            	break;
		case 2:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen2(&length);
            	break;
		case 3:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen3(&length);
            break;
		case 4:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen4(&length);
            break;
		case 5:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen5(&length);
            break;
		case 6:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen6(&length);
            break;
		case 7:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen7(&length);
            break;
		case 8:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen8(&length);
            break;
		case 9:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen9(&length);
            break;
		case 10:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen10(&length);
            break;
		case 11:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen11(&length);
            break;
		case 12:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen12(&length);
            break;
            	case 13:
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen13(&length);
            	break;
		case 14:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen14(&length);
            	break;
		case 15:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen15(&length);
            break;
		case 16:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen16(&length);
            break;
		case 17:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen17(&length);
            break;
		case 18:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen18(&length);
            break;
		case 19:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen19(&length);
            break;
		case 20:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen20(&length);
            break;
		case 21:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen21(&length);
            break;
		case 22:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen22(&length);
            break;
		case 23:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen23(&length);
            break;
		case 24:
		if (size > EElen_username) size = EElen_username;
			if (size > EElen_username) size = EElen_username;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_usernamelen24(&length);
            break;
	}
return;
}

/*********************************/


void onlykey_flashget_label (uint8_t *ptr, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 6144; //4th free sector
	switch (slot) {
        case 1:
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 2:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 3:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 4:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 5:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 6:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 7:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 8:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 9:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 10:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 11:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 12:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 13:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 14:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 15:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 16:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 17:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 18:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 19:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 20:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 21:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 22:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 23:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;
		case 24:
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
            break;	
	}
}

void onlykey_flashset_label (uint8_t *ptr, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 6144; //4th free sector
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z <= EElen_label; z++){
    temp[z+((EElen_label*slot)-EElen_label)] = ((uint8_t)*(ptr+z));
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
    onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
return;
}

/*********************************/

int onlykey_flashget_totpkey (uint8_t *ptr, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 8192; //5th free sector
	switch (slot) {
		uint8_t length;
		int size;
        	case 1:
			onlykey_eeget_totpkeylen1(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 2:
			onlykey_eeget_totpkeylen2(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 3:
			onlykey_eeget_totpkeylen3(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 4:
			onlykey_eeget_totpkeylen4(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 5:
			onlykey_eeget_totpkeylen5(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 6:
			onlykey_eeget_totpkeylen6(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 7:
			onlykey_eeget_totpkeylen7(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 8:
			onlykey_eeget_totpkeylen8(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 9:
			onlykey_eeget_totpkeylen9(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 10:
			onlykey_eeget_totpkeylen10(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 11:
			onlykey_eeget_totpkeylen11(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 12:
			onlykey_eeget_totpkeylen12(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 13:
			onlykey_eeget_totpkeylen13(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 14:
			onlykey_eeget_totpkeylen14(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 15:
			onlykey_eeget_totpkeylen15(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 16:
			onlykey_eeget_totpkeylen16(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 17:
			onlykey_eeget_totpkeylen17(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 18:
			onlykey_eeget_totpkeylen18(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 19:
			onlykey_eeget_totpkeylen19(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 20:
			onlykey_eeget_totpkeylen20(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 21:
			onlykey_eeget_totpkeylen21(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 22:
			onlykey_eeget_totpkeylen22(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 23:
			onlykey_eeget_totpkeylen23(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;
		case 24:
			onlykey_eeget_totpkeylen24(&length);
			size = (int) length;
			if (size > EElen_label) size = EElen_label;
			adr=adr+((EElen_label*slot)-EElen_label);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_label);
			return size;
            break;	
	}

return 0;
}

void onlykey_flashset_totpkey (uint8_t *ptr, int size, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 8192;
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z <= EElen_totpkey; z++){
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
            	break;
		case 2:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen2(&length);
            	break;
		case 3:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen3(&length);
            break;
		case 4:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen4(&length);
            break;
		case 5:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen5(&length);
            break;
		case 6:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen6(&length);
            break;
		case 7:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen7(&length);
            break;
		case 8:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen8(&length);
            break;
		case 9:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen9(&length);
            break;
		case 10:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen10(&length);
            break;
		case 11:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen11(&length);
            break;
		case 12:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen12(&length);
            break;
            	case 13:
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen13(&length);
            	break;
		case 14:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen14(&length);
            	break;
		case 15:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen15(&length);
            break;
		case 16:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen16(&length);
            break;
		case 17:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen17(&length);
            break;
		case 18:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen18(&length);
            break;
		case 19:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen19(&length);
            break;
		case 20:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen20(&length);
            break;
		case 21:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen21(&length);
            break;
		case 22:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen22(&length);
            break;
		case 23:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen23(&length);
            break;
		case 24:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 2048);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen24(&length);
            break;
	}
return;
}

/*********************************/
void onlykey_flashget_U2F ()
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("Flashget U2F");
#endif 
	uint8_t length[2];
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
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
    adr=adr+64; //6th flash sector
    onlykey_eeget_U2Fcertlen(length);
    int length2 = length[0] << 8 | length[1];
#ifdef DEBUG 
    Serial.print("attestation der length=");
    Serial.println(length2);
#endif 
    onlykey_flashget_common((uint8_t*)attestation_der, (unsigned long*)adr, length2); 
#ifdef DEBUG 
    Serial.print("attestation der =");
    for (unsigned int i = 0; i< sizeof(attestation_der); i++) {
    Serial.print(attestation_der[i],HEX);
    }
#endif 
#endif
    return;

}

/*********************************/
void SETU2FPRIV (uint8_t *buffer)
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("OKSETU2FPRIV MESSAGE RECEIVED");
#endif 
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 10240; //6th flash sector
	uint8_t *ptr;
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
	ptr=buffer+5;
    onlykey_flashset_common(ptr, (unsigned long*)adr, 32);
#ifdef DEBUG
    Serial.print("U2F Private address =");
    Serial.println(adr, HEX);
#endif
    onlykey_flashget_common(ptr, (unsigned long*)adr, 32); 
#ifdef DEBUG
    Serial.print("U2F Private value =");
#endif
    for (int i=0; i<32; i++) {
    attestation_priv[i] = *(buffer + 5 + i);
#ifdef DEBUG
    Serial.print(attestation_priv[i],HEX);
#endif
    }
    hidprint("Successfully set U2F Private");

  blink(3);
#endif
  return;

}
    

void WIPEU2FPRIV (uint8_t *buffer)
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKWIPEU2FPRIV MESSAGE RECEIVED");
#endif
	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
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
    blink(3);
#endif
    return;

}

void SETU2FCERT (uint8_t *buffer)
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("OKSETU2FCERT MESSAGE RECEIVED");
#endif 
	uint8_t length[2];
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 10304; //6th flash sector
	uint8_t *ptr;
	if (buffer[5]==0xFF) //Not last packet
	{
		if (large_data_len <= 710) {
			memcpy(attestation_der+large_data_len, buffer+6, 58);
			large_data_len = large_data_len + 58;
		} else {
			hidprint("Error U2F Cert larger than 768 bytes");
		}
		return;
	} else { //Last packet
		if (large_data_len <= 710 && buffer[5] <= 58) {
			memcpy(attestation_der+large_data_len, buffer+6, buffer[5]);
			large_data_len = large_data_len + buffer[5];
		} else if (large_data_len <= 768 && buffer[0] == 0xBA) { //Import from backup
			memcpy(attestation_der, buffer+6, large_data_len);
		} else{
			hidprint("Error U2F Cert larger than 768 bytes");
		}
		length[0] = large_data_len >> 8  & 0xFF;
		length[1] = large_data_len       & 0xFF;
		//Set U2F Certificate size
		onlykey_eeset_U2Fcertlen(length); 
#ifdef DEBUG 

		Serial.print("Length of U2F certificate = ");
        Serial.println(large_data_len);
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
		ptr=(uint8_t*)attestation_der;
    	onlykey_flashset_common(ptr, (unsigned long*)adr, large_data_len);
    	       

	}
#ifdef DEBUG 
    Serial.print("U2F Cert value =");
    for (int i = 0; i<large_data_len; i++) {
    Serial.print(attestation_der[i],HEX);
    }
#endif
	large_data_len = 0;
	hidprint("Successfully set U2F Certificate");
      blink(3);
#endif
      return;

}

void WIPEU2FCERT (uint8_t *buffer)
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("OKWIPEU2FCERT MESSAGE RECEIVED");
#endif
	uint8_t length[2] = {0x00,0x00};
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 10304; //6th flash sector
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
    blink(3);
#endif
    return;

}

void SETPRIV (uint8_t *buffer)
{
	if (buffer[6] > 80) {//Type is Backup key
	buffer[6] = buffer[6] - 80;
	onlykey_eeset_backupkey(buffer+5); //Set this key slot as the backup key
	} 
	
	if (buffer[5] < 101) { 
	SETRSAPRIV(buffer);
	} else {
	SETECCPRIV(buffer);
	}
}

void WIPEPRIV (uint8_t *buffer) {
	if (buffer[5] < 101) {
	WIPERSAPRIV(buffer);
	} else {
		for(int i=6; i<=32; i++) {
		buffer[i]=0x00;
		}
	SETECCPRIV(buffer);
	}
}

int onlykey_flashget_ECC (int slot)
{

if (PDmode) return 0;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("Flashget ECC");
#endif 
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 12288; //7th flash sector
	uint8_t type;
	onlykey_eeget_ecckey((uint8_t*)type, slot); //Key Type (1-3) and slot (101-132)
	if (type==0x00) {	
	Serial.printf("There is no ECC Private Key set in this slot");
	hidprint("There is no ECC Private Key set in this slot");
	return 0;
	}
	adr = adr + ((slot-100)*32);
    onlykey_flashget_common((uint8_t*)ecc_private_key, (unsigned long*)adr, 32); 
	#ifdef DEBUG 
	Serial.printf("Read ECC Private Key from Sector 0x%X ",adr);
	#endif
	const struct uECC_Curve_t * curves[2];
    int num_curves = 0;
    curves[num_curves++] = uECC_secp256r1();
    curves[num_curves++] = uECC_secp256k1();
	if (type==0x10) Ed25519::derivePublicKey(ecc_public_key, ecc_private_key);
	else if (type==0x11) {
		uECC_compute_public_key(ecc_private_key, ecc_public_key, curves[1]);
	}
	else if (type==0x12) {
		uECC_compute_public_key(ecc_private_key, ecc_public_key, curves[2]);
	}
	return type;
#endif
}

void SETECCPRIV (uint8_t *buffer)
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("OKSETECCPRIV MESSAGE RECEIVED");
#endif 
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 12288; //7th free flash sector
	uint8_t *ptr;
	//Write ID to EEPROM
	ptr = buffer+5; 
	onlykey_eeset_ecckey((ptr+1), (int)(ptr)); //Key Type (1-3) and slot (101-132)
	//Write buffer to flash
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
	ptr = buffer+7;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z <= 32; z++){
    temp[z+((32*(buffer[5]-100))-32)] = ((uint8_t)*(ptr+z));
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
    onlykey_flashset_common(ptr, (unsigned long*)adr, 2048);

#ifdef DEBUG 
    Serial.print("ECC Key value =");
    for (int i = 0; i<32; i++) {
    Serial.print(buffer[i+7],HEX);
    }
#endif
	hidprint("Successfully set ECC Key");
      blink(3);
#endif
      return;

}

int onlykey_flashget_RSA (int slot)
{

if (PDmode) return 0;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.print("Flashget RSA key from slot # ");
	Serial.println(slot);
#endif 
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 14336; //8th free flash sector
	uint8_t type;
	onlykey_eeget_rsakey((uint8_t*)type, slot); //Key Type (1-2) and slot (1-4)
	if (type==0x00) {	
	Serial.printf("There is no RSA Private Key set in this slot");
	hidprint("There is no RSA Private Key set in this slot");
	return 0;
	}
	adr = adr + (slot*256);
    onlykey_flashget_common((uint8_t*)rsa_private_key, (unsigned long*)adr, (type*128)); 
	#ifdef DEBUG 
	Serial.printf("Read RSA Private Key from Sector 0x%X ",adr);
	#endif
	return type;
#endif
}


void SETRSAPRIV (uint8_t *buffer)
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("OKSETRSAPRIV MESSAGE RECEIVED");
#endif 
	extern uint8_t rsa_private_key[256];
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 14336; //8th free flash sector
	uint8_t *ptr;

	if (buffer[0] == 0xFF && buffer[6]==0x01) //Expect 128 Bytes, if buffer[0] != FF we know this is import from backup
	{
		if (large_data_len <= 114) {
		memcpy(rsa_private_key+large_data_len, buffer+7, 57);
		large_data_len = large_data_len + 57;
		return;
		}
	} else if (buffer[0] == 0xFF && buffer[6]==0x02) { //Expect 256 Bytes
		if (large_data_len <= 228) {
		memcpy(rsa_private_key+large_data_len, buffer+7, 57);
		large_data_len = large_data_len + 57;
		return;
		}
	}
	//Write ID to EEPROM
	ptr = buffer+5; 
	onlykey_eeset_rsakey((ptr+1), (int)(ptr)); //Key Type (1-2) and slot (1-4)
	//Write buffer to flash
#ifdef DEBUG 
		Serial.print("Received RSA Key of size ");
        Serial.println((buffer[6]*128));
#endif 
    uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
	ptr=rsa_private_key;
	if (buffer[0] == 0xBA) ptr=buffer+7;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Add new flash contents to buffer
    for( int z = 0; z <= 256; z++){
    temp[z+((256*buffer[5])-256)] = ((uint8_t)*(ptr+z));
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
    onlykey_flashset_common(ptr, (unsigned long*)adr, 2048);

#ifdef DEBUG 
    Serial.print("RSA Key value =");
    for (int i = 0; i<(buffer[6]*128); i++) {
    Serial.print(rsa_private_key[i],HEX);
    }
#endif
	large_data_len = 0;
	hidprint("Successfully set RSA Key");
      blink(3);
#endif
      return;

}


void WIPERSAPRIV (uint8_t *buffer)
{
if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKWIPERSAPRIV MESSAGE RECEIVED");
#endif
	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 14336; //8th free flash sector
	uint8_t *ptr;
	//Wipe ID from EEPROM
	ptr = buffer+5; 
	onlykey_eeset_rsakey(0, (int)(ptr)); //Key ID (1-2) and slot (1-4)
	//Wipe flash
	uint8_t temp[2048];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 2048);
    //Wipe content from buffer
    for( int z = 0; z <= 256; z++){
    temp[z+((256*buffer[5])-256)] = 0x00;
    }
	//Write buffer to flash
    onlykey_flashset_common(ptr, (unsigned long*)adr, 2048);
	hidprint("Successfully wiped RSA Private Key");
    blink(3);
#endif
    return;

}

/*************************************/
//Initialize Yubico OTP
/*************************************/
void yubikeyinit() {
#ifdef US_VERSION
  uint32_t seed;
  uint8_t *ptr = (uint8_t *)&seed;
  RNG2(ptr, 32); //Seed the onlyKey with random data

  uint8_t temp[32];
  uint8_t yaeskey[16];
  uint8_t privID[6];
  uint8_t pubID[16];
  uint16_t counter;
  char public_id[32+1];
  char private_id[12+1];

#ifdef DEBUG 
  Serial.println("Initializing onlyKey ...");
#endif
  memset(temp, 0, 32); //Clear temp buffer
  
  ptr = temp;
  onlykey_eeget_public(ptr);
  
  ptr = (temp+EElen_public);
  onlykey_eeget_private(ptr);
  
  ptr = (temp+EElen_public+EElen_private);
  onlykey_eeget_aeskey(ptr);
  
  aes_gcm_decrypt(temp, (uint8_t*)('y'+ID[34]), phash, (EElen_aeskey+EElen_private+EElen_public));
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
  
  ptr = (uint8_t*) &counter;
  yubikey_eeget_counter(ptr);

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
 
  ptr = (uint8_t*) &(ctx.counter);
  yubikey_eeset_counter(ptr);
#endif
}
/*************************************/
//Generate Yubico OTP
/*************************************/
void yubikeysim(char *ptr) {
	#ifdef US_VERSION
	yubikey_simulate1(ptr, &ctx);
        yubikey_incr_usage(&ctx);
        #endif
}
/*************************************/
//Increment Yubico timestamp
/*************************************/
void yubikey_incr_time() {
	#ifdef US_VERSION
	yubikey_incr_timestamp(&ctx);
	#endif
}

void increment(Task* me) {
  analogWrite(BLINKPIN, fade);
  fade += 8;
  if(fade == 0) {
    // -- Byte value overflows: 240 + 16 = 0
    SoftTimer.remove(&FadeinTask);
    SoftTimer.add(&FadeoutTask);
  }
}

void decrement(Task* me) {
  fade -= 8;
  analogWrite(BLINKPIN, fade);
  if(fade == 0) {
    // -- Floor reached.
    SoftTimer.remove(&FadeoutTask);
    SoftTimer.add(&FadeinTask);
  }
}

void fadeoff() {
  SoftTimer.remove(&FadeinTask);
  SoftTimer.remove(&FadeoutTask);
  fade=0;
}
		  
void backupslots() {
  unsigned char *pos;
  uint8_t temp[64];
  uint8_t large_temp[7028];
  int urllength;
  int usernamelength;
  int passwordlength;
  int otplength;
  uint8_t *ptr;
  unsigned char beginsbackup[] = "-----BEGIN ONLYKEY SLOT BACKUP-----";
  unsigned char endsbackup[] = "-----END ONLYKEY SLOT BACKUP-----";
  large_data_offset = 0;
  memset(large_temp, 0, sizeof(large_temp)); //Wipe all data from largebuffer
  int slot;
  
  for (int z = 0; z <= 35; z++) {
        Keyboard.write(beginsbackup[z]);
		delay(((TYPESPEED[0]*TYPESPEED[0])*10));
	} 
  
  for (slot=1; slot<=24; slot++)
  {
  #ifdef DEBUG
    Serial.print("Backing up Slot Number ");
    Serial.println(slot);
  #endif
    memset(temp, 0, 64); //Wipe all data from temp buffer
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
        for (int z = 0; z < urllength; z++) {
        Serial.print(temp[z], HEX);
        }
        Serial.println();
    #endif
    #ifdef US_VERSION
        aes_gcm_decrypt(temp, (uint8_t*)('r'+ID[34]+slot), phash, urllength);
    #endif
    #ifdef DEBUG
        Serial.println("Unencrypted");
        for (int z = 0; z < urllength; z++) {
        Serial.print(temp[z], HEX);
        }
        Serial.println();
        #endif
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 15; //15 - URL
		memcpy(large_temp+large_data_offset+3, temp, urllength);
        large_data_offset=large_data_offset+urllength+3;
      }
      onlykey_eeget_addchar1(ptr, slot);
      if(temp[0] > 0)
      {
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 16; //16 - Add Char 1
		large_temp[large_data_offset+3] = temp[0]; 
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
        if (!PDmode) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < usernamelength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, (uint8_t*)('u'+ID[34]+slot), phash, usernamelength);
        #endif
        }
		#ifdef DEBUG
        Serial.println("Unencrypted");
        for (int z = 0; z < usernamelength; z++) {
        Serial.print(temp[z], HEX);
        }
        Serial.println();
        #endif
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 2; //2 - Username
		memcpy(large_temp+large_data_offset+3, temp, usernamelength);
        large_data_offset=large_data_offset+usernamelength+3;
      }
      onlykey_eeget_addchar2(ptr, slot);
      if(temp[0] > 0)
      {
        large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 3; //3 - Add Char 2
		large_temp[large_data_offset+3] = temp[0]; 
        large_data_offset=large_data_offset+4;
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
        if (!PDmode) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < passwordlength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
          #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, (uint8_t*)('p'+ID[34]+slot), phash, passwordlength);
        #endif
        }
		#ifdef DEBUG
        Serial.println("Unencrypted");
        for (int z = 0; z < passwordlength; z++) {
        Serial.print(temp[z], HEX);
        }
        Serial.println();
        #endif
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 5; //5 - Password
		memcpy(large_temp+large_data_offset+3, temp, passwordlength);
        large_data_offset=large_data_offset+passwordlength+3;
      }  
      onlykey_eeget_addchar3(ptr, slot);
      if(temp[0] > 0)
      {
        large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = 6; //6 - Add Char 3
		large_temp[large_data_offset+3] = temp[0]; 
        large_data_offset=large_data_offset+4;
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
        for (int z = 0; z < otplength; z++) {
        Serial.print(temp[z], HEX);
        }
      Serial.println();
      Serial.print("TOTP Key Length = ");
      Serial.println(otplength);
      #endif
      #ifdef US_VERSION
      if (!PDmode) aes_gcm_decrypt(temp, (uint8_t*)('t'+ID[34]+slot), phash, otplength);
      #endif
      #ifdef DEBUG
      Serial.println("Unencrypted");
        for (int z = 0; z < otplength; z++) {
        Serial.print(temp[z], HEX);
        }
        Serial.println();
	  #endif
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = slot;
	  large_temp[large_data_offset+2] = 9; //9 - TOTP Key
	  memcpy(large_temp+large_data_offset+3, temp, otplength);
      large_data_offset=large_data_offset+otplength+3;
	  }	  
}
      onlykey_eeget_public(ptr);
  
      ptr = (temp+EElen_public);
      onlykey_eeget_private(ptr);
  
      ptr = (temp+EElen_public+EElen_private);
      onlykey_eeget_aeskey(ptr);
  
      aes_gcm_decrypt(temp, (uint8_t*)('y'+ID[34]), phash, (EElen_aeskey+EElen_private+EElen_public));

	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = slot;
	  large_temp[large_data_offset+2] = 10; //10 - Yubikey
	  memcpy(large_temp+large_data_offset+3, temp, (EElen_aeskey+EElen_private+EElen_public));
      large_data_offset=large_data_offset+(EElen_aeskey+EElen_private+EElen_public)+3;
	  
      onlykey_eeget_timeout(ptr);
	  if (*ptr != 0) {
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = slot;
	  large_temp[large_data_offset+2] = 11; //11 - Idle Timeout
	  large_temp[large_data_offset+3] = temp[0]; 
      large_data_offset=large_data_offset+4;
	  }
	  onlykey_eeget_typespeed(ptr);
	  if (*ptr != 0) {
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = slot;
	  large_temp[large_data_offset+2] = 13; //13 - Keyboard type speed
	  large_temp[large_data_offset+3] = temp[0]; 
      large_data_offset=large_data_offset+4;
	  }
	  onlykey_eeget_keyboardlayout(ptr);
	  if (*ptr != 0) {
	  large_temp[large_data_offset] = 0xFF; //delimiter
	  large_temp[large_data_offset+1] = slot;
	  large_temp[large_data_offset+2] = 14; //14- Keyboard layout 
	  large_temp[large_data_offset+3] = temp[0]; 
      large_data_offset=large_data_offset+4;
	  }
//Encrypt
    
    #ifdef DEBUG
	Serial.println();
        Serial.println("Unencoded");
        for (int z = 0; z <= large_data_offset; z++) {
        Serial.print(large_temp[z], HEX);
        }
        Serial.println();
    #endif
	int i = 0;
	while(i <= large_data_offset && i < sizeof(large_temp)) {
		Keyboard.println();
		delay(((TYPESPEED[0]*TYPESPEED[0])*10));
		if ((large_data_offset - i) < 42) {
			int enclen = base64_encode(large_temp+i, temp, (large_data_offset - i), '/n'); //Equals 56 in base32
			for (int z = 0; z <= enclen; z++) {
			Keyboard.write(temp[z]);
			delay(((TYPESPEED[0]*TYPESPEED[0])*10));
			}  
		}	
		else {
			base64_encode(large_temp+i, temp, 42, '/n'); //Equals 56 in base32
			for (int z = 0; z <= 56; z++) {
			Keyboard.write(temp[z]);
			delay(((TYPESPEED[0]*TYPESPEED[0])*10));
			}  
		}
		i = i+42;
		memset(temp, 0, sizeof(temp));
	}
	Keyboard.println();
	delay(((TYPESPEED[0]*TYPESPEED[0])*10));
	#ifdef DEBUG
        Serial.println("Encoded");
        for (int z = 0; z <= large_data_offset; z++) {
        Serial.print(large_temp[z], HEX);
        }
        Serial.println();
    #endif
	
	//End backup footer
    for (int z = 0; z <= 33; z++) {
        Keyboard.write(endsbackup[z]);
		delay(((TYPESPEED[0]*TYPESPEED[0])*10));
	} 
	Keyboard.println();
large_data_offset = 0;
memset(large_temp, 0 , sizeof(large_temp));
}

void backupkeys() {
  uint8_t length[2];
  uint8_t temp[256];
  uint8_t large_temp[2970];
  int type;
  uint8_t *ptr;
  unsigned char beginkbackup[] = "-----BEGIN ONLYKEY KEY BACKUP-----";
  unsigned char endkbackup[] = "-----END ONLYKEY KEY BACKUP-----";
  large_data_offset = 0;
  memset(large_temp, 0, sizeof(large_temp)); //Wipe all data from largebuffer
  
  //Begin backup header 
	for (int z = 0; z <= sizeof(beginkbackup); z++) {
		Keyboard.write(beginkbackup[z]);
		delay(((TYPESPEED[0]*TYPESPEED[0])*10));
	} 
	Keyboard.println();
	
  //Copy RSA keys to buffer  
  for (int slot=1; slot<=4; slot++)
  {
	  
	#ifdef DEBUG
    Serial.print("Backing up RSA Key Number ");
    Serial.println(slot);
   #endif
    memset(temp, 0, 256); //Wipe all data from temp buffer
    ptr = temp;
	type = onlykey_flashget_RSA(slot);
	if(type != 0x00)
      {
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = type;
		memcpy(large_temp+large_data_offset+3, rsa_private_key, (type*128));
        large_data_offset=large_data_offset+(type*128)+3;
      } else {
			#ifdef DEBUG
			Serial.print("No key set to slot");
			#endif
	  }
  }
  
  //Copy ECC keys to buffer
  for (int slot=101; slot<=132; slot++)
  {
	#ifdef DEBUG
    Serial.print("Backing up ECC Key Number ");
    Serial.println(slot);
   #endif
    memset(temp, 0, 256); //Wipe all data from temp buffer
    ptr = temp;
	type = onlykey_flashget_ECC(slot);
	if(type != 0x00)
      {
		large_temp[large_data_offset] = 0xFF; //delimiter
		large_temp[large_data_offset+1] = slot;
		large_temp[large_data_offset+2] = type;
		memcpy(large_temp+large_data_offset+3, ecc_private_key, 32);
        large_data_offset=large_data_offset+32+3;
      } else {
			#ifdef DEBUG
			Serial.print("No key set to slot");
			#endif
	  }
  }
  
//Copy U2F key/Cert to buffer
	large_temp[large_data_offset] = 0xF1; //delimiter
	memcpy(large_temp+large_data_offset+1, attestation_priv, 32);
    large_data_offset=large_data_offset+32+1;
	
	onlykey_eeget_U2Fcertlen(length);
    int length2 = length[0] << 8 | length[1];
	large_temp[large_data_offset] = 0xF2; //delimiter
	memcpy(large_temp+large_data_offset+1, attestation_der, length2);
    large_data_offset=large_data_offset+length2+1;

//Encrypt
    
    #ifdef DEBUG
	Serial.println();
        Serial.println("Unencoded");
        for (int z = 0; z <= large_data_offset; z++) {
        Serial.print(large_temp[z], HEX);
        }
        Serial.println();
    #endif
	int i = 0;
	while(i <= large_data_offset && i < sizeof(large_temp)) {
		Keyboard.println();
		delay(((TYPESPEED[0]*TYPESPEED[0])*10));
		if ((large_data_offset - i) < 42) {
			int enclen = base64_encode(large_temp+i, temp, (large_data_offset - i), '/n'); //Equals 56 in base32
			for (int z = 0; z <= enclen; z++) {
			Keyboard.write(temp[z]);
			delay(((TYPESPEED[0]*TYPESPEED[0])*10));
			}  
		}	
		else {
			base64_encode(large_temp+i, temp, 42, '/n'); //Equals 56 in base32
			for (int z = 0; z <= 56; z++) {
			Keyboard.write(temp[z]);
			delay(((TYPESPEED[0]*TYPESPEED[0])*10));
			}  
		}
		i = i+42;
		memset(temp, 0, sizeof(temp));
	}
	Keyboard.println();
	delay(((TYPESPEED[0]*TYPESPEED[0])*10));
	#ifdef DEBUG
        Serial.println("Encoded");
        for (int z = 0; z <= large_data_offset; z++) {
        Serial.print(large_temp[z], HEX);
        }
        Serial.println();
    #endif
	
//End backup footer
    for (int z = 0; z <= sizeof(endkbackup); z++) {
        Keyboard.write(endkbackup[z]);
		delay(((TYPESPEED[0]*TYPESPEED[0])*10));
	} 
	Keyboard.println();
large_data_offset = 0;
memset(large_temp, 0 , sizeof(large_temp));
}

void RESTORE(uint8_t *buffer) {
  uint8_t temp[64];
  static uint8_t large_temp [7028];
  static bool finishedslots;
  int urllength;
  int usernamelength;
  int passwordlength;
  int otplength;
  uint8_t *ptr;

  //Slot restore
  if (buffer[5]==0xFF && !finishedslots) //Not last packet
	{
	if (large_data_offset <= (sizeof(large_temp) - 57)) {
			base64_decode(large_temp+large_data_offset, buffer+6, 56); //Equals 56 in base32
			large_data_offset = large_data_offset + 42;
		} else {
			hidprint("Error backup file too large");
			return;
		}
		return;
	} else if (!finishedslots) { //Last packet
		if (large_data_offset <= (sizeof(large_temp) - 57) && buffer[5] <= 56) {
			base64_decode(large_temp+large_data_offset, buffer+6, buffer[5]); //Equals 56 in base32
			large_data_offset = large_data_offset + buffer[5];
		} else {
			hidprint("Error backup file too large");
			return;
		}
#ifdef DEBUG 
		Serial.print("Length of backup file = ");
        Serial.println(large_data_offset);
#endif 
		
	//TODO Decrypt  
		ptr = large_temp;
		large_temp[sizeof(large_temp)] = 0;
		while(*ptr) {
			if (*ptr = 0xFF) {
				temp[0] = 0xFF;
				temp[1] = 0xFF;
				temp[2] = 0xFF;
				temp[3] = 0xFF;
				temp[4] = OKSETSLOT;
				ptr++;
				temp[5] = *ptr; //Slot
				ptr++;
				temp[6] = *ptr; //Value
				ptr++;
				temp[7] = *ptr; 
				int i = 8;
				ptr++;
				while (*ptr != 0xFF && *ptr != 0x00) {
					temp[i] = *ptr;
					ptr++;
					i++;
				} 
				SETSLOT(temp);
			} else {
			ptr++;
			}
		}
	hidprint("Successfully loaded backup of slot configuration");
	memset(temp, 0, sizeof(temp)); //Wipe all data from temp
	memset(large_temp, 0, sizeof(large_temp)); //Wipe all data from largebuffer
	large_data_offset = 0;
	finishedslots = true;
	}

  //Key restore
  if (buffer[5]==0xFF && finishedslots) //Not last packet
	{
		if (large_data_offset <= (sizeof(large_temp) - 57)) {
			base64_decode(large_temp+large_data_offset, buffer+6, 56); //Equals 56 in base32
			large_data_offset = large_data_offset + 42;
		} else {
			hidprint("Error backup file too large");
			return;
		}
		return;
	} else if (finishedslots) { //Last packet
		if (large_data_offset <= (sizeof(large_temp) - 57) && buffer[5] <= 56) {
			base64_decode(large_temp+large_data_offset, buffer+6, buffer[5]); //Equals 56 in base32
			large_data_offset = large_data_offset + buffer[5];
		} else {
			hidprint("Error backup file too large");
			return;
		}
#ifdef DEBUG 
		Serial.print("Length of backup file = ");
        Serial.println(large_data_offset);
#endif 
		
	//TODO Decrypt  
	large_temp[sizeof(large_temp)] = 0;
	
	//Import Keys
	while (*ptr == 0xFF) {
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
		if (temp[5] > 100) {
			ptr++;
			memcpy(temp+7, ptr, 32);
			SETPRIV(temp);
			ptr = ptr + 32;
			large_data_offset = large_data_offset - 35;
		} 
		else if (*ptr == 1) {
			ptr++;
			memcpy(temp+7, ptr, 128);
			SETPRIV(temp);
			ptr = ptr + 128;
			large_data_offset = large_data_offset - 131;
		}
		else if (*ptr == 2) {
			ptr++;
			memcpy(temp+7, ptr, 256);
			SETPRIV(temp);
			ptr = ptr + 256;
			large_data_offset = large_data_offset - 259;
		} else {
			hidprint("Error backup file format incorrect");
		}

	}

		//Import U2F Priv
	if (*ptr == 0xF1) {
		memset(temp, 0, sizeof(temp));
		temp[0] = 0xBA;
		temp[1] = 0xFF;
		temp[2] = 0xFF;
		temp[3] = 0xFF;
		temp[4] = OKSETU2FPRIV;
		memcpy(temp+5, ptr, 32);
		SETU2FPRIV(temp);
		ptr = ptr + 32;
		large_data_offset = large_data_offset - 34;
	} else {
		hidprint("Error backup file format incorrect");
	}

		//Import U2F Cert
	if (*ptr == 0xF2) {
		memset(temp, 0, sizeof(temp));
		temp[0] = 0xBA;
		temp[1] = 0xFF;
		temp[2] = 0xFF;
		temp[3] = 0xFF;
		temp[4] = OKSETU2FCERT;
		temp[5] = 0xBA;
		memcpy(temp+6, ptr, (large_data_offset-3));
		large_data_len=(large_data_offset-3);
		SETU2FCERT(temp);
	} else {
		hidprint("Error backup file format incorrect");
	}
	hidprint("Successfully loaded backup file");
	memset(temp, 0, sizeof(temp)); //Wipe all data from temp
	memset(large_temp, 0, sizeof(large_temp)); //Wipe all data from largebuffer
	large_data_offset = 0;
	delay(2000);
	hidprint("Remove and Reinsert OnlyKey to complete restore");
	while (1==1) {
		blink(3);
	}
    }
	
}