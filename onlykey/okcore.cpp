/* okcore.cpp
*/

/* Modifications by Tim Steiner
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
 *Original U2F Portion
 *Copyright (c) 2015, Yohanes Nugroho
 *All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 *Redistributions in binary form must reproduce the above copyright notice,
 *this list of conditions and the following disclaimer in the documentation
 *and/or other materials provided with the distribution.
 *
 *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
Password password = Password( "not used" );
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
//RNG Assignments
/*************************************/
size_t length = 48; // First block should wait for the pool to fill up.
/*************************************/
//U2F Assignments
/*************************************/
uint8_t expected_next_packet;
int large_data_len;
int large_data_offset;
uint8_t large_buffer[1024];
uint8_t large_resp_buffer[1024];
uint8_t recv_buffer[64];
uint8_t resp_buffer[64];
extern uint8_t handle[64];
uint8_t sha256_hash[32];
char attestation_pub[66];
char attestation_priv[33];
char attestation_der[768];
/*************************************/
//SSH Authentication assignments
/*************************************/
extern uint8_t ssh_signature[64];
extern uint8_t ssh_public_key[32];
extern uint8_t ssh_private_key[32];
/*************************************/

void recvmsg() {
  int n;
  int c;
  int z;
  
  n = RawHID.recv(recv_buffer, 0); // 0 timeout = do not wait
  if (n > 0) {
#ifdef DEBUG    
    Serial.print(F("\n\nReceived packet"));
    for (z=0; z<64; z++) {
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
	   }else if (initialized==true && unlocked==true) 
	   {
		#ifdef US_VERSION
		SETU2FPRIV(recv_buffer);
		#endif
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
		#ifdef US_VERSION
		WIPEU2FPRIV(recv_buffer);
		#endif
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
		#ifdef US_VERSION
		SETU2FCERT(recv_buffer);
		#endif
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
		#ifdef US_VERSION
		WIPEU2FCERT(recv_buffer);
		#endif
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
	  case OKSETSSHPRIV:
           if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
                #ifdef US_VERSION
                SETSSHPRIV(recv_buffer);
                #endif
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
      case OKWIPESSHPRIV:
           if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
                #ifdef US_VERSION
                WIPESSHPRIV(recv_buffer);
                #endif
	   }
	   else
	   {
	   hidprint("ERROR DEVICE LOCKED");
	   return;
	   }	
      return;
      break;
      case OKSIGNSSHCHALLENGE:
           if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
                if(!PDmode) {
				#ifdef US_VERSION
				SoftTimer.add(&FadeinTask);
				SIGNSSHCHALLENGE(recv_buffer);
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
      case OKGETSSHPUBKEY:
			if(initialized==false && unlocked==true) 
	   {
		hidprint("No PIN set, You must set a PIN first");
		return;
	   }else if (initialized==true && unlocked==true) 
	   {
                #ifdef US_VERSION
                GETSSHPUBKEY();
                #endif
	   }
	   else
	   {
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
      for (int i =0; i <= strlen(password.guess); i++) {
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
			for (int i =0; i <= strlen(password.guess); i++) {
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
      for (int i =0; i <= strlen(password.guess); i++) {
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
		for (int i =0; i <= strlen(password.guess); i++) {
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
      for (int i =0; i <= strlen(password.guess); i++) {
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
			for (int i =0; i <= strlen(password.guess); i++) {
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
		hidprint("UNLOCKED");
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
	  
	  onlykey_eeget_label(ptr, (offset + 1));
	  label[0] = (uint8_t)0x01;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
	  hidprint(labelchar);
	  delay(20);
	  
	  onlykey_eeget_label(ptr, (offset   + 2));
	  label[0] = (uint8_t)0x02;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
      	  hidprint(labelchar);
      	  delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 3));
	  label[0] = (uint8_t)0x03;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 4));
	  label[0] = (uint8_t)0x04;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 5));
	  label[0] = (uint8_t)0x05;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 6));
	  label[0] = (uint8_t)0x06;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 7));
	  label[0] = (uint8_t)0x07;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 8));
	  label[0] = (uint8_t)0x08;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 9));
	  label[0] = (uint8_t)0x09;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 10));
	  label[0] = (uint8_t)0x10;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 11));
	  label[0] = (uint8_t)0x11;
	  label[1] = (uint8_t)0x7C;
	  ByteToChar(label, labelchar, EElen_label+3);
#ifdef DEBUG
	  Serial.println(labelchar);
#endif
          hidprint(labelchar);
          delay(20);
	  
	  onlykey_eeget_label(ptr, (offset  + 12));
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
	
      char cmd = buffer[4]; //cmd or continuation
      int slot = buffer[5];
      int value = buffer[6];
      int length;
#ifdef DEBUG
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
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Label Value to EEPROM...");
#endif
            onlykey_eeset_label(buffer + 7, length, slot);
			hidprint("Successfully set Label");
            return;
            //break;
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
            onlykey_eeset_username(buffer + 7, length, slot);
	    hidprint("Successfully set Username");
            return;
            //break;
            case 3:
            //Set value in EEPROM
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
            //break;
            case 4:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Delay1 to EEPROM...");
#endif
            buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay1(buffer + 7, slot);
	    hidprint("Successfully set Delay1");
            return;
            //break;
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
            //break;
            case 6:
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
            //break;
            case 7:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing Delay2 to EEPROM...");
#endif
            buffer[7] = (buffer[7] -'0');
            onlykey_eeset_delay2(buffer + 7, slot);
	    hidprint("Successfully set Delay2");
            return;
            //break;
            case 8:
            //Set value in EEPROM
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Writing 2FA Type to EEPROM...");
#endif
            onlykey_eeset_2FAtype(buffer + 7, slot);
	    hidprint("Successfully set 2FA Type");
            return;
            //break;
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
            //break;
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
            //break;
            default: 
            return;
          }
      blink(3);
      return;
}

void WIPESLOT (uint8_t *buffer)
{
      char cmd = buffer[4]; //cmd or continuation
      int slot = buffer[5];
      int value = buffer[6];
      int length;
#ifdef DEBUG
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
	 if (value==0x0A) {
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
            onlykey_eeset_label((buffer + 7), 0, slot);
            hidprint("Successfully wiped Label");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping Username Value...");
#endif 
            onlykey_eeset_username((buffer + 7), 0, slot);
            hidprint("Successfully wiped Username");
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
            Serial.print("Wiping Password Value...");
#endif 
            onlykey_eeset_password((buffer + 7), 0, slot);
            hidprint("Successfully wiped Password");
#ifdef DEBUG
            Serial.println(); //newline
            Serial.print("Wiping Additional Character2 Value...");
#endif 
            onlykey_eeset_addchar2((buffer + 7), slot);
            hidprint("Successfully wiped Additional Character 2");
#ifdef DEBUG
	    Serial.println(); //newline
            Serial.print("Wiping Delay2 Value...");
#endif 
            onlykey_eeset_delay2((buffer + 7), slot);
            hidprint("Successfully wiped Delay 2");
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
    static char const hexchars[] = "0123456789ABCDEF";
    while (len > 0) {
        int b = *data++;
#ifdef DEBUG
        Serial.print(hexchars[(b >> 4) & 0x0F]);
        Serial.print(hexchars[b & 0x0F]);
#endif 

        --len;
    } 
#ifdef DEBUG
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
	uintptr_t adr = 0x0;
	onlykey_eeget_wipemode(&mode);
	if (mode <= 1) {
	wipeflash(); //Wipe flash first need eeprom address for flash to wipe
	wipeEEPROM();
	} else {
	//FULLWIPE Mode
	flashEraseAll();
#ifdef DEBUG
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
	uint8_t tag[16];
	uint8_t *ptr;
	ptr = iv2;
	onlykey_flashget_noncehash(ptr, 12);
		for(int i =0; i<=12; i++) {
		  iv2[i]=iv2[i]^*iv1;
		}
	gcm.clear ();
	gcm.setKey(key, sizeof(key));
	gcm.setIV(iv2, 12);
	gcm.encrypt(state, state, len);
	gcm.computeTag(tag, sizeof(tag)); 
	#endif
}

int aes_gcm_decrypt (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
        #ifdef US_VERSION
	GCM<AES256> gcm; 
	uint8_t iv2[12];
	uint8_t tag[16];
	uint8_t *ptr;
	ptr = iv2;
	onlykey_flashget_noncehash(ptr, 12);
		for(int i =0; i<=12; i++) {
		  iv2[i]=iv2[i]^*iv1;
		}
	gcm.clear ();
	gcm.setKey(key, sizeof(key));
	gcm.setIV(iv2, 12);
	gcm.decrypt(state, state, len);
	if (!gcm.checkTag(tag, sizeof(tag))) {
		return 1;
	}
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

int aes_gcm_decrypt2 (uint8_t * state, uint8_t * iv1, const uint8_t * key, int len) {
        #ifdef US_VERSION
	GCM<AES256> gcm; 
	uint8_t tag[16];
	gcm.clear ();
	gcm.setKey(key, sizeof(key));
	gcm.setIV(iv1, 12);
	gcm.decrypt(state, state, len);
	if (!gcm.checkTag(tag, sizeof(tag))) {
		return 1;
	}
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



int onlykey_flashget_totpkey (uint8_t *ptr, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 2048; //Next Sector
	switch (slot) {
		uint8_t length;
		int size;
        	case 1:
			onlykey_eeget_totpkeylen1(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 2:
			onlykey_eeget_totpkeylen2(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 3:
			onlykey_eeget_totpkeylen3(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 4:
			onlykey_eeget_totpkeylen4(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 5:
			onlykey_eeget_totpkeylen5(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 6:
			onlykey_eeget_totpkeylen6(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 7:
			onlykey_eeget_totpkeylen7(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 8:
			onlykey_eeget_totpkeylen8(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 9:
			onlykey_eeget_totpkeylen9(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 10:
			onlykey_eeget_totpkeylen10(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 11:
			onlykey_eeget_totpkeylen11(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 12:
			onlykey_eeget_totpkeylen12(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 13:
			onlykey_eeget_totpkeylen13(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 14:
			onlykey_eeget_totpkeylen14(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 15:
			onlykey_eeget_totpkeylen15(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 16:
			onlykey_eeget_totpkeylen16(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 17:
			onlykey_eeget_totpkeylen17(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 18:
			onlykey_eeget_totpkeylen18(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 19:
			onlykey_eeget_totpkeylen19(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 20:
			onlykey_eeget_totpkeylen20(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 21:
			onlykey_eeget_totpkeylen21(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 22:
			onlykey_eeget_totpkeylen22(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 23:
			onlykey_eeget_totpkeylen23(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;
		case 24:
			onlykey_eeget_totpkeylen24(&length);
			size = (int) length;
			if (size > EElen_totpkey) size = EElen_totpkey;
			adr=adr+((EElen_totpkey*slot)-EElen_totpkey);
			onlykey_flashget_common(ptr, (unsigned long*)adr, EElen_totpkey);
			return size;
            break;	
	}

return 0;
}

void onlykey_flashset_totpkey (uint8_t *ptr, int size, int slot) {

    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 2048;
    uint8_t temp[1536];
    uint8_t *tptr;
    tptr=temp;
    //Copy current flash contents to buffer
    onlykey_flashget_common(tptr, (unsigned long*)adr, 1536);
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
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen1(&length);
            	break;
		case 2:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen2(&length);
            	break;
		case 3:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen3(&length);
            break;
		case 4:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen4(&length);
            break;
		case 5:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen5(&length);
            break;
		case 6:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen6(&length);
            break;
		case 7:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen7(&length);
            break;
		case 8:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen8(&length);
            break;
		case 9:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen9(&length);
            break;
		case 10:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen10(&length);
            break;
		case 11:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen11(&length);
            break;
		case 12:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen12(&length);
            break;
            	case 13:
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen13(&length);
            	break;
		case 14:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen14(&length);
            	break;
		case 15:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen15(&length);
            break;
		case 16:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen16(&length);
            break;
		case 17:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen17(&length);
            break;
		case 18:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen18(&length);
            break;
		case 19:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen19(&length);
            break;
		case 20:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen20(&length);
            break;
		case 21:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen21(&length);
            break;
		case 22:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen22(&length);
            break;
		case 23:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
			length = (uint8_t) size;
			onlykey_eeset_totpkeylen23(&length);
            break;
		case 24:
		if (size > EElen_totpkey) size = EElen_totpkey;
			if (size > EElen_totpkey) size = EElen_totpkey;
			//Write buffer to flash
    		onlykey_flashset_common(tptr, (unsigned long*)adr, 1536);
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
	adr = adr + 4096; //3rd flash sector
    onlykey_flashget_common((uint8_t*)attestation_priv, (unsigned long*)adr, 32); 
#ifdef DEBUG 
    Serial.print("attestation priv =");
#endif 
    for (int i = 0; i< sizeof(attestation_priv); i++) {
#ifdef DEBUG 
    Serial.println(attestation_priv[i],HEX);
#endif 
    }
    adr=adr+2048; //4th flash sector
    onlykey_eeget_U2Fcertlen(length);
    int length2 = length[0] << 8 | length[1];
#ifdef DEBUG 
    Serial.print("attestation der length=");
    Serial.println(length2);
#endif 
    onlykey_flashget_common((uint8_t*)attestation_der, (unsigned long*)adr, length2); 
#ifdef DEBUG 
    Serial.print("attestation der =");
    for (int i = 0; i< sizeof(attestation_der); i++) {
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
	adr = adr + 4096; //3rd flash sector
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
	adr = adr + 4096; //3rd flash sector
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
	adr = adr + 6144; //4th flash sector
	uint8_t *ptr;
	if (buffer[5]==0xFF) //Not last packet
	{
		if (large_data_offset <= 710) {
			memcpy(large_buffer+large_data_offset, buffer+6, 58);
			large_data_offset = large_data_offset + 58;
		} else {
			hidprint("Error U2F Cert larger than 768 bytes");
		}
		return;
	} else { //Last packet
		if (large_data_offset <= 710 && buffer[5] <= 58) {
			memcpy(large_buffer+large_data_offset, buffer+6, buffer[5]);
			large_data_offset = large_data_offset + buffer[5];
		} else {
			hidprint("Error U2F Cert larger than 768 bytes");
		}
		length[0] = large_data_offset >> 8  & 0xFF;
		length[1] = large_data_offset       & 0xFF;
		//Set U2F Certificate size
		onlykey_eeset_U2Fcertlen(length); 
#ifdef DEBUG 

		Serial.print("Length of U2F certificate = ");
        Serial.println(large_data_offset);
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
		ptr=large_buffer;
    	onlykey_flashset_common(ptr, (unsigned long*)adr, large_data_offset);
    	       

	}
    memcpy(attestation_der, large_buffer, 768);
#ifdef DEBUG 
    Serial.print("U2F Cert value =");
    for (int i = 0; i<large_data_offset; i++) {
    Serial.print(attestation_der[i],HEX);
    }
#endif
	large_data_offset = 0;
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
	adr = adr + 6144; //4th flash sector
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

int onlykey_flashget_SSH ()
{

if (PDmode) return 0;
#ifdef US_VERSION
#ifdef DEBUG 
    Serial.println("Flashget SSH");
#endif 
	uint8_t length[2];
    uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 8192; //5th flash sector
    onlykey_flashget_common((uint8_t*)ssh_private_key, (unsigned long*)adr, 32); 
	
	if (ssh_private_key[0] == 255 && ssh_private_key[1] == 255 && ssh_private_key[2] == 255) { //pinhash not set
		#ifdef DEBUG 
		Serial.printf("Read SSH Private Key from Sector 0x%X ",adr);
		Serial.printf("There is no SSH Private Key set");
		#endif
    	return 0;
    }
    else {
		#ifdef DEBUG 
		Serial.printf("Read SSH Private Key from Sector 0x%X ",adr);
		Serial.printf("SSH Private Key has been set");
		#endif
		return 1;
    }
#endif
}

void SETSSHPRIV (uint8_t *buffer)
{

if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println();
    Serial.println("OKSETSSHPRIV MESSAGE RECEIVED");
#endif
	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 8192; //5th flash sector
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
    Serial.print("SSH Private Key address =");
    Serial.println(adr, HEX);
#endif

	SSHinit();
    hidprint("Successfully set SSH private key");

    blink(3);
#endif
    return;

}

void WIPESSHPRIV (uint8_t *buffer)
{
if (PDmode) return;
#ifdef US_VERSION
#ifdef DEBUG
    Serial.println("OKWIPESSHPRIV MESSAGE RECEIVED");
#endif
	uint8_t flashoffset[1];	
	onlykey_eeget_flashpos((uint8_t*)flashoffset);
	uintptr_t adr = (unsigned long)flashoffset[0] * (unsigned long)2048;
	adr = adr + 8192; //5th flash sector
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
	memset(ssh_public_key, 0, 64); //Wipe all data from buffer 
	memset(ssh_private_key, 0, 64); //Wipe all data from buffer 
	SSHinit();
	hidprint("Successfully wiped SSH Private Key");
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
  uint8_t aeskey[16];
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
  
  aes_gcm_decrypt(temp, (uint8_t*)('y'+ID[34]), phash, (EElen_aeskey+EElen_private+EElen_aeskey));
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
    aeskey[i] = temp[i+EElen_public+EElen_private];
#ifdef DEBUG 
    Serial.print(aeskey[i],HEX);
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
  
  yubikey_init1(&ctx, aeskey, public_id, private_id, counter, time, seed);
 
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
		  
