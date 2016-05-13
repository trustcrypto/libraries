/*
||
|| @file Password.cpp
|| @version 1.2
|| @author Alexander Brevig
|| @contact alexanderbrevig@gmail.com
||
||  4/5/2012 Updates Nathan Sobieck: Nathan@Sobisource.com
||   Now v1.2 Arduino IDE v1.0 With BAckwards compatibility
||
|| @description
|| | Handle passwords easily
|| #
||
|| @license
|| | This library is free software; you can redistribute it and/or
|| | modify it under the terms of the GNU Lesser General Public
|| | License as published by the Free Software Foundation; version
|| | 2.1 of the License.
|| |
|| | This library is distributed in the hope that it will be useful,
|| | but WITHOUT ANY WARRANTY; without even the implied warranty of
|| | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
|| | Lesser General Public License for more details.
|| |
|| | You should have received a copy of the GNU Lesser General Public
|| | License along with this library; if not, write to the Free Software
|| | Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
|| #
||
*/

#include "sha256.h"
#include "password.h"
#include "yksim.h"
#include <EEPROM.h>
#include "flashkinetis.h"
#include "onlykey.h"

static uint8_t temp[32];

//construct object in memory, set all variables
Password::Password(char* pass){
	set( pass );
	reset();
}

//set the password
void Password::set(char* pass){
	target = pass;
}

//evaluate a string, is it equal to the password?
bool Password::is(char* pass){ 
	byte i=0;
	while (*pass && i<MAX_PASSWORD_LENGTH){
		guess[i] = pass[i];
		i++;
	}
	return evaluate();
}

//append a char to the guessed password
bool Password::append(char character){ 
	if (currentIndex+1==MAX_PASSWORD_LENGTH){
		return false;
	}else{
		guess[currentIndex++] = character;
		guess[currentIndex] = STRING_TERMINATOR; //ensure a valid c string
		
	}
	return true;
}

//reset the guessed password, one can guess again
void Password::reset(){ 
	currentIndex = 0;
	guess[currentIndex] = STRING_TERMINATOR;
}

//is the current guessed password equal to the target password?
bool Password::evaluate(){ 
	char pass = target[0];
	char guessed = guess[0];
	
	for (byte i=1; i<MAX_PASSWORD_LENGTH; i++){
	
		
		//check if guessed char is equal to the password char
		if (pass==STRING_TERMINATOR && guessed==STRING_TERMINATOR){
			return true; //both strings ended and all previous characters are equal 
		}else if (pass!=guessed || pass==STRING_TERMINATOR || guessed==STRING_TERMINATOR){
			return false; //difference OR end of string has been reached
		}
		//read next char
		pass = target[i];
		guessed = guess[i];
	}
	return false; //a 'true' condition has not been met
}


//is the hash of the current guessed password equal to the stored hash?
bool Password::hashevaluate(){ 
	uint8_t hash[32];
	uint8_t *ptr;
	ptr = temp;

	//Copy characters to byte array
			for (int i =0; i <= strlen(guess); i++) {
			temp[i] = (byte)guess[i];
			}
			SHA256_CTX pinhash;
			sha256_init(&pinhash);
			sha256_update(&pinhash, temp, strlen(guess)); //Add new PIN to hash
			onlykey_eeget_noncehash (ptr, 32); //Get nonce from EEPROM
			
			Serial.print(F("NONCE HASH:")); //TODO remove debug
      for (int i =0; i < 32; i++) {
        Serial.print(temp[i], HEX);
      }
	  Serial.println();
	  
			sha256_update(&pinhash, temp, 32); //Add nonce to hash
			sha256_final(&pinhash, temp); //Create hash and store in temp
			ptr = hash;
			onlykey_eeget_pinhash (ptr, 32); //store valid pinhash in hash
	
	Serial.print(F("Guessed Hash:")); //TODO remove debug
      for (int i =0; i < 32; i++) {
        Serial.print(temp[i], HEX);
      }
	  Serial.println();
	  Serial.print(F("PIN Hash:")); //TODO remove debug
      for (int i =0; i < 32; i++) {
        Serial.print(hash[i], HEX);
      }
	  Serial.println();
	  
	char pass2 = hash[0];
	char guessed2 = temp[0];
	for (byte i=1; i<32; i++){
		
		//check if guessed char is equal to the password char
		if (i == 31 && pass2==guessed2){
			return true; //both strings ended and all previous characters are equal 
		}else if (pass2!=guessed2){
			return false; //difference 
		}
		
		//read next char
		pass2 = hash[i];
		guessed2 = temp[i];
	}
	return false; //a 'true' condition has not been met
}

bool Password::sdhashevaluate(){ 
	uint8_t hash[32];
	uint8_t *ptr;
	ptr = temp;

	Serial.println();

	ptr = hash;
	onlykey_eeget_selfdestructhash (ptr); //store self destruct PIN hash
	
	  Serial.print(F("SD PIN Hash:")); //TODO remove debug
      for (int i =0; i < 32; i++) {
        Serial.print(hash[i], HEX);
      }
	  Serial.println();
	  
	char pass2 = hash[0];
	char guessed2 = temp[0];
	for (byte i=1; i<32; i++){
		
		//check if guessed char is equal to the password char
		if (i == 31 && pass2==guessed2){
			return true; //both strings ended and all previous characters are equal 
		}else if (pass2!=guessed2){
			return false; //difference 
		}
		
		//read next char
		pass2 = hash[i];
		guessed2 = temp[i];
	}
	return false; //a 'true' condition has not been met
}
bool Password::pdhashevaluate(){ 
	uint8_t hash[32];
	uint8_t *ptr;
	ptr = temp;

	Serial.println();

	ptr = hash;
	onlykey_eeget_plausdenyhash (ptr); //store plausible deniability PIN hash
	
	  Serial.print(F("PD PIN Hash:")); //TODO remove debug
      for (int i =0; i < 32; i++) {
        Serial.print(hash[i], HEX);
      }
	  Serial.println();
	  
	char pass2 = hash[0];
	char guessed2 = temp[0];
	for (byte i=1; i<32; i++){
		
		//check if guessed char is equal to the password char
		if (i == 31 && pass2==guessed2){
			return true; //both strings ended and all previous characters are equal 
		}else if (pass2!=guessed2){
			return false; //difference 
		}
		
		//read next char
		pass2 = hash[i];
		guessed2 = temp[i];
	}
	return false; //a 'true' condition has not been met
}
//set password using operator =
Password &Password::operator=(char* pass){
	set( pass );
	return *this;
}


//test password using ==
bool Password::operator==(char* pass){
	return is( pass );
}

//test password using !=
bool Password::operator!=(char* pass){
	return !is( pass );
}

//append to currently guessed password using operator <<
Password &Password::operator<<(char character){
	append( character );
	return *this;
}

/*
|| @changelog
|| | 2009-06-17 - Alexander Brevig : Added assignment operator =, equality operators == != and insertion operator <<
|| | 2009-06-17 - Alexander Brevig : Initial Release
|| #
*/