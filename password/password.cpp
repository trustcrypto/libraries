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
#include <EEPROM.h>
#include "flashkinetis.h"
#include "onlykey.h"
#include "T3MacLib.h"
#include <Curve25519.h>

uint8_t profilekey[32];
uint8_t p1hash[32];
uint8_t sdhash[32];
uint8_t p2hash[32];
uint8_t nonce[32];
extern uint8_t profilemode;
int integrityctr1 = 0;
int integrityctr2 = 0;
extern uint8_t type;

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
bool Password::profile1hashevaluate(){ 
	uint8_t p2mode;
	uint8_t temp[32];
	uint8_t pinmask[10];
	size_t guesslen = strlen(guess);
	if (guesslen < 7) {
		delay (30); //Simulate time taken to hash
		return false; //PIN length must be 7 - 10 digits
	}
//Hash values
	SHA256_CTX pinhash;
	sha256_init(&pinhash);
#ifdef DEBUG
	Serial.print("NONCE HASH:"); 
	byteprint(nonce, 32);
#endif
	sha256_update(&pinhash, nonce, 32); //Add nonce to hash
	onlykey_eeget_pinmask((uint8_t*)pinmask);
	for (int i =0; i <= guesslen; i++) {
		temp[i] = (uint8_t)guess[i] ^ (ID[i] ^ (nonce[i] ^ pinmask[i])); //Mask PIN Number with nonce (flash), pinmask (eeprom), and chip ID (ROM)
	}
	sha256_update(&pinhash, temp, guesslen); //Add new PIN to hash
	sha256_final(&pinhash, profilekey); //Create hash and store in profilekey
	//Generate public key of pinhash
	memcpy(temp, profilekey, 32);
	temp[0] &= 0xF8;
    temp[31] = (temp[31] & 0x7F) | 0x40;
	//Generate public key of pinhash
	Curve25519::eval(profilekey, temp, 0); //Generate public in profilekey

#ifdef DEBUG
	Serial.print("Guessed Hash/PublicKey:"); 
    byteprint(profilekey, 32);
	Serial.print("PIN Hash/PublicKey:"); 
	byteprint(p1hash, 32);
#endif
	char pass2 = p1hash[0];
	char guessed2 = profilekey[0];
	for (byte i=1; i<32; i++){

		//check if guessed char is equal to the password char
		integrityctr1++;
		if (i == 31 && pass2==guessed2){
			onlykey_eeget_2ndprofilemode (&p2mode); //get 2nd profile mode
#ifdef DEBUG
			Serial.print("Profile Mode"); 
			Serial.print(p2mode);
#endif
			if (p2mode==STDPROFILE2) { //there are two profiles
			#ifdef STD_VERSION
			//Generate shared secret of p1hash private key and p2hash public key
				Curve25519::eval(profilekey, temp, p2hash); //shared secret stored in profilekey			
				#ifdef DEBUG
				Serial.print("Shared Secret Profile 1"); 
				byteprint(profilekey, 32);
				#endif
			#endif	
			} else { //there is one profile
			#ifdef STD_VERSION
			//Generate shared secret of p1hash private key and p1hash public key
				Curve25519::eval(profilekey, temp, p1hash); //Set this as profile key, used to encrypt profile 1 data
			#endif
			}
			integrityctr2++;
			profilemode=STDPROFILE1;
			return true; //both strings ended and all previous characters are equal 
		}else if (pass2!=guessed2){
			integrityctr2++;
			return false; //difference 
		}
		
		//read next char
		pass2 = p1hash[i];
		guessed2 = profilekey[i];
		integrityctr2++;
	}
	return false; //a 'true' condition has not been met
}

bool Password::profile2hashevaluate(){ 
	uint8_t p2mode;
	uint8_t temp[32];
	uint8_t pinmask[10];
	size_t guesslen = strlen(guess);
	if (guesslen < 7) {
		delay (30); //Simulate time taken to hash
		return false; //PIN length must be 7 - 10 digits
	}
//Hash values
	SHA256_CTX pinhash;
	sha256_init(&pinhash);
#ifdef DEBUG
	Serial.print("NONCE HASH:"); 
	byteprint(nonce, 32);
#endif
	sha256_update(&pinhash, nonce, 32); //Add nonce to hash
	onlykey_eeget_pinmask((uint8_t*)pinmask);
	for (int i =0; i <= guesslen; i++) {
		temp[i] = (uint8_t)guess[i] ^ (ID[i] ^ (nonce[i] ^ pinmask[i])); //Mask PIN Number with nonce (flash), pinmask (eeprom), and chip ID (ROM)
				Serial.print("ID Char ");
		Serial.println(ID[i]);
				Serial.print("PINmask Char ");
		Serial.println(pinmask[i]);
				Serial.print("nonce Char ");
		Serial.println(nonce[i]);
		Serial.print("PIN Char ");
		Serial.println(temp[i]);
	}
	sha256_update(&pinhash, temp, guesslen); //Add new PIN to hash
	sha256_final(&pinhash, profilekey); //Create hash and store in profilekey
	//Generate public key of pinhash
	memcpy(temp, profilekey, 32);
	temp[0] &= 0xF8;
    temp[31] = (temp[31] & 0x7F) | 0x40;
	//Generate public key of pinhash
	Curve25519::eval(profilekey, temp, 0); //Generate public in profilekey

#ifdef DEBUG
	Serial.print("Guessed Hash/PublicKey:"); 
    byteprint(profilekey, 32);
	Serial.print("2nd Profile PIN Hash/PublicKey:"); 
	byteprint(p2hash, 32);
#endif
	char pass2 = p2hash[0];
	char guessed2 = profilekey[0];
	for (byte i=1; i<32; i++){
		
		//check if guessed char is equal to the password char
		integrityctr1++;
		if (i == 31 && pass2==guessed2){
			onlykey_eeget_2ndprofilemode (&p2mode); //get 2nd profile mode
			if (p2mode!=NONENCRYPTEDPROFILE) { //profile key not used for plausible deniability mode
				#ifdef STD_VERSION
				Curve25519::eval(profilekey, temp, p1hash); //Generate shared secret of p2hash private key and p1hash public key
				#ifdef DEBUG
				Serial.print("Shared Secret Profile 2"); 
				byteprint(profilekey, 32);
				#endif
				//Set this as profile key, used to encrypt profile 2 data
				profilemode=STDPROFILE2;
				#endif
			} else {
				if (configmode) return false;
				profilemode=NONENCRYPTEDPROFILE;
			}
			integrityctr2++;
			return true; //both strings ended and all previous characters are equal 
		} else if (pass2!=guessed2){
			integrityctr2++;
			return false; //difference 
		}
		
		//read next char
		pass2 = p2hash[i];
		guessed2 = profilekey[i];
		integrityctr2++;
	}
	return false; //a 'true' condition has not been met
}


bool Password::sdhashevaluate(){ 
	size_t guesslen = strlen(guess);
	if (guesslen < 7) {
		delay (30); //Simulate time taken to hash
		return false; //PIN length must be 7 - 10 digits
	}
//Hash values
	SHA256_CTX pinhash;
	sha256_init(&pinhash);
	sha256_update(&pinhash, (uint8_t *)guess, guesslen); //Add new PIN to hash
#ifdef DEBUG
	Serial.print("NONCE HASH:"); 
	byteprint(nonce, 32);
#endif
	  
	sha256_update(&pinhash, nonce, 32); //Add nonce to hash
	sha256_final(&pinhash, profilekey); //Create hash and store in profilekey
#ifdef DEBUG
	Serial.println();
	
	  Serial.print("SD PIN Hash: "); 
      byteprint(sdhash, 32);
#endif
	char pass2 = sdhash[0];
	char guessed2 = profilekey[0];
	for (byte i=1; i<32; i++){
		
		//check if guessed char is equal to the password char
		if (i == 31 && pass2==guessed2){
			return true; //both strings ended and all previous characters are equal 
		}else if (pass2!=guessed2){
			return false; //difference 
		}
		
		//read next char
		pass2 = sdhash[i];
		guessed2 = profilekey[i];
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