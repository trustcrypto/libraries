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
	uint8_t KEK[32];
	uint8_t nonce2[32];
	extern int Profile_Offset;
	extern uint8_t onlykeyhw;
	extern uint8_t Duo_config[2];

	size_t guesslen = strlen(guess);

	Duo_config[0]=0;
	if (onlykeyhw==OK_HW_DUO) {
		if (guesslen==0) {
			// check if default PIN is set (chip ID)
			guesslen=16;
			memcpy(guess, (ID+18), 16);
			Duo_config[0]=1;
		}
	}
	
	if (guesslen < 7) {
		delay (30); //Simulate time taken to hash to decrease attack emanation surface
		return false; //PIN length must be 7 - 10 digits
	}

	//Hash PIN and Nonce
	SHA256_CTX pinhash;
	sha256_init(&pinhash);
	sha256_update(&pinhash, (uint8_t *)guess, guesslen); //Add new PIN to hash
	#ifdef DEBUG
	Serial.println("GUESSED PROFILE 1 PIN");
	byteprint((uint8_t *)guess, guesslen);
	Serial.print("NONCE HASH:"); 
	byteprint(nonce, 32);
	#endif
	
	sha256_update(&pinhash, nonce, 32); //Add nonce to hash
	sha256_final(&pinhash, KEK); //Create hash and store in KEK
	//Generate public key of pinhash
	KEK[0] &= 0xF8;
	KEK[31] = (KEK[31] & 0x7F) | 0x40;
	//Generate public key of pinhash
	Curve25519::eval(profilekey, KEK, 0); //Generate public in profilekey
	#ifdef DEBUG
	Serial.print("Public key of PIN hash:");
	byteprint(profilekey, 32);
	#endif
	
	//Hash generated public with mask (eeprom), and chip ID (ROM)
	sha256_init(&pinhash); 
	okeeprom_eeget_nonce2((uint8_t*)nonce2);
	sha256_update(&pinhash, nonce2, 16); //Add mask (eeprom)
	sha256_update(&pinhash, (uint8_t*)(ID+16), 16); //Add chip ID (ROM)
	sha256_update(&pinhash, profilekey, sizeof(profilekey)); //Add generated public to hash
	sha256_final(&pinhash, profilekey); //Create hash and store in profilekey

	//Do the same with stored public
	sha256_init(&pinhash); 
	sha256_update(&pinhash, nonce2, 16); //Add mask (eeprom)
	sha256_update(&pinhash, (uint8_t*)(ID+16), 16); //Add chip ID (ROM)
	sha256_update(&pinhash, p1hash, sizeof(p1hash)); //Add generated public to hash
	sha256_final(&pinhash, temp); //Create hash and store in profilekey

	#ifdef DEBUG
	Serial.print("Guessed Hash/PublicKey:"); 
	byteprint(profilekey, 32);
	Serial.print("Stored PIN Hash/PublicKey:"); 
	byteprint(temp, 32);
	#endif
	char pass2 = temp[0];
	char guessed2 = profilekey[0];
		
	for (byte i=1; i<32; i++){
		//check if guessed char is equal to the password char
		integrityctr1++;
		if (i == 31 && pass2==guessed2){
			okeeprom_eeget_2ndprofilemode (&p2mode); //get 2nd profile mode
			#ifdef DEBUG
			Serial.print("Profile Mode"); 
			Serial.print(p2mode);
			#endif
			if (p2mode==STDPROFILE2) { //there are two profiles
			#ifdef STD_VERSION
				//Generate shared secret of p1hash private key and p2hash public key
				if (!okcore_flashget_profilekey(profilekey)) { // Backwards support for old key method, KEK used as master, PIN changes not supported
				Curve25519::eval(profilekey, KEK, p2hash); //shared secret stored in profilekey
				#ifdef DEBUG
				Serial.print("Profile Key "); 
				byteprint(profilekey, 32);
				#endif			
				} else { // Using new method, PIN changes supported 
				//Create KEK - Hash with nonce (flash), mask (eeprom), and chip ID (ROM)
				Curve25519::eval(temp, KEK, p2hash); //shared secret stored in profilekey			
				#ifdef DEBUG
				Serial.print("Shared Secret Profile 1");
				byteprint(temp, 32);
				#endif
				#ifdef DEBUG
				Serial.print("nonce2");
				byteprint(nonce2, 32);
				#endif	
				#ifdef DEBUG
				Serial.print("ID");
				byteprint((uint8_t*)ID, 16);
				#endif	
				sha256_init(&pinhash); 
				sha256_update(&pinhash, nonce2, sizeof(nonce2)); //Add mask (eeprom)
				sha256_update(&pinhash, (uint8_t*)ID, 16); //Add chip ID (ROM)
				sha256_update(&pinhash, temp, sizeof(temp)); //Add generated shared secret
				sha256_update(&pinhash, nonce, 32); //Add nonce to hash
				sha256_final(&pinhash, KEK); //Create hash and store in KEK
				okcrypto_aes_gcm_decrypt2(profilekey, (uint8_t*)ID, KEK, 32);
				#ifdef DEBUG
				Serial.print("Profile Key "); 
				byteprint(profilekey, 32);
				#endif
				}
			#endif	
			} else { //there is one profile
			#ifdef STD_VERSION
				//Generate shared secret of p1hash private key and p2hash public key
				if (!okcore_flashget_profilekey(profilekey)) { // Backwards support for old key method, KEK used as master, PIN changes not supported
				Curve25519::eval(profilekey, KEK, p1hash); //shared secret stored in profilekey			
				#ifdef DEBUG
				Serial.print("Profile Key "); 
				byteprint(profilekey, 32);
				#endif
				} else { // Using new method, PIN changes supported 
				//Create KEK - Hash with nonce (flash), mask (eeprom), and chip ID (ROM)
				Curve25519::eval(temp, KEK, p1hash); //shared secret stored in profilekey			
				#ifdef DEBUG
				Serial.print("Shared Secret Profile 1");
				byteprint(temp, 32);
				#endif	
				sha256_init(&pinhash); 
				sha256_update(&pinhash, nonce2, sizeof(nonce2)); //Add mask (eeprom)
				sha256_update(&pinhash, (uint8_t*)ID, 16); //Add chip ID (ROM)
				sha256_update(&pinhash, temp, sizeof(temp)); //Add generated shared secret
				sha256_update(&pinhash, nonce, 32); //Add nonce to hash
				sha256_final(&pinhash, KEK); //Create hash and store in KEK
				okcrypto_aes_gcm_decrypt2(profilekey, (uint8_t*)ID, KEK, 32);
				#ifdef DEBUG
				Serial.print("Profile Key "); 
				byteprint(profilekey, 32);
				#endif
				}		
			#endif
			}
			integrityctr2++;
			profilemode=STDPROFILE1;
			Profile_Offset=0;
			return true; //both strings ended and all previous characters are equal 
		} else if (pass2!=guessed2){
			integrityctr2++;
			return false; //difference 
		}
		
		//read next char
		pass2 = temp[i];
		guessed2 = profilekey[i];
		integrityctr2++;
	}

	return false; //a 'true' condition has not been met
}

bool Password::profile2hashevaluate(){ 
	uint8_t p2mode;
	uint8_t temp[32];
	uint8_t KEK[32];
	uint8_t nonce2[32];
	extern uint8_t Profile_Offset;
	extern uint8_t onlykeyhw;

	size_t guesslen = strlen(guess);

	if (guesslen < 7) {
		delay (30); //Simulate time taken to hash to decrease emanation attack surface
		return false; //PIN length must be 7 - 10 digits
	}

	//Hash PIN and Nonce
	SHA256_CTX pinhash;
	sha256_init(&pinhash);
	sha256_update(&pinhash, (uint8_t *)guess, guesslen); //Add new PIN to hash
	#ifdef DEBUG
	Serial.println("GUESSED PROFILE 2 PIN");
	byteprint((uint8_t *)guess, guesslen);
	Serial.print("NONCE HASH:"); 
	byteprint(nonce, 32);
	#endif

	sha256_update(&pinhash, nonce, 32); //Add nonce to hash
	sha256_final(&pinhash, KEK); //Create hash and store in KEK
	//Generate public key of pinhash
	KEK[0] &= 0xF8;
	KEK[31] = (KEK[31] & 0x7F) | 0x40;
	//Generate public key of pinhash
	Curve25519::eval(profilekey, KEK, 0); //Generate public in profilekey

	//Hash generated public with mask (eeprom), and chip ID (ROM)
	sha256_init(&pinhash); 
	okeeprom_eeget_nonce2((uint8_t*)nonce2);
	sha256_update(&pinhash, nonce2, 16); //Add mask (eeprom)
	sha256_update(&pinhash, (uint8_t*)(ID+16), 16); //Add chip ID (ROM)
	sha256_update(&pinhash, profilekey, sizeof(profilekey)); //Add generated public to hash
	sha256_final(&pinhash, profilekey); //Create hash and store in profilekey

	//Do the same with stored public
	sha256_init(&pinhash); 
	sha256_update(&pinhash, nonce2, 16); //Add mask (eeprom)
	sha256_update(&pinhash, (uint8_t*)(ID+16), 16); //Add chip ID (ROM)
	sha256_update(&pinhash, p2hash, sizeof(p2hash)); //Add generated public to hash
	sha256_final(&pinhash, temp); //Create hash and store in profilekey

	#ifdef DEBUG
	Serial.print("Guessed Hash/PublicKey:"); 
	byteprint(profilekey, 32);
	Serial.print("Stored 2nd PIN Hash/PublicKey:"); 
	byteprint(temp, 32);
	#endif
	char pass2 = temp[0];
	char guessed2 = profilekey[0];
	for (byte i=1; i<32; i++){
		
		//check if guessed char is equal to the password char
		integrityctr1++;
		if (i == 31 && pass2==guessed2){
			okeeprom_eeget_2ndprofilemode (&p2mode); //get 2nd profile mode
			if (p2mode!=NONENCRYPTEDPROFILE) { //profile key not used for plausible deniability mode
				#ifdef STD_VERSION
				//Generate shared secret of p1hash private key and p2hash public key
				if (!okcore_flashget_profilekey(profilekey)) { // Backwards support for old key method, KEK used as master, PIN changes not supported
				Curve25519::eval(profilekey, KEK, p1hash); //shared secret stored in profilekey			
				#ifdef DEBUG
				Serial.print("Profile Key "); 
				byteprint(profilekey, 32);
				#endif
				} else { // Using new method, PIN changes supported 
				//Create KEK - Hash with nonce (flash), mask (eeprom), and chip ID (ROM)
				Curve25519::eval(temp, KEK, p1hash); //shared secret stored in profilekey			
				#ifdef DEBUG
				Serial.print("Shared Secret Profile 2");
				byteprint(temp, 32);
				#endif
				sha256_init(&pinhash); 
				sha256_update(&pinhash, nonce2, sizeof(nonce2)); //Add mask (eeprom)
				sha256_update(&pinhash, (uint8_t*)ID, 16); //Add chip ID (ROM)
				sha256_update(&pinhash, temp, sizeof(temp)); //Add generated shared secret
				sha256_update(&pinhash, nonce, 32); //Add nonce to hash
				sha256_final(&pinhash, KEK); //Create hash and store in KEK
				okcrypto_aes_gcm_decrypt2(profilekey, (uint8_t*)ID, KEK, 32);
				#ifdef DEBUG
				Serial.print("Profile Key "); 
				byteprint(profilekey, 32);
				#endif
				}
				//Set this as profile key, used to encrypt profile 2 data
				profilemode=STDPROFILE2;
				Profile_Offset=84;
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
		pass2 = temp[i];
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