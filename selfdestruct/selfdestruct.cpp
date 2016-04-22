/*
||
|| @file selfdestruct.cpp
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

#include "selfdestruct.h"

//construct object in memory, set all variables
selfdestruct::selfdestruct(char* pass){
	set( pass );
	reset();
}

//set the selfdestruct
void selfdestruct::set(char* pass){
	target = pass;
}

//evaluate a string, is it equal to the selfdestruct?
bool selfdestruct::is(char* pass){ 
	byte i=0;
	while (*pass && i<MAX_selfdestruct_LENGTH){
		guess[i] = pass[i];
		i++;
	}
	return evaluate();
}

//append a char to the guessed selfdestruct
bool selfdestruct::append(char character){ 
	if (currentIndex+1==MAX_selfdestruct_LENGTH){
		return false;
	}else{
		guess[currentIndex++] = character;
		guess[currentIndex] = STRING_TERMINATOR; //ensure a valid c string
	}
	return true;
}

//reset the guessed selfdestruct, one can guess again
void selfdestruct::reset(){ 
	currentIndex = 0;
	guess[currentIndex] = STRING_TERMINATOR;
}

//is the current guessed selfdestruct equal to the target selfdestruct?
bool selfdestruct::evaluate(){ 
	char pass = target[0];
	char guessed = guess[0];
	for (byte i=1; i<MAX_selfdestruct_LENGTH; i++){
		
		//check if guessed char is equal to the selfdestruct char
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

//set selfdestruct using operator =
selfdestruct &selfdestruct::operator=(char* pass){
	set( pass );
	return *this;
}

//test selfdestruct using ==
bool selfdestruct::operator==(char* pass){
	return is( pass );
}

//test selfdestruct using !=
bool selfdestruct::operator!=(char* pass){
	return !is( pass );
}

//append to currently guessed selfdestruct using operator <<
selfdestruct &selfdestruct::operator<<(char character){
	append( character );
	return *this;
}

/*
|| @changelog
|| | 2009-06-17 - Alexander Brevig : Added assignment operator =, equality operators == != and insertion operator <<
|| | 2009-06-17 - Alexander Brevig : Initial Release
|| #
*/
