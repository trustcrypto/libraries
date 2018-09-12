/*
||
|| @file Password.h
|| @version 1.2
|| @author Alexander Brevig
|| @contact alexanderbrevig@gmail.com
||
||  4/5/2012 Updates Nathan Sobieck: Nathan@Sobisource.com
||   Now v1.2 Arduino IDE v1.0 With BAckwards compatibility
||
|| 
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

#ifndef PASSWORD_H
#define PASSWORD_H

// Arduino versioning.
#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"	// for digitalRead, digitalWrite, etc
#else
#include "WProgram.h"
#endif

#define MAX_PASSWORD_LENGTH 12

#define STRING_TERMINATOR '\0'

class Password {
public:
	Password(char* pass);
	
	void set(char* pass);
	bool is(char* pass);
	bool append(char character);
	void reset();
	bool evaluate();
	bool profile1hashevaluate();
	bool sdhashevaluate();
	bool profile2hashevaluate();
	//char* getPassword();
	//char* getGuess();
	
	//operators
	Password &operator=(char* pass);
	bool operator==(char* pass);
	bool operator!=(char* pass);
	Password &operator<<(char character);
	
	char guess[ MAX_PASSWORD_LENGTH ];
	byte currentIndex;  
	
	
private:
	char* target;
	
};

#endif

/*
|| @changelog
|| | 1.1 2009-06-17 - Alexander Brevig : Added assignment operator =, equality operators == != and insertion operator <<
|| | 1.0 2009-06-17 - Alexander Brevig : Initial Release
|| #
*/
