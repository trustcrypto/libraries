/*
	Arduino - Kinetis ("Teensy") Flashing Library
	(c) Frank Boesing, f.boesing@gmx.de

	License:

	Private and educational use allowed.

	If you need this library for commecial use, please
	ask me.

	In every case, keep this header.
*/


//	This example performs various tests.


#include "flashkinetis.h"

void setup()
{

	Serial.begin(9600);
	while(!Serial);
	delay(5000);

	uintptr_t adr = 0x40c;
	unsigned long data =  0xFFFFF9FE;

  
	Serial.printf("\r\nTeensy Program Flash Demo\r\n");
	Serial.printf("First empty Sector is 0x%X\r\n", flashFirstEmptySector());

	Serial.printf("Sector 0x%X is ", adr);
	if (flashCheckSectorErased((unsigned long*)adr)) Serial.printf("NOT ");
	Serial.printf("erased\r\n");

//ERASE adr

	Serial.printf("Erase Sector 0x%X ",adr);
	if (flashEraseSector((unsigned long*)adr)) Serial.printf("NOT ");
	Serial.printf("successful\r\n");

  Serial.printf("0x%X", adr);
  Serial.printf(" 0x%X", *((unsigned int*)adr));
  Serial.println();

//WRITE 0xFFFFF9FE to adr
  
	Serial.printf("Program 0x%X, value 0x%X ", adr, data);
	if ( flashProgramWord((unsigned long*)adr, &data) ) Serial.printf("NOT ");
	Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  
  
	while(1){;}
}


void loop()
{}
