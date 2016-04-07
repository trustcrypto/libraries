/* lockoutReadBack.ino; a simplistic example of using methods to lock and
unlock the security bits in Teensy 3.1 @ FTFL_FSEC's source copy.

Suggested implementation: In setup() add;

	if(FTFL_FSEC!=0x64) flashSecurityLockBits();
	
Somewhere else in the sketch/program include a method obscure enough to
protect your work from prying eyes to unlock it using similar;

	if(the_signal_i_chose==occurred) flashQuickUnlockBits();
	
This way you can lock your Teensy to the point that;

(1) The code cannot be read back by less than unlikely & extraordinary means
(2) Nothing short of a proper catastrophe will stop Teensy executing the
	code you last intended.
	

WARNING!! DANGER!!!
Setting certain values in FTFL_FSEC and then pressing the 'program' button
WILL brick your Teensy 3.1 in ways that are not recoverable, the value
0x64 is as aggressively locked as the device can be made by this register
alone and is the only value the Author tested at any great length, in terms
of being able to use the unlocking method reliably repeatedly.

*/


#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include <flashKinetis.h>


void setup() {
  //if(FTFL_FSEC!=0x64) flashSecurityLockBits();
  Serial.begin(Serial.baud());
}

elapsedMillis heartBeat;

void loop() {
  int nn;
  if(Serial.available())
  {
    switch(Serial.read()) {
    case 'a':
      Serial.print("FTFL_FSEC=0x");
      Serial.println(FTFL_FSEC,HEX);
    break;
    case 'b':
      nn=flashSecurityLockBits();
      Serial.print("Flash security bits ");
      if(nn) Serial.print("not ");
      Serial.println("written successfully");
      Serial.println("\nHit the program button to very basically reset Teensy now.");
    break;
    case 'c':
      Serial.println("By the time you read this it should be safe");
      Serial.println("to hit the program button to upload a new (or");
      Serial.println("the previous) sketch. Teensy will not be");
      Serial.println("responsive again until you do.");
      
      flashQuickUnlockBits();
    }
  }
  
  if(heartBeat>3000)
  {
    Serial.print("I am still functional, FTFL_FSEC=0x");
    Serial.print(FTFL_FSEC,HEX);
    if(FTFL_FSEC==254) Serial.print(" send the letter 'b' to lock"); else Serial.print(" send the letter 'c' to unlock");
    Serial.println(" Teensy.");
    heartBeat=0;
  }
}
