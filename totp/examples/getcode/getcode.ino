// GetCode.ino
// 
// Basic example for the TOTP library
//
// This example uses the opensource SwRTC library as a software real-time clock
// you can download from https://github.com/leomil72/swRTC
// for real implementation it's suggested the use of an hardware RTC

#include "sha1.h"
#include "TOTP.h"
#include "Time.h"

// The shared secret is MyLegoDoor
uint8_t hmacKey[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};

TOTP totp = TOTP(hmacKey, 10);
char code[7];


void setup() {
  
  Serial.begin(9600);
  
  // Adjust the following values to match the current date and time
  // and power on Arduino at the time set (use GMT timezone!)

  setTime(15, 22, 30, 6, 1, 2016);
}

void loop() {

  long GMT = now();
  char* newCode = totp.getCode(GMT);
  if(strcmp(code, newCode) != 0) {
    strcpy(code, newCode);
    Serial.println(code);
  }  
}
