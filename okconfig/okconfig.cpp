/* okconfig.cpp --- Supports transmitting and receiving config packets
*/

/*
 * Written by Tim Steiner, CryptoTrust LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "okconfig.h"
#include <Time.h>
#include "stdlib.h"
#include "Arduino.h"


const int ledPin = 13;
byte buffer[64];
unsigned int waitTimeout = 10000;
unsigned int packetCount = 0;
int label_char_index;
int n, recv_buffer;
uint32_t unixTimeStamp;

okconfig::okconfig()
{

}

void okconfig::recvmsg()
{

  label_char_index = 0;

  Serial.println(F("Waiting for packet ..."));

  n = RawHID.recv(buffer, 0);
  if (n > 0) {

    // the computer sent a message.
    Serial.print(F("Received msg, ID: "));
    Serial.println((int)buffer[0]);

    recv_buffer = (int)buffer[0];

/*https://fidoalliance.org/specs/u2f-specs-master/inc/u2f_hid.h
U2FHID native commands

#define U2FHID_PING         (TYPE_INIT | 0x01)  // Echo data through local processor only
#define U2FHID_MSG          (TYPE_INIT | 0x03)  // Send U2F message frame
#define U2FHID_LOCK         (TYPE_INIT | 0x04)  // Send lock channel command
#define U2FHID_INIT         (TYPE_INIT | 0x06)  // Channel initialization
#define U2FHID_WINK         (TYPE_INIT | 0x08)  // Send device identification wink
#define U2FHID_SYNC         (TYPE_INIT | 0x3c)  // Protocol resync command
#define U2FHID_ERROR        (TYPE_INIT | 0x3f)  // Error response

#define recvtime (TYPE_INIT | 0x62)  // First vendor defined command
#define sendlabels  (TYPE_INIT | 0x63)  
#define setslot  (TYPE_INIT | 0x64)  
*/

        switch (recv_buffer) {
              case 0x62:
                OK.recvtime();
            // statements
                break;
              case 0x63:
                OK.sendlabels();
                break;
			  case 0x64:
                OK.setslot();
                break;
              default: 
            // statements
              break;
        
    
    
    }
  
  }
  
}

void okconfig::sendlabels()
{

const char labels[][128] = {
"Google1",
"Yahoo1",
"Twitter1",
"Lastpass1",
"Dropbox1",
"Google2",
"Yahoo2",
"Twitter2",
"Lastpass2",
"Dropbox2",
"Google3",
"Yahoo3",
"Twitter3"
};
              //n = RawHID.recv(buffer, 0);
                while(n <= 0); 
                {
                    n = RawHID.recv(buffer, 0);
                      Serial.println(F("Waiting for packet ..."));
                      
                }
    // the computer sent a message.
    Serial.print(F("Received packet, first byte: "));
    Serial.println((int)buffer[0]);

    recv_buffer = (int)buffer[0] - 1;
    while(labels[recv_buffer][label_char_index] != 0){
          buffer[label_char_index + 1] = labels[recv_buffer][label_char_index];
          Serial.print("label char is: ");
          Serial.println((char) buffer[label_char_index + 1])
;
          label_char_index += 1;
        }
    
        buffer[label_char_index + 1] = 0;
    
        // put the length of the label, including \0 in the first byte
        buffer[0] = label_char_index;
    
        // fill the rest with zeros
        for (int i = label_char_index + 1; i < 64 - label_char_index; i++) {
          buffer[i] = 0;
        }
    
        // actually send the packet
        n = RawHID.send(buffer, 200);
        if (n > 0) {
          Serial.println(F("Transmit label"));
        } else {
          Serial.println(F("Unable to transmit packet"));
        }
    
        blink(2);
}

void okconfig::recvtime()
{
   	
        while(n <= 0); 
        {
        	n = RawHID.recv(buffer, 0);
                Serial.println(F("Waiting for packet ..."));
        }



   
   int i, j;    


                    
    for(i=0, j=3; i<4; i++, j--){
    unixTimeStamp |= ((uint32_t)buffer[j] << (i*8) );
    Serial.println(buffer[j], HEX);
    }
                      
    time_t t2 = unixTimeStamp;
	Serial.print(F("Received Unix Epoch Time: "));
    Serial.println(unixTimeStamp, HEX); 
    setTime(t2); 
	Serial.print(F("Current Time Set to: "));
    digitalClockDisplay();  
            
 }

 void okconfig::setslot()
{
 
 int i, slot_num, buf_size; 
 int data_buffer[32];
 Serial.println("Test");
 delay(1000);
    while(n <= 0); 
        {
        	n = RawHID.recv(buffer, 0);
                Serial.println(F("Waiting for packet ..."));
        }
    // the computer sent the slot number
    Serial.print("Received slot number: ");
    Serial.println((int)buffer[0]);
    slot_num = (int)buffer[0];
	

        while(n <= 0); 
        {
        	n = RawHID.recv(buffer, 0);
                Serial.println(F("Waiting for packet ..."));
        }
    // the computer sent the size of the value to set
    Serial.print("Received size: ");
    Serial.println((int)buffer[0]);
    buf_size = (int)buffer[0];
	

        while(n <= 0); 
        {
        	n = RawHID.recv(buffer, 0);
                Serial.println(F("Waiting for packet ..."));
        }
    // the computer sent the value
	
    Serial.print("Received value to set: ");
	
    for(i=0; i<buf_size; i++){
    data_buffer[i] = buffer[i];
    Serial.println(buffer[i], HEX);
    }

    return;        
 }
void okconfig::digitalClockDisplay(){
  // digital clock display of the time
  Serial.print(hour());
  OK.printDigits(minute());
  OK.printDigits(second());
  Serial.print(" ");
  Serial.print(day());
  Serial.print(" ");
  Serial.print(month());
  Serial.print(" ");
  Serial.print(year()); 
  Serial.println(); 
}

void okconfig::printDigits(int digits){
  // utility function for digital clock display: prints preceding colon and leading 0
  Serial.print(":");
  if(digits < 10)
    Serial.print('0');
  Serial.print(digits);
}

void okconfig::blink(int times){
  
  int i;
  for(i = 0; i < times; i++){
    digitalWrite(ledPin, HIGH);
    delay(100);
    digitalWrite(ledPin, LOW);
    delay(100);
  }
}

bool okconfig::exists = false;

okconfig OK = okconfig(); // create an instance for the user





