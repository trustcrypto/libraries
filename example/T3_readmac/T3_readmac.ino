#include "T3Mac.h"

void setup() {
  delay(1000);
  Serial.begin(57600);
  
  Serial.println("Reading MAC from hardware...");
  read_mac();
  
  Serial.print("MAC: ");
  print_mac();
  Serial.println();
  
  Serial.print("Finished.");
}

void loop() {
}

