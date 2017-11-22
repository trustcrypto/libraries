//
// Teensy 3.x/LC simple internal temperature
//

#include <InternalTemperature.h>

InternalTemperature temperature;

void setup()
{
  temperature.begin();

  Serial.begin(115200);
  while (!Serial);
}

void loop()
{
  Serial.print("Temperature: ");
  Serial.print(temperature.readTemperatureC(), 1);
  Serial.println("°C");
  delay(10000);
}

