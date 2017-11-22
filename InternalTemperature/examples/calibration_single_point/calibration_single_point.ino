//
// Teensy 3.x/LC single point calibration example
//

#include <InternalTemperature.h>

InternalTemperature temperature;
boolean celsius = true;

void setup()
{
  float currentTemperature;

  temperature.begin();

  Serial.begin(115200);
  while (!Serial);

  Serial.print("Teensy unique id : ");
  Serial.println(temperature.getUniqueID(), HEX);

  Serial.print("Enter 1 for Celsius or 2 for Fahrenheit : ");
  while (!Serial.available());

  if (Serial.parseInt() == 2) {
    celsius = false;
  }

  Serial.println("");

  Serial.print("Enter current temperature : ");
  Serial.clear();
  while (!Serial.available());

  currentTemperature = Serial.parseFloat();

  if (celsius) {
    if (!temperature.singlePointCalibrationC(currentTemperature, temperature.readTemperatureC())) {
      Serial.println(" ERROR - invalid calibration temperature");
    }
  } else {
    if (!temperature.singlePointCalibrationF(currentTemperature, temperature.readTemperatureF())) {
      Serial.println(" ERROR - invalid calibration temperature");
    }
  }

  Serial.println("");
  Serial.println("");

  Serial.println("To make change permanent in a sketch for this Teensy, add these lines after call to temperature.begin:");
  Serial.println("");

  Serial.print("  if (temperature.getUniqueID() == 0x");
  Serial.print(temperature.getUniqueID(), HEX);
  Serial.println(") {");

  Serial.print("    temperature.setSlope(");
  Serial.print(temperature.getSlope(), 6);
  Serial.println(");");

  Serial.print("    temperature.setVTemp25(");
  Serial.print(temperature.getVTemp25(), 4);
  Serial.println(");");

  Serial.println("  }");
  Serial.println("");
}

void loop()
{
  Serial.print("Calibrated Temperature: ");
  if (celsius) {
    Serial.print(temperature.readTemperatureC(), 1);
    Serial.print("°C");
  } else {
    Serial.print(temperature.readTemperatureF(), 1);
    Serial.print("°F");
  }
  Serial.print(", Uncalibrated Temperature: ");
  if (celsius) {
    Serial.print(temperature.readUncalibratedTemperatureC(), 1);
    Serial.print("°C");
  } else {
    Serial.print(temperature.readUncalibratedTemperatureF(), 1);
    Serial.print("°F");
  }
  Serial.println("");
  delay(10000);
}

