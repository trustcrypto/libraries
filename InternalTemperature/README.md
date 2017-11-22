# InternalTemperature

---
The Kinetis Cortex-M processor on the Teensy 3/LC boards has a built-in temperature sensor. This library provides functions to read the temperature in both Celsius and Fahrenheit.

Here is a simple example of how to use it:
```c++
#include <InternalTemperature.h>

InternalTemperature temperature;

void setup()
{
  temperature.begin();
}

void loop()
{
  float temp = temperature.readTemperatureC();
}
```

For more details and information on calibration, see

https://github.com/LAtimes2/InternalTemperature/blob/master/InternalTemperature.pdf 
