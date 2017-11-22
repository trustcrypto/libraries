//
// Teensy 3.x/LC Thermometer on an ILI9341 TFT display
//
// This example goes into low speed/low power mode to give a good approximation of the air temperature.
// It uses the Snooze and ILI9341_t3 or Adafruit_ILI9341 libraries.
//
// Because low speed is too slow for USB, it requires a pushbutton reset to write a new sketch to it.
//

#include <InternalTemperature.h>

// User settings
bool useCelsius = true;

// Teensy LC can't use the optimized library
#if defined(__MKL26Z64__)
#define useOptimizedLibrary false
#else
#define useOptimizedLibrary true
#endif

#if useOptimizedLibrary
#include <ILI9341_t3.h>
#else
#include <Adafruit_ILI9341.h>
#endif

#include <Snooze.h>

// For optimized ILI9341_t3 library
#define TFT_DC      20
#define TFT_CS      21
#define TFT_RST    255  // 255 = unused, connect to 3.3V
#define TFT_MOSI    11
#define TFT_SCLK    13
#define TFT_MISO    12

#if useOptimizedLibrary
ILI9341_t3 display = ILI9341_t3(TFT_CS, TFT_DC, TFT_RST, TFT_MOSI, TFT_SCLK, TFT_MISO);
#else
Adafruit_ILI9341 display = Adafruit_ILI9341(TFT_CS, TFT_DC);
#endif

InternalTemperature temperature;

void setup()
{
  temperature.begin();

  //**********
  // Calibration can go here
  //**********

  display.begin();
  display.setRotation(3);
  display.fillScreen(ILI9341_BLACK);
  display.setTextColor(ILI9341_YELLOW, ILI9341_BLACK);
  display.setTextSize(4);

  Serial.begin(115200);

  // wait up to 1 second for USB serial port
  int startTime = millis();
  while (!Serial && (millis() - startTime < 10000));

  Serial.println("Switching to low power mode - say good-bye to USB :)");
  delay(10);
}

void loop()
{
  char scale = 'C';

  // REDUCED_CPU_BLOCK needs a SnoozeBlock passed to it
  // so we pass a dummy SnoozeBlock with no Drivers installed.
  SnoozeBlock dummyConfig;

  REDUCED_CPU_BLOCK(dummyConfig) {

    // need to call begin again to reset voltage reference
    temperature.begin(true);

    while (1) {
      // print to TFT
      display.setCursor(40,20);

      if (useCelsius) {
        display.print(temperature.readTemperatureC(), 1);
      } else {
        display.print(temperature.readTemperatureF(), 1);
        scale = 'F';    
      }

      display.print((char)247);   // degree symbol
      display.println(scale);

      // wait 10 seconds
      delay(10000);
    }
  }
}

