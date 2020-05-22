/* InternalTemperature - read internal temperature of ARM processor
 * Copyright (C) 2017 LAtimes2
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission
 * notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Typical usage:
 *   InternalTemperature temperature;
 *   
 *   temperature.begin();
 *   Serial.println(temperature.readTemperatureC());
 */

#ifndef InternalTemperature_h_
#define InternalTemperature_h_
// Hardware ID
#define SIM_SDID                *(const    uint32_t *)0x40048024 // System Device Identification Register
#define SIM_SDID_PINID                  ((SIM_SDID & 0x000F) >> 0)      // Pincount identification


class InternalTemperature
{
public:
  InternalTemperature();

  //
  // Main functions
  //
  bool begin (bool lowPowerMode = false);
  float readTemperatureC (void);
  float readTemperatureF (void);

  //
  //  Calibration functions
  //
  bool singlePointCalibrationC (float actualTemperatureC, float measuredTemperatureC, bool fromDefault = false);
  bool singlePointCalibrationF (float actualTemperatureF, float measuredTemperatureF, bool fromDefault = false);

  bool dualPointCalibrationC (float actualTemperature1C, float measuredTemperature1C,
                              float actualTemperature2C, float measuredTemperature2C, bool fromDefault = false);
  bool dualPointCalibrationF (float actualTemperature1F, float measuredTemperature1F,
                              float actualTemperature2F, float measuredTemperature2F, bool fromDefault = false);

  bool setVTemp25 (float volts);
  bool setSlope (float voltsPerDegreeC);
  float getVTemp25 (void);
  float getSlope (void);
  static int getUniqueID (void);

  //
  // low level utilities
  //
  float convertTemperatureC (float volts);
  static float convertUncalibratedTemperatureC (float volts);
  static bool getHwModel (void);
  static float readRawVoltage (void);
  static float readUncalibratedTemperatureC (void);
  static float readUncalibratedTemperatureF (void);
  static float toCelsius (float temperatureFahrenheit);
  static float toFahrenheit (float temperatureCelsius);

private:
  static float convertTemperatureC (float volts, float vTemp25, float slope);

private:
  float slope;
  float vTemp25;
};

#endif
