#include <avr/io.h>

void debug(uint8_t c) {
  while (!(UCSR0A & _BV(UDRE0)));
  UDR0=c;
}
void debugHH(uint8_t c) {
  debug("0123456789abcdef"[c>>4]);
  debug("0123456789abcdef"[c&15]);
}
void debugStr(char *s) {
  uint8_t c;
  while (c=*s++) debug(c);
}
