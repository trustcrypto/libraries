#ifndef T3Mac_h
#ifdef __cplusplus

#define T3Mac_h

#include <Arduino.h>

extern uint8_t mac[6];
extern char ID[36];
extern unsigned long serialNum;
extern unsigned long chipNum[4];

void read_mac();
void print_mac();
void print_Serial();
void print_ID();
void CHIP_ID();
#endif
#endif
