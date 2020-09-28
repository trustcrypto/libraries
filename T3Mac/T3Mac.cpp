#include "T3MacLib.h"
//#define DEBUG


uint8_t mac[6];
unsigned long serialNum;
char ID[36];
#ifndef __MKL26Z64__
	unsigned long chipNum[4] = { SIM_UIDH, SIM_UIDMH, SIM_UIDML, SIM_UIDL };
#else
	unsigned long chipNum[4] = { 0L, SIM_UIDMH, SIM_UIDML, SIM_UIDL };
#endif

// http://forum.pjrc.com/threads/91-teensy-3-MAC-address
void read(uint8_t word, uint8_t *mac, uint8_t offset) {
	noInterrupts();
	FTFL_FCCOB0 = 0x41;             // Selects the READONCE command
	FTFL_FCCOB1 = word;             // read the given word of read once area

	// launch command and wait until complete
	FTFL_FSTAT = FTFL_FSTAT_CCIF;
	while(!(FTFL_FSTAT & FTFL_FSTAT_CCIF));

	//*(mac+offset+0)	= FTFL_FCCOB4;
	*(mac+offset+0) = FTFL_FCCOB5;
	*(mac+offset+1) = FTFL_FCCOB6;
	*(mac+offset+2) = FTFL_FCCOB7;
	interrupts();
}

void read_mac() {
	serialNum = 0L;
	read(0xe,mac,0);
	read(0xf,mac,3);
	for (uint ii = 3; ii < sizeof(mac); ii++) {
		serialNum = (serialNum << 8) + mac[ii];
	}
	//serialNum;
}

void print_mac()  {
	for(uint8_t ii = 0; ii < 6; ++ii) {
#ifdef DEBUG
		if (ii) Serial.print(": ");

		Serial.print((*(mac+ii) & 0xF0) >> 4, 16);
		Serial.print(*(mac+ii) & 0x0F, 16);
#endif
	}
}

void print_Serial()  {
#ifdef DEBUG
	Serial.printf("%lu0\n", serialNum);// PJRC standard adjustment for MAC OS
#endif
}

void print_ID()  {
#ifdef DEBUG
	Serial.println(ID);
#endif
}

void CHIP_ID() {
	sprintf(ID, "%08lX %08lX %08lX %08lX", chipNum[0], chipNum[1], chipNum[2], chipNum[3]);
}
