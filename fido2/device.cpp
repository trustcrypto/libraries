// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include "device.h"
#include "util.h"
#include "log.h"
#include "ctaphid.h"
#include "ctap.h"
#include "crypto.h"
#include "oku2f.h"
#include "Time.h"
#include "Adafruit_NeoPixel.h"


//#define LOW_FREQUENCY        1
//#define HIGH_FREQUENCY       0

//void wait_for_usb_tether();


uint32_t __90_ms = 0;
uint32_t __device_status = 0;
uint32_t __last_update = 0;
//extern PCD_HandleTypeDef hpcd;
static bool haveNFC = 0;
//static bool isLowFreq = 0;

#define IS_BUTTON_PRESSED()         (u2f_button == 1)

void device_set_status(uint32_t status)
{

    __last_update = millis();


    if (status != CTAPHID_STATUS_IDLE && __device_status != status)
    {
        ctaphid_update_status(status);
    }
    __device_status = status;

}

extern int u2f_button;
int device_is_button_pressed()
{
    return IS_BUTTON_PRESSED();
}

void device_reboot()
{
    NVIC_SystemReset();
}

void device_init()
{
    ctaphid_init();
    ctap_init();
}

int device_is_nfc()
{
    return haveNFC;
}


void ctaphid_write_block(uint8_t * data)
{
	Serial.println("Sending FIDO response block");
	byteprint(data, 64);
	RawHID.send(data, 100);
}

static int wink_time = 0;
static uint32_t winkt1 = 0;
#ifdef LED_WINK_VALUE
static uint32_t winkt2 = 0;
#endif
void device_wink()
{
    wink_time = 10;
    winkt1 = 0;
}

void authenticator_read_state(AuthenticatorState * a)
{
   	uint8_t buffer[sizeof(AuthenticatorState)];
	Serial.println("authenticator_read_state");
	ctap_flash (0, buffer, sizeof(AuthenticatorState), 3);
	memcpy((uint8_t*)a, buffer, sizeof(AuthenticatorState));
	byteprint(buffer,sizeof(AuthenticatorState));
}

void authenticator_read_backup_state(AuthenticatorState * a)
{
   	//This function is unnecessary, using EEPROM
   	Serial.println("authenticator_read_backup_state");
}

// Return 1 yes backup is init'd, else 0
int authenticator_is_backup_initialized()
{
    //This function is unnecessary, using EEPROM
	Serial.println("authenticator_is_backup_initialized");
	return 0;
}

void authenticator_write_state(AuthenticatorState * a, int backup)
{

	uint8_t buffer[sizeof(AuthenticatorState)];
	Serial.println("authenticator_write_state");
	memcpy(buffer, (uint8_t*)a, sizeof(AuthenticatorState));
    Serial.println("authenticator_write_state size");
    Serial.println(sizeof(AuthenticatorState));
    ctap_flash (0, buffer, sizeof(AuthenticatorState), 4);
	byteprint(buffer,sizeof(AuthenticatorState));
}

uint32_t ctap_atomic_count(int sel)
{
	uint32_t counter1 = getCounter();

    if (sel == 0)
    {
      counter1++;
	  setCounter(counter1);
      printf1(TAG_RED,"counter1: %d\n", counter1);
      return counter1;
    }
    else
    {
        printf2(TAG_ERR,"counter2 not imple\n");
        exit(1);
    }
}

void device_manage()
{
	Serial.println("device_manage");
#if NON_BLOCK_PRINTING
    int i = 10;
    uint8_t c;
    while (i--)
    {
        if (fifo_debug_size())
        {
            fifo_debug_take(&c);
            while (! LL_USART_IsActiveFlag_TXE(DEBUG_UART))
                ;
            LL_USART_TransmitData8(DEBUG_UART,c);
        }
        else
        {
            break;
        }
    }
#endif
//#ifndef IS_BOOTLOADER
	// if(device_is_nfc())
	//	nfc_loop();
//#endif
}


int ctap_user_presence_test(uint32_t wait)
{
	Serial.println("ctap_user_presence_test");
    extern Adafruit_NeoPixel pixels;
    int ret = 0;
    uint32_t t1 = millis();
    uint8_t fadevalue = 0;

    if (wait) {
        do
        {
            if (t1 + (wait*2) < millis())
            {
            return 0;
            }
            delay(1);
            if (touch_sense_loop()) u2f_button=1;
            ret = handle_packets();
            pixels.setPixelColor(0, Wheel(fadevalue & 255)); //Multicolor
            pixels.show();
            fadevalue++;
            if (ret) return ret;
        }
        while (! IS_BUTTON_PRESSED());
    }

    if(IS_BUTTON_PRESSED()) {
        u2f_button=0;
        return 1;
    } else return 0;
}

int handle_packets()
{
    uint8_t hidmsg[64];
    memset(hidmsg,0, sizeof(hidmsg));
    int n = RawHID.recv(hidmsg, 0); // 0 timeout = do not wait
    if (n) {
        if ( ctaphid_handle_packet(hidmsg) ==  CTAPHID_CANCEL)
        {
            printf1(TAG_GREEN, "CANCEL!\r\n");
            return -1;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}

int ctap_generate_rng(uint8_t * dst, size_t num)
{
    RNG2(dst, num);
	Serial.println("ctap_generate_rng");
    return 1;
}


int ctap_user_verification(uint8_t arg)
{
	Serial.println("ctap_user_verification");
    return 1;
}

void ctap_reset_rk()
{
	Serial.println("ctap_reset_rk");
	//TODO determine if we need a function that wipes all rks
}

uint32_t ctap_rk_size()
{
    Serial.println("ctap_rk_size support 5 RKs for now ");
    return 6; //support 5 RKs for now
}

void ctap_store_rk(int index,CTAP_residentKey * rk)
{
	printf1(TAG_GREEN, "storing RK %d \r\n", index);
	ctap_flash(index, (uint8_t*)rk, sizeof(CTAP_residentKey), 2);
}

void ctap_load_rk(int index,CTAP_residentKey * rk)
{
	 printf1(TAG_GREEN, "reading RK %d \r\n", index);
	ctap_flash(index, (uint8_t*)rk, sizeof(CTAP_residentKey), 1);
}

void ctap_overwrite_rk(int index,CTAP_residentKey * rk)
{

	printf1(TAG_GREEN, "overwriting RK %d \r\n", index);
	ctap_store_rk(index, rk);
}



void _Error_Handler(char *file, int line)
{
    printf2(TAG_ERR,"Error: %s: %d\r\n", file, line);
    while(1)
    {
    }
}
