// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include "device.h"
#include "onlykey.h"
#ifdef STD_VERSION
#include "util.h"
#include "log.h"
#include "ctaphid.h"
#include "ctap.h"
#include "crypto.h"
#include "Time.h"
#include "Adafruit_NeoPixel.h"


//#define LOW_FREQUENCY        1
//#define HIGH_FREQUENCY       0

//void wait_for_usb_tether();


uint32_t __90_ms = 0;
uint32_t __device_status = 0;
uint32_t __last_update = 0;
//extern PCD_HandleTypeDef hpcd;
//static int _NFC_status = 0;
//static bool isLowFreq = 0;
//static bool _RequestComeFromNFC = false;

#define IS_BUTTON_PRESSED()         (u2f_button == 1)

extern uint8_t profilemode;
extern int large_buffer_offset;
extern uint8_t* large_resp_buffer;
extern int large_resp_buffer_offset;
extern int packet_buffer_offset;
extern uint8_t recv_buffer[64];
extern uint8_t resp_buffer[64];
extern uint8_t CRYPTO_AUTH;

int u2f_button = 0;

void U2Finit()
{
  uint8_t length[2];
  device_init();
  onlykey_eeget_U2Fcertlen(length);
  int length2 = length[0] << 8 | length[1];
  if (length2 != 0) {
  extern uint16_t attestation_cert_der_size;
  attestation_cert_der_size=length2;
  onlykey_flashget_U2F();
  } else {
  byteprint((uint8_t*)attestation_key,sizeof(attestation_key));
  byteprint((uint8_t*)attestation_cert_der,sizeof(attestation_cert_der));
  }
  //DERIVEKEY(0 , (uint8_t*)attestation_key); //Derive key from default key in slot 32
  //memcpy(handlekey, ecc_private_key, 32); // Copy derived key to handlekey
  //SHA256_CTX APPKEY;
  //sha256_init(&APPKEY);
  //sha256_update(&APPKEY, (uint8_t*)attestation_cert_der+(profilemode*32), 32); //Separate U2F key for profile 1 and 2
  //sha256_update(&APPKEY, (uint8_t*)attestation_key, 32);
  //sha256_update(&APPKEY, handlekey, 32);
  //sha256_final(&APPKEY, apphandlekey); // Derivation key for app IDs
#ifdef DEBUG
  //Serial.println("HANDLE KEY =");
  //byteprint(handlekey, 32);
#endif
}

void fido_msg_timeout() {
	ctaphid_check_timeouts();
}

void recv_fido_msg(uint8_t *buffer) {
	ctaphid_handle_packet(buffer);
    memset(recv_buffer, 0, sizeof(recv_buffer));
}

void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}
void update_SHA256(const uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, message_size);
}
void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}

void store_FIDO_response (uint8_t *data, int len, bool encrypt) {
	cancelfadeoffafter20();
  if (len >= (int)LARGE_RESP_BUFFER_SIZE) return; //Double check buf overflow
	if (encrypt) {
		aes_crypto_box (data, len, false);
	} else {
    // Unencrypted message, check if it's an error message
    if (strcmp((char*)data, "Error")) {
      memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
      CRYPTO_AUTH = 0;
    } 
  }
  large_resp_buffer_offset = len;
  memmove(large_resp_buffer, data, len);
#ifdef DEBUG
      Serial.print ("Stored Data for FIDO Response");
	  byteprint(large_resp_buffer, large_resp_buffer_offset);
#endif
	 wipedata(); //Data will wait 5 seconds to be retrieved
}

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
    //return haveNFC;
    return 0;
}


void ctaphid_write_block(uint8_t * data)
{
    printf1(TAG_GREEN, "Sending FIDO response block");
	byteprint(data, 64);
	RawHID.send(data, 100);
}


void device_wink()
{
    setcolor(170); //blue
    delay(500);
}

void authenticator_read_state(AuthenticatorState * a)
{
   	uint8_t buffer[sizeof(AuthenticatorState)];
    printf1(TAG_GREEN, "authenticator_read_state");
	ctap_flash (0, buffer, sizeof(AuthenticatorState), 3);
	memcpy((uint8_t*)a, buffer, sizeof(AuthenticatorState));
	byteprint(buffer,sizeof(AuthenticatorState));
}

void authenticator_read_backup_state(AuthenticatorState * a)
{
   	//This function is unnecessary, using EEPROM
    printf1(TAG_GREEN, "authenticator_read_backup_state");
}

// Return 1 yes backup is init'd, else 0
int authenticator_is_backup_initialized()
{
    //This function is unnecessary, using EEPROM
    printf1(TAG_GREEN, "authenticator_is_backup_initialized");
	return 0;
}

void authenticator_write_state(AuthenticatorState * a, int backup)
{

	uint8_t buffer[sizeof(AuthenticatorState)];
    printf1(TAG_GREEN, "authenticator_write_state");
	memcpy(buffer, (uint8_t*)a, sizeof(AuthenticatorState));
    printf1(TAG_GREEN, "authenticator_write_state size %d\n", sizeof(AuthenticatorState));
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
    printf1(TAG_GREEN, "device_manage");
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
    printf1(TAG_GREEN, "ctap_user_presence_test");
    extern Adafruit_NeoPixel pixels;
    int ret = 0;
    uint32_t t1 = millis();
    uint8_t blink = 0;
    extern uint8_t isfade;
    

    if (wait > 750) {
        fadeon(170);

        do
        {
            if (t1 + (wait) < millis())
            {
            fadeoff(1);
            return 0;
            }
            if (touch_sense_loop()) u2f_button=1;
            ret = handle_packets();
            if (blink==0) setcolor(170);
            if (blink==128) setcolor(0);
            blink++;
            if (ret) return ret;
        }
        while (! IS_BUTTON_PRESSED());
        
    }

    if(IS_BUTTON_PRESSED()) {
        fadeoff(0);
        u2f_button=0;
        return 1;
    } else {
        return 0;
    }

}

int handle_packets()
{
    uint8_t hidmsg[64];
    memset(hidmsg,0, sizeof(hidmsg));
    int n = RawHID.recv(hidmsg, 0); 
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
    printf1(TAG_GREEN, "ctap_generate_rng");
    return 1;
}


int ctap_user_verification(uint8_t arg)
{
    printf1(TAG_GREEN, "ctap_user_verification");
    return 1;
}

void ctap_reset_rk()
{
    printf1(TAG_GREEN, "ctap_reset_rk");
    ctap_flash(NULL, NULL, NULL, 5);
}

uint32_t ctap_rk_size()
{
    printf1(TAG_GREEN, "15 RKs for now");
    return 16; //support 15 RKs for now
}

void ctap_store_rk(int index,CTAP_residentKey * rk)
{
	printf1(TAG_GREEN, "store RK %d \r\n", index);
	ctap_flash(index, (uint8_t*)rk, sizeof(CTAP_residentKey), 2);
}

void ctap_load_rk(int index,CTAP_residentKey * rk)
{
	 printf1(TAG_GREEN, "read RK %d \r\n", index);
	ctap_flash(index, (uint8_t*)rk, sizeof(CTAP_residentKey), 1);
}

void ctap_overwrite_rk(int index,CTAP_residentKey * rk)
{

	printf1(TAG_GREEN, "OVWR RK %d \r\n", index);
	ctap_store_rk(index, rk);
}

void ctap_backup_rk(int index,CTAP_residentKey * rk)
{
    /*
        unsigned int index = STATE.rk_stored;
        unsigned int i;
        for (i = 0; i < index; i++)
        {
            ctap_load_rk(i, &rk2);
            if (is_matching_rk(&rk, &rk2))
            {
                ctap_overwrite_rk(i, &rk);
                goto done_rk;
            }
        }
         */
}

void _Error_Handler(char *file, int line)
{
    printf2(TAG_ERR,"Error: %s: %d\r\n", file, line);
    while(1)
    {
    }
}

#endif
