/* Tim Steiner
 * Copyright (c) 2015-2018, CryptoTrust LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (http://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "OnlyKey Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" or "CryptoTrust" appear in their names without
 *    specific prior written permission. For written permission, please
 *    contact admin@crp.to.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (http://www.crp.to/ok)"
 *
 * 7. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for this software and any
 *    accompanying software that uses this software. The source code
 *    must either be included in the distribution or be available for
 *    no more than the cost of distribution plus a nominal fee, and must
 *    be freely redistributable under reasonable conditions. For a
 *    binary file, complete source code means the source code for all
 *    modules it contains.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS
 * ARE GRANTED BY THIS LICENSE. IF SOFTWARE RECIPIENT INSTITUTES PATENT
 * LITIGATION AGAINST ANY ENTITY (INCLUDING A CROSS-CLAIM OR COUNTERCLAIM
 * IN A LAWSUIT) ALLEGING THAT THIS SOFTWARE (INCLUDING COMBINATIONS OF THE
 * SOFTWARE WITH OTHER SOFTWARE OR HARDWARE) INFRINGES SUCH SOFTWARE
 * RECIPIENT'S PATENT(S), THEN SUCH SOFTWARE RECIPIENT'S RIGHTS GRANTED BY
 * THIS LICENSE SHALL TERMINATE AS OF THE DATE SUCH LITIGATION IS FILED. IF
 * ANY PROVISION OF THIS AGREEMENT IS INVALID OR UNENFORCEABLE UNDER
 * APPLICABLE LAW, IT SHALL NOT AFFECT THE VALIDITY OR ENFORCEABILITY OF THE
 * REMAINDER OF THE TERMS OF THIS AGREEMENT, AND WITHOUT FURTHER ACTION
 * BY THE PARTIES HERETO, SUCH PROVISION SHALL BE REFORMED TO THE MINIMUM
 * EXTENT NECESSARY TO MAKE SUCH PROVISION VALID AND ENFORCEABLE. ALL
 * SOFTWARE RECIPIENT'S RIGHTS UNDER THIS AGREEMENT SHALL TERMINATE IF IT
 * FAILS TO COMPLY WITH ANY OF THE MATERIAL TERMS OR CONDITIONS OF THIS
 * AGREEMENT AND DOES NOT CURE SUCH FAILURE IN A REASONABLE PERIOD OF
 * TIME AFTER BECOMING AWARE OF SUCH NONCOMPLIANCE. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR  PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "device.h"
#include "onlykey.h"
#ifdef STD_VERSION
#include "log.h"
#include "wallet.h"
//#include APP_CONFIG
#include "util.h"
#include "storage.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "crypto.h"
#include "u2f.h"
#include "extensions.h"
#include "ok_extension.h"

// Functions for use with derived key (RESERVED_KEY_WEB_DERIVATION)
#define DERIVE_PUBLIC_KEY 1
#define DERIVE_SHAREDSEC 2
#define DERIVE_OPCODE_MAX DERIVE_SHAREDSEC
// Option to encrypt response for end-to-end data in-transit encryption
#define NO_ENCRYPT_RESP 0
#define ENCRYPT_RESP 1

extern uint8_t *large_resp_buffer;
extern int large_resp_buffer_offset;
extern int large_resp_buffer_cursor;
extern uint8_t large_resp_buffer_last_opt3;
// Largest payload per response: sigder[514] holds a status byte and the
// payload, and sigder_sz must stay below sizeof(sigder).
#define MAX_LARGE_RESP_CHUNK 512
extern uint8_t profilemode;
extern uint8_t isfade;
extern uint8_t NEO_Color;
extern uint8_t type;
extern uint8_t CRYPTO_AUTH;
extern int outputmode;
extern uint8_t ecc_public_key[(MAX_ECC_KEY_SIZE * 2) + 1];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
extern uint8_t recv_buffer[64];
extern uint8_t pending_operation;
extern int packet_buffer_offset;
extern uint8_t packet_buffer_details[5];

// Confirmation for slot-128 shared-secret derives, set by field 30:
// 0 = challenge code, 1 = button press, 2 = none. The challenge code is
// bytes 0/15/31 of SHA-256(label hash | input public key), mod 6 (mod 3 on
// a DUO) plus one; the web app shows the same code.
static int web_agent_derive_gate(uint8_t floor_mode, const uint8_t *data, int len) {
    extern uint8_t onlykeyhw;
    uint8_t need = okcore_web_agent_derive_mode();
    // floor_mode: the minimum confirmation the caller requires.
    if (need == USER_INPUT_NONE && floor_mode != USER_INPUT_NONE) need = floor_mode;
    if (need == USER_INPUT_NONE) return 0;
    int but;
    device_set_status(CTAPHID_STATUS_UPNEEDED);
    if (need == USER_INPUT_PRESS) {
        but = ctap_user_presence_test(CTAP2_UP_DELAY_MS);
    } else {
        uint8_t h[32];
        SHA256_CTX c;
        sha256_init(&c);
        sha256_update(&c, (uint8_t *)data, len);
        sha256_final(&c, h);
        uint8_t m = (onlykeyhw == OK_HW_DUO) ? 3 : 6;
        but = ctap_challenge_test(CTAP2_UP_DELAY_MS, (h[0] % m) + 1, (h[15] % m) + 1, (h[31] % m) + 1);
        memset(h, 0, 32);
    }
    if (but == -2) {
        pending_operation = 0;
        return CTAP2_ERR_OPERATION_DENIED;
    }
    if (but > 1) return CTAP2_ERR_PROCESSING;
    if (but < 0) return CTAP2_ERR_KEEPALIVE_CANCEL;
    if (but == 0) {
        pending_operation = 0;
        return CTAP2_ERR_ACTION_TIMEOUT;
    }
    return 0;
}
uint8_t transit_key[32];

// Duplicate-packet suppression for inbound OKDECRYPT/OKSIGN requests
// (Windows 10 1903 sends each FIDO2 request twice): highest opt3 seen for
// the message in progress.
static uint8_t last_request_opt3 = 0;


/* Bytes of `keyh` consumed by the OnlyKey request header before the payload:
 * cmd, opt1, opt2, opt3, then the 4-byte wallet tag and 2 more. */
#define OK_KEYHANDLE_HEADER_LEN 10

int16_t bridge_to_onlykey(uint8_t *_appid, uint8_t *keyh, int handle_len, uint8_t *output) {
    int8_t ret = 0;
    uint8_t client_handle[256];

    if (handle_len < OK_KEYHANDLE_HEADER_LEN || handle_len > (int)sizeof(client_handle)) {
#ifdef DEBUG
        Serial.print("Rejecting keyhandle of length ");
        Serial.println(handle_len, DEC);
#endif
        return 0;
    }
    handle_len -= OK_KEYHANDLE_HEADER_LEN;
    uint8_t cmd = keyh[0];
    uint8_t opt1 = keyh[1];
    uint8_t opt2 = keyh[2];
    uint8_t opt3 = keyh[3];
    uint8_t browser;
    uint8_t os;
    uint8_t temp[256];
    uint8_t pubsize = 0;

    memcpy(client_handle, keyh + OK_KEYHANDLE_HEADER_LEN, handle_len);

#ifdef DEBUG
    Serial.println("Keyhandle:");
    byteprint(client_handle, handle_len);
#endif

    const int wc_level = webcryptcheck(_appid, client_handle);
    if (wc_level) {
        outputmode = DISCARD; // Discard output
        if (cmd == OKCONNECT && !CRYPTO_AUTH) {
            large_buffer_offset = 0;
            // Set time if not already set
            set_time(client_handle);
            memset(ecc_public_key, 0, sizeof(ecc_public_key));
            // Generate a random NACL key that we will use for data in transit encryption OnlyKey <--> Web App
            // This is optional and enabled by ENCRYPT_RESP
            // crypto_box_keypair uses RNG2 to create random 32 byte private
            // crypto_box_keypair puts generated private in ecc_private_key and public in ecc_public_key along with OnlyKey version info
            crypto_box_keypair(ecc_public_key, ecc_private_key); //Generate keys
#ifdef DEBUG
            Serial.println("OnlyKey public = ");
            byteprint(ecc_public_key, 32);
#endif
            memcpy(ecc_public_key + 32, HW_MODEL(UNLOCKED), sizeof(UNLOCKED) + 1);
            // Response goes out via WEBAUTHN
            outputmode = WEBAUTHN;
            memcpy(temp, ecc_public_key, sizeof(ecc_public_key)); //Store OnlyKey public NACL transit key (includes OnlyKey version info)
            memcpy(ecc_public_key, client_handle + 9, 32); //Get app public NACL transit key
            browser = client_handle[9 + 32];
            os = client_handle[9 + 32 + 1];
#ifdef DEBUG
            Serial.println("App public = ");
            byteprint(ecc_public_key, 32);
            Serial.print("Browser = ");
            Serial.println((char)browser);
            Serial.print("OS = ");
            Serial.println((char)os);
#endif
            //NACL for transit encryption, this setting isn't currently user configurable
            type = 1;
            if (okcrypto_shared_secret(ecc_public_key, transit_key)) {
                ret = CTAP2_ERR_OPERATION_DENIED;
                printf2(TAG_ERR, "Error with ECC Shared Secret\n");
                return ret;
            }
#ifdef DEBUG
            Serial.println("Transit Shared Secret = ");
            byteprint(transit_key, 32);
#endif
            // Hash the shared secret to generate the AES transit private key
            SHA256_CTX context;
            sha256_init(&context);
            sha256_update(&context, transit_key, 32);
            sha256_final(&context, transit_key);
            okcrypto_transit_reset();
#ifdef DEBUG
            Serial.println("Transit AES Key = ");
            byteprint(transit_key, 32);
#endif
            pending_operation = CTAP2_ERR_DATA_READY;
            // OnlyKey Private Web (beta)
            // Keys derived from the slot-128 key and the caller's 32-byte label
            // (HKDF). The origin is not an input, so every trusted origin gets
            // the same key for a label.
            if (opt1 >= DERIVE_PUBLIC_KEY) {
                if (opt1 > DERIVE_OPCODE_MAX) {
                    ret = CTAP2_ERR_EXTENSION_NOT_SUPPORTED;
                    wipedata();
                    return ret;
                }
                if (opt3) opt3 = 2; // 1=encrypt everything, 2=encrypt everything except transit public so app can derive shared secret
                uint8_t *input_pubkey = client_handle + 43 + 32; // Use uncompressed ecc pubkeys, could use compressed in future
                uint8_t additional_data[33] = {0};
                memcpy(additional_data + 1, client_handle + 43, 32); // 32 bytes of data to include in key derivation
                opt2++;
                memset(ecc_public_key, 0, sizeof(ecc_public_key));

                // X-Wing: DERIVE_PUBLIC_KEY returns pk_M(1184) | pk_X(32) through
                // large_resp_buffer. Decapsulation needs the 1120-byte ciphertext,
                // so it goes through OKDECRYPT on slot 128 (okcrypto_decrypt()).
                if (opt2 == KEYTYPE_XWING) {
                    uint8_t *label32 = client_handle + 43;
                    if (opt1 == DERIVE_SHAREDSEC) {
                        hidprint("Error use OKDECRYPT for derived X-Wing decapsulation");
                        ret = send_stored_response(output, opt3);
                        return ret;
                    }
                    const int hdr = 32 + sizeof(UNLOCKED) + 1;
                    memmove(large_resp_buffer, temp, hdr); /* transit pubkey + status */
#ifdef DEBUG
                    Serial.print("XWING derive start ms=");
                    Serial.println(millis());
#endif
                    okcrypto_xwing_derive_getpubkey(label32, large_resp_buffer + hdr);
#ifdef DEBUG
                    Serial.print("XWING derive done ms=");
                    Serial.print(millis());
                    Serial.print(" hdr=");
                    Serial.print(hdr);
                    Serial.print(" total=");
                    Serial.println(hdr + XWING_PK_SIZE);
#endif
                    send_transport_response(large_resp_buffer, hdr + XWING_PK_SIZE, opt3, false);
                    ret = send_stored_response(output, opt3);
#ifdef DEBUG
                    Serial.print("XWING derive ret=");
                    Serial.print(ret);
                    Serial.print(" staged=");
                    Serial.print(large_resp_buffer_offset);
                    Serial.print(" cursor=");
                    Serial.println(large_resp_buffer_cursor);
#endif
                    return ret;
                }

                //Similar format to SSH derivation but use RESERVED_KEY_WEB_DERIVATION key
                if (opt2 == KEYTYPE_NACL || opt2 == KEYTYPE_CURVE25519) {
                    okcrypto_derive_key(KEYTYPE_CURVE25519, additional_data, RESERVED_KEY_WEB_AGENT_DERIVATION); //Curve25519
                    pubsize = 32;
                } else if (opt2 == KEYTYPE_P256R1) {
                    okcrypto_derive_key(KEYTYPE_P256R1, additional_data, RESERVED_KEY_WEB_AGENT_DERIVATION);
                    memmove(ecc_public_key + 1, ecc_public_key, 64);
                    ecc_public_key[0] = 4;
                    pubsize = 65;
                } else if (opt2 == KEYTYPE_P256K1) {
                    okcrypto_derive_key(KEYTYPE_P256K1, additional_data, RESERVED_KEY_WEB_AGENT_DERIVATION);
                    memmove(ecc_public_key + 1, ecc_public_key, 64);
                    ecc_public_key[0] = 4;
                    pubsize = 65;
                } else {
                    ret = CTAP2_ERR_UNSUPPORTED_ALGORITHM;
                    wipedata();
                    return ret;
                }

                // Derived private key stored in ecc_private_key
                // Derived public key stored in ecc_public_key

                memcpy(temp + 32 + sizeof(UNLOCKED) + 1, ecc_public_key, pubsize); // Copy derived public key to temp

#ifdef DEBUG
                Serial.println("Returned Public");
                byteprint(ecc_public_key, pubsize);
                Serial.println("Derived Private");
                byteprint(ecc_private_key, sizeof(ecc_private_key));
#endif

                if (opt1 == DERIVE_SHAREDSEC) { // Return DERIVE_PUBLIC_KEY and DERIVE_SHAREDSEC
#ifdef DEBUG
                    Serial.println("Input Pubkey");
                    byteprint(input_pubkey, pubsize);
#endif
                    if (os == 'W' && packet_buffer_details[3] == 'W') {
                        // Already generated shared secret, Windows duplicate request
                        packet_buffer_details[3] = 0;
                        ret = send_stored_response(output, opt3);
                        return ret;
                    } else {
                        // Generate Shared Secret
                        {
                            int g = web_agent_derive_gate(USER_INPUT_NONE, client_handle + 43, 32 + pubsize);
                            if (g) return g;
                            if (os == 'W') packet_buffer_details[3] = 'W';
                        }
                        // Use ecc_private_key and provided pubkey to generate shared secret
                        if (okcrypto_shared_secret(input_pubkey, temp + 32 + sizeof(UNLOCKED) + 1 + pubsize)) { // Generate derived key shared secret in temp
                            ret = CTAP2_ERR_OPERATION_DENIED;
                            printf2(TAG_ERR, "Error with ECC Shared Secret\n");
                            return ret;
                        }
#ifdef DEBUG
                        Serial.println("Shared Secret");
                        byteprint(temp + 32 + sizeof(UNLOCKED) + 1 + pubsize, 32);
#endif
                        send_transport_response(temp, 32 + sizeof(UNLOCKED) + 1 + pubsize + sizeof(ecc_private_key), opt3, false); // Encrypt data in trasit using transit key if opt3 and send right away
                        ret = send_stored_response(output, opt3);
                        return ret;
                    }
                } else { // Just Return DERIVE_PUBLIC_KEY
                    send_transport_response(temp, 32 + sizeof(UNLOCKED) + 1 + pubsize, opt3, false); //Encrypt if opt3 and send right away
                    ret = send_stored_response(output, opt3);
                    return ret;
                }
            } else {
                send_transport_response(temp, 32 + sizeof(UNLOCKED) + 1, opt3, false); //Encrypt if opt3 and send right away
            }
        } else if (wc_level) { // Protected mode, only allow crp.to and localhost
            //Todo add localhost support
            // Transit v2: [counter(4)][ciphertext][tag(16)], authenticated before
            // use. On success the plaintext is at the front of client_handle and
            // handle_len is its length.
            {
                int ptlen = okcrypto_transit_open(client_handle, handle_len);
                if (ptlen < 0) {
                    // Failed authentication: dispatch nothing. Stage an error only when
                    // no result or operation is pending, so a duplicate request
                    // cannot replace a staged result.
                    if (!large_resp_buffer_offset && !CRYPTO_AUTH &&
                        pending_operation != CTAP2_ERR_OPERATION_PENDING) {
                        outputmode = WEBAUTHN;
                        hidprint("Error message failed authentication");
                    }
                    ret = send_stored_response(output, opt3);
                    return ret;
                }
                handle_len = ptlen;
            }
#ifdef DEBUG
            Serial.println("Decrypted client handle");
            byteprint(client_handle, handle_len);
            Serial.println("Received FIDO2 request to send data to OnlyKey");
#endif

            if (cmd == OKPING) { //Ping
                outputmode = WEBAUTHN;
                if (!CRYPTO_AUTH && !large_resp_buffer_offset) {
#ifdef DEBUG
                    Serial.println("Error incorrect challenge was entered");
#endif
                    hidprint("Error incorrect challenge was entered");
                } else {
#ifdef DEBUG
                    Serial.println("Sending stored data from ping request");
#endif
                }
            }
            // Break the FIDO message into packets
            else if (!CRYPTO_AUTH) {
                // Slot 128 (derived X-Wing decapsulation) needs level 1; any other slot
                // is a stored key and needs level 2.
                if (wc_level < 2 && opt1 != RESERVED_KEY_WEB_AGENT_DERIVATION) {
#ifdef DEBUG
                    Serial.println("Stored-key operations over FIDO2 are disabled");
#endif
                    // Report the error to the browser.
                    outputmode = WEBAUTHN;
                    hidprint("Error stored key use over FIDO2 not enabled");
                    ret = send_stored_response(output, opt3);
                    return ret;
                }
                int i = 0;
                if (!last_request_opt3) {
                    last_request_opt3 = opt3; // first packet
                    if (cmd == OKDECRYPT || cmd == OKSIGN) {
                        memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
                        large_resp_buffer_offset = 0;
                        large_resp_buffer_cursor = 0;
                        large_resp_buffer_last_opt3 = 0;
                    }
                } else if (opt3 <= last_request_opt3)
                    return 0; // duplicate packet, thanks to win 10 1903 sending all FIDO2 messages twice

                while (handle_len > 0) { // Max size packet minus header
                    memset(recv_buffer, 0, sizeof(recv_buffer));
                    if (handle_len >= 57)
                        memmove(recv_buffer + 7, client_handle + (i * 57), 57);
                    else
                        memmove(recv_buffer + 7, client_handle + (i * 57), handle_len);
                    memset(recv_buffer, 0xFF, 4);
                    recv_buffer[4] = cmd;
                    recv_buffer[5] = opt1; //slot
                    recv_buffer[6] = 0xFF;
                    if (opt2 && handle_len <= 57) recv_buffer[6] = handle_len; // last packet
                    if (cmd == OKDECRYPT) {
                        last_request_opt3 = opt3;
                        NEO_Color = 128; //Turquoise
                        large_buffer_offset = 0;
                        outputmode = WEBAUTHN;
#ifdef DEBUG
                        Serial.println("OKDECRYPT Chunk");
                        byteprint(recv_buffer, 64);
#endif
                        okcrypto_decrypt(recv_buffer);
                    } else if (cmd == OKSIGN) {
                        last_request_opt3 = opt3;
                        NEO_Color = 213; //Purple
                        large_buffer_offset = 0;
                        outputmode = WEBAUTHN;
#ifdef DEBUG
                        Serial.println("OKSIGN Chunk");
                        byteprint(recv_buffer, 64);
#endif
                        okcrypto_sign(recv_buffer);
                    }
                    handle_len -= 57;
                    i++;
                }
                // Last chunk: reset duplicate detection.
                if (opt2) last_request_opt3 = 0;
                ret = 0;
            }
        }
        ret = send_stored_response(output, opt3);
        return ret;

        //if (!isfade) fadeon(NEO_Color);
    }

    ret = CTAP2_ERR_EXTENSION_NOT_SUPPORTED; //APPID doesn't match
    wipedata();
    return ret;
}

int16_t send_stored_response(uint8_t *output, uint8_t opt3) {
    int16_t ret = 0;
    if (profilemode != NONENCRYPTEDPROFILE) {
#ifdef DEBUG
        Serial.print("Sending data on OnlyKey via Webauthn ");
        Serial.println(large_resp_buffer_offset);
#endif
#ifdef DEBUG_BULK_DUMPS
        byteprint(large_resp_buffer, large_resp_buffer_offset);
#endif
        // Check if large response is ready
        if (pending_operation == CTAP2_ERR_OPERATION_PENDING) {
#ifdef DEBUG
            Serial.print("CTAP2_ERR_OPERATION_PENDING");
#endif
            ret = CTAP2_ERR_OPERATION_PENDING;
        } else if (large_resp_buffer_offset) {
            int delivered = large_resp_buffer_cursor >= large_resp_buffer_offset;
            int is_duplicate = delivered || (opt3 && large_resp_buffer_last_opt3 && opt3 <= large_resp_buffer_last_opt3);
            int chunk_start = large_resp_buffer_cursor;
            if (is_duplicate && large_resp_buffer_cursor)
                chunk_start = (large_resp_buffer_cursor - 1) / MAX_LARGE_RESP_CHUNK * MAX_LARGE_RESP_CHUNK;
            int remaining = large_resp_buffer_offset - chunk_start;
            int chunk_len = remaining > MAX_LARGE_RESP_CHUNK ? MAX_LARGE_RESP_CHUNK : remaining;
#ifdef DEBUG
            Serial.print("chunk opt3=");
            Serial.print(opt3);
            Serial.print(" last=");
            Serial.print(large_resp_buffer_last_opt3);
            Serial.print(" dup=");
            Serial.print(is_duplicate);
            Serial.print(" start=");
            Serial.print(chunk_start);
            Serial.print(" len=");
            Serial.print(chunk_len);
            Serial.print(" of=");
            Serial.println(large_resp_buffer_offset);
#endif
            extension_writeback_init(output, chunk_len);
            extension_writeback(large_resp_buffer + chunk_start, chunk_len);
            if (!is_duplicate) {
                large_resp_buffer_cursor = chunk_start + chunk_len;
                large_resp_buffer_last_opt3 = opt3;
            }
            // Windows 10 1903 bug, it sends every fido2 request/response twice
            // Everything happens twice, and the computer only pays attention to the 2nd request/response.
            // This means we can't wipe the response after it's retrieved, have to wipe
            // based on a timer
            //memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
            if (is_duplicate) return ret;
            wipedata(); // restarts the wipe timer
            if (large_resp_buffer_cursor >= large_resp_buffer_offset) {
                pending_operation = CTAP2_ERR_DATA_WIPE;
            }
        } else if (CRYPTO_AUTH || packet_buffer_offset) {
#ifdef DEBUG
            Serial.println("Ping success");
#endif
            memset(large_resp_buffer, 0, LARGE_RESP_BUFFER_SIZE);
            ret = CTAP2_ERR_USER_ACTION_PENDING;
        } else if (!CRYPTO_AUTH) {
#ifdef DEBUG
            Serial.print("Error no data ready to be retrieved");
#endif
            //custom_error(6);
            ret = CTAP2_ERR_NO_OPERATION_PENDING;
            fadeoff(1);
        }
        return ret;
    }
    return ret;
}

#endif
