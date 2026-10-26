/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 *
 * This file is part of Solo.
 *
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 *
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */

#include <stdint.h>
#include "extensions.h"
#include "u2f.h"
#include "wallet.h"
#include "device.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "version.h"
#include "ok_extension.h"

#include "log.h"
//#include APP_CONFIG

// output must be at least 71 bytes
int16_t bridge_u2f_to_solo(uint8_t *_appid, uint8_t *output, uint8_t *keyh, int keylen) {
    int8_t ret = 0;

    wallet_request *req = (wallet_request *)keyh;
    extension_writeback_init(output, 71);

    printf1(TAG_WALLET, "u2f-solo [%d]: ", keylen);
    dump_hex1(TAG_WALLET, keyh, keylen);

    switch (req->operation) {
        case WalletVersion: {
            // Write back through extension_writeback() so the response length
            // is what was written. Filling output[] directly left the offset
            // at 0 and the caller fell back to a 72-byte reply, 68 bytes of
            // which were whatever the caller's buffer held before.
            uint8_t version[3] = { SOLO_VERSION_MAJ, SOLO_VERSION_MIN, SOLO_VERSION_PATCH };
            extension_writeback(version, sizeof(version));
            break;
        }
        case WalletRng: {
            printf1(TAG_WALLET, "SoloRng\n");

            uint8_t rng[71];
            ret = ctap_generate_rng(rng, sizeof(rng));
            if (ret != 1) {
                printf1(TAG_WALLET, "Rng failed\n");
                ret = CTAP2_ERR_PROCESSING;
                goto cleanup;
            }
            extension_writeback(rng, sizeof(rng));
            ret = 0;

            break;
        }

#ifdef ENABLE_WALLET
        case WalletSign:
        case WalletRegister:
        case WalletPin:
        case WalletReset:
            return bridge_to_wallet(keyh, keylen);
#endif
#ifdef ONLYKEY_SOLO
        case OKPING:
        case OKDECRYPT:
        case OKSIGN:
        //case OKGETPUBKEY:
        case OKCONNECT:
            // Size 0 means nothing written; send_stored_response() sets it.
            extension_writeback_init(output, 0);
            return bridge_to_onlykey(_appid, keyh, keylen, output);

#endif

        default:
            printf2(TAG_ERR, "Invalid wallet command: %x\n", req->operation);
            ret = CTAP1_ERR_INVALID_COMMAND;
            break;
    }

cleanup:

    return ret;
}
