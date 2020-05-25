/* mikey.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
    \file wolfssl/wolfcrypt/mikey.h
*/


#ifndef WOLF_CRYPT_MIKEY_H
#define WOLF_CRYPT_MIKEY_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFCRYPT_HAVE_MIKEY

#include <wolfssl/wolfcrypt/eccsi.h>
#include <wolfssl/wolfcrypt/sakke.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>

#define WOLFCRYPT_MIKEY_KMS
#define WOLFCRYPT_MIKEY_CLIENT

/** Length of a MIKEY-SAKKE UID. */
#define MIKEY_SAKKE_UID_LEN             32
/** Maximum length of an identifier. */
#define MIKEY_ID_MAX_LEN                64
/** Maximum length of text. */
#define MIKEY_TEXT_MAX_LEN              64
/** Maximum number of group identifiers in a MIKEY-SAKKE I_MESSAGE. */
#define MIKEY_GROUP_ID_MAX_CNT          255
/** Maximum length of the SSV in a MIKEY-SAKKE I_MESSAGE. */
#define MIKEY_SAKKE_SSV_MAX_LEN         1024
/** Maximum length of random in an I_MESSAGE. */
#define MIKEY_RAND_MAX_LEN              16
/** Length of the CSB-ID. */
#define MIKEY_CSB_ID_LEN                4

/** Purpose tag GMK. */
#define MIKEY_PURPOSE_GMK               0
/** Purpose tag PCK. */
#define MIKEY_PURPOSE_PCK               1
/** Purpose tag CSK. */
#define MIKEY_PURPOSE_CSK               2
/** Purpose tag SPK. */
#define MIKEY_PURPOSE_SPK               3
/** Purpose tag MKFC. */
#define MIKEY_PURPOSE_MKFC              4
/** Purpose tag MSCCK. */
#define MIKEY_PURPOSE_MSCCK             5
/** Purpose tag MuSiK. */
#define MIKEY_PURPOSE_MUSIK             6

/** MIKEY-SAKKE key type GMK. */
#define MIKEY_KEY_TYPE_GMK              0
/** MIKEY-SAKKE key type PCK. */
#define MIKEY_KEY_TYPE_PCK              1
/** MIKEY-SAKKE key type CSK. */
#define MIKEY_KEY_TYPE_CSK              2
/** MIKEY-SAKKE key type SPK. */
#define MIKEY_KEY_TYPE_SPK              3
/** MIKEY-SAKKE key type MKFC. */
#define MIKEY_KEY_TYPE_MKFC             4
/** MIKEY-SAKKE key type MSCCK. */
#define MIKEY_KEY_TYPE_MSCCK            5
/** MIKEY-SAKKE key type MuSiK. */
#define MIKEY_KEY_TYPE_MUSIK            6

/** Bit index of status with revoked information. */
#define MIKEY_STATUS_REVOKED            0
/** Bit index of status with information about sharing with gateway. */
#define MIKEY_STATUS_SHARED             1

/** Mapping crypto sessions to security protocol session using SRTP Id. */
#define MIKEY_CS_MAP_TYPE_SRTP_ID       0

#ifdef WOLFCRYPT_HAVE_ECCSI

/**
 * Data required for signing/verifying a MIKEY-SAKKE I_MESSAGE with ECCSI.
 */
typedef struct MikeyEccsi {
    /** ECCSI key.  */
    EccsiKey key;
    /** MP integer of the Secret share key (SSK). */
    mp_int ssk;
    /** ECC point of the Public Validation Token (PVT). */
    ecc_point pvt;
} MikeyEccsi;

#endif /* WOLFCRYPT_HAVE_ECCSI */

/**
 * MIKEY identifier.
 */
typedef struct MikeyId {
    /** Data of the identifier. */
    byte data[MIKEY_ID_MAX_LEN];
    /** Length of the identifier in bytes. */
    word16 sz;
} MikeyId;

/**
 * Group Identifier.
 * TS 133.180 references Clause 15.2.14 of TS 24.282.
 */
typedef struct MikeyGroupId {
    /** Destination for the data. */
    byte iei;
    /** Length of content. */
    word16 len;
    /** Content of the information. */
    byte* content;
} MikeyGroupId;

#ifdef WOLFCRYPT_HAVE_SAKKE

/**
 * MIKEY-SAKKE associated parameters.
 * TS 133.180 E.6.
 */
typedef struct MikeySakkeParams {
   /** Key purpose/type. */
   byte keyType;
   /** Status of key (revoked/shared) */
   word32 status;
   /** Time of activation. */
   time_t activation;
   /** Time of expiry. */
   time_t expiry;
   /** User-readable name associated with the key. */
   byte text[MIKEY_TEXT_MAX_LEN];
   /** Size of the text in bytes. */
   word16 textSz;
   /** All Group Identities. */
   MikeyGroupId groupId[MIKEY_GROUP_ID_MAX_CNT];
   /** Count of group identites. */
   byte groupIdCnt;
} MikeySakkeParams;

/**
 * MIKEY-SAKKE data.
 */
typedef struct MikeySakke {
    /** SAKKE key used to encapsualte or derive data. */
    SakkeKey key;

    /** UID used in encapsulating SSV withe SAKKE key.  */
    byte uid[MIKEY_SAKKE_UID_LEN];

    /** Current time. */
    time_t current;
    /** Acceptable time skew. */
    time_t skew;
    /** Receiver Secret Key (RSK). */
    ecc_point* rsk;
    /** Initiator identity. */
    MikeyId initiator;
    /** Responder identity. */
    MikeyId responder;
    /** Initiator's KMS identity. */
    MikeyId initiatorKMS;
    /** Responder's KMS identity. */
    MikeyId responderKMS;

    /** Shared Secret Value (SSV) data. */
    byte ssv[MIKEY_SAKKE_SSV_MAX_LEN];
    /** Length of Shared Secret Value (SSV) in bytes. */
    word16 ssvSz;

    /** Associated Parameters for MKEY-SAKKE I_MESSAGE. */
    MikeySakkeParams params;
   /** The SAKKE encapsulated data in the received message. */
   byte* encData;
   /** Length of SAKKE encapsulated data in bytes. */
   word16 encDataLen;
} MikeySakke;

#endif /* WOLFCRYPT_HAVE_SAKKE */

typedef struct Mikey {
#ifdef WOLFCRYPT_HAVE_SAKKE
    /** SAKKE data for encrypting/decrypting SSV. */
    MikeySakke sakke;
#endif

#ifdef WOLFCRYPT_HAVE_ECCSI
    /** ECCSI data for signing/verifying message. */
    MikeyEccsi eccsi;
#endif

    /** Bit to indicate whether a verificate message is expected or not. */
    byte v;
    /** The Pseudo-Random Function (PRF) used. */
    byte prfFunc;
    /** Crypto Session Bundle Identifier (CSB-ID) */
    byte csbId[MIKEY_CSB_ID_LEN];
    /** Number of crypto sessions that will be handled with the CBS. */
    byte csCnt;
    /** Method of mapping Crypto Sessions to security protocol sessions. */
    byte csIdMapType;
    /** Identifies crypto session(s) for which SA should be created. */
    word16 csIdMapInfo;

    /** Error message's error value. */
    byte err;

    /** Random number in MIKEY I_MESSAGE. */
    byte rand[MIKEY_RAND_MAX_LEN];
    /** Size of random number in bytes. */
    byte randSz;
} Mikey;


WOLFSSL_API int wc_InitMikey(Mikey* mikey, void* heap, int devId);
WOLFSSL_API void wc_FreeMikey(Mikey* mikey);

WOLFSSL_API int wc_ImportMikeyEccsiKey(Mikey* mikey, byte* key, word32 keySz);
WOLFSSL_API int wc_ImportMikeyEccsiPubKey(Mikey* mikey, byte* key,
        word32 keySz);
WOLFSSL_API int wc_ImportMikeySakkePubKey(Mikey* mikey, byte* key,
        word32 keySz);
WOLFSSL_API int wc_SetMikeySakkeInitiator(Mikey* mikey, byte* idri,
        word32 idriSz, byte* idrkmsi, word32 idrkmsiSz);
WOLFSSL_API int wc_SetMikeySakkeResponder(Mikey* mikey, byte* idrr,
        word32 idrrSz, byte* idrkmsr, word32 idrkmsrSz);

WOLFSSL_API int wc_GenerateMikeySakkeUid(byte* id, word16 idSz, byte* kmsId,
        word16 kmsIdSz, word32 period, byte offset, time_t msgTime, byte* uid);
WOLFSSL_API int wc_SetMikeySakkeUid(Mikey* mikey, byte* uid);

WOLFSSL_API int wc_MakeMikeyKId(Mikey* mikey, WC_RNG* rng, byte purpose);
WOLFSSL_API int wc_AddMikeySalt(Mikey* mikey);

WOLFSSL_API int wc_WriteMikeySakke(Mikey* mikey, WC_RNG* rng, time_t current,
        MikeySakkeParams* params, int toSelf, byte* msg, word32* msgSz);
WOLFSSL_API int wc_WriteMikeyError(Mikey* mikey, int error, byte* msg,
        word32* msgSz);

WOLFSSL_API int wc_ReadMikeySakke(Mikey* mikey, int responder, byte* msg,
        word32 msgSz);
WOLFSSL_API int wc_ReadMikeyError(Mikey* mikey, byte* msg, word32 msgSz);
WOLFSSL_API int wc_ReadMikey(Mikey* mikey, int responder, byte* msg,
        word32 msgSz);

WOLFSSL_API int wc_GetMikeySakkeSSV(Mikey* mikey, byte* ssv, word16* ssvSz);
WOLFSSL_API int wc_GetMikeySakkeParams(Mikey* mikey, MikeySakkeParams** params);

WOLFSSL_API int wc_DeriveMikeySrtp(Mikey* mikey, byte* tgk, word32 tgkSz,
        byte csId, byte* key, byte keySz, byte* salt, byte saltSz);

WOLFSSL_API int wc_InitMikeySakkeParams(MikeySakkeParams* params,
        byte keyType, time_t activation, time_t expiry);
WOLFSSL_API int wc_GetMikeySakkeParamsKAE(MikeySakkeParams* params,
        byte* keyType, time_t* activation, time_t* expiry);
WOLFSSL_API int wc_SetMikeySakkeParamsRevoked(MikeySakkeParams* params);
WOLFSSL_API int wc_IsMikeySakkeParamsRevoked(MikeySakkeParams* params,
        int* revoked);
WOLFSSL_API int wc_SetMikeySakkeParamsShared(MikeySakkeParams* params);
WOLFSSL_API int wc_IsMikeySakkeParamsShared(MikeySakkeParams* params,
        int* shared);
WOLFSSL_API int wc_SetMikeySakkeParamsName(MikeySakkeParams* params,
        char* name);
WOLFSSL_API int wc_GetMikeySakkeParamsName(MikeySakkeParams* params,
        char* name);
WOLFSSL_API int wc_AddMikeySakkeParamsGroupId(MikeySakkeParams* params,
        int id, byte* data, word16 len);
WOLFSSL_API int wc_GetMikeySakkeParamsGroupIdCount(MikeySakkeParams* params,
        int* count);
WOLFSSL_API int wc_GetMikeySakkeParamsGroupId(MikeySakkeParams* params, int idx,
        int* id, byte* data, word16* len);

#endif /* WOLFCRYPT_HAVE_MIKEY */

#endif /* WOLF_CRYPT_MIKEY_H */

