/* mikey.c
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



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFCRYPT_HAVE_MIKEY

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mikey.h>

#ifdef WOLFCRYPT_MIKEY_CLIENT
/**
 * Initialize MIKEY object.
 *
 * Must be called before performing any operations.
 * Free the MIKEY object with wc_FreeMikey() when no longer needed.
 *
 * @param  [in]  mikey  MIKEY object.
 * @param  [in]  heap   Heap hint.
 * @param  [in]  devId  Device identifier.
 *                      Use INVALID_DEVID when no device used.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
int wc_InitMikey(Mikey* mikey, void* heap, int devId)
{
    int err = 0;

    if (mikey == NULL) {
        err = BAD_FUNC_ARG;
    }
    if (err == 0) {
        XMEMSET(mikey, 0, sizeof(*mikey));

#ifdef WOLFCRYPT_HAVE_ECCSI
        err = wc_InitEccsiKey(&mikey->eccsi.key, heap, devId);
#endif
    }
#ifdef WOLFCRYPT_HAVE_SAKKE
    if (err == 0) {
        err = wc_InitSakkeKey(&mikey->sakke.key, heap, devId);
    }
#endif

    return err;
}

/**
 * Free MIKEY object.
 *
 * Must be called when finished with the MIKEY object.
 *
 * @param  [in]  mikey  MIKEY object.
 */
void wc_FreeMikey(Mikey* mikey)
{
    if (mikey != NULL) {
#ifdef WOLFCRYPT_HAVE_SAKKE
        wc_FreeSakkeKey(&mikey->sakke.key);
#endif
#ifdef WOLFCRYPT_HAVE_ECCSI
        wc_FreeEccsiKey(&mikey->eccsi.key);
#endif
    }
}

#ifdef WOLFCRYPT_HAVE_ECCSI
/**
 * Import an ECCSI key from a binary encoding.
 *
 * @param  [in]  mikey  MIKEY object.
 * @param  [in]  key    Binary encoded ECCSI key.
 * @param  [in]  keySz  Length of binary encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or key is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
int wc_ImportMikeyEccsiKey(Mikey* mikey, byte* key, word32 keySz)
{
    int err = 0;

    if ((mikey == NULL) || (key == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = wc_ImportEccsiKey(&mikey->eccsi.key, key, keySz);
    }

    return err;
}

/**
 * Import an ECCSI public key from a binary encoding.
 *
 * @param  [in]  mikey  MIKEY object.
 * @param  [in]  key    Binary encoded ECCSI public key.
 * @param  [in]  keySz  Length of binary encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or key is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
int wc_ImportMikeyEccsiPubKey(Mikey* mikey, byte* key, word32 keySz)
{
    int err = 0;

    if ((mikey == NULL) || (key == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = wc_ImportEccsiPublicKey(&mikey->eccsi.key, key, keySz);
    }

    return err;
}
#endif
#endif

#ifdef WOLFCRYPT_HAVE_SAKKE
/**
 * Import a SAKKE public key from a binary encoding.
 *
 * @param  [in]  mikey  MIKEY object.
 * @param  [in]  key    Binary encoded SAKKE public key.
 * @param  [in]  keySz  Length of binary encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or key is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
int wc_ImportMikeySakkePubKey(Mikey* mikey, byte* key, word32 keySz)
{
    int err = 0;

    if ((mikey == NULL) || (key == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = wc_ImportSakkePublicKey(&mikey->sakke.key, key, keySz);
    }

    return err;
}
#endif

#ifdef WOLFCRYPT_MIKEY_KMS

#ifdef WOLFCRYPT_HAVE_SAKKE

/* Prefx to all UID hash calculations.
 * 3GPP TS 133 180 - F.2.1.1.
 *   FC = 0x00
 *   P0 = "MIKEY-SAKKE-UID"
 *   L0 = 15 -> 0x00, 0x0f
 */
static const byte uidHashPrefix[] = {
    0x00, 0x4d, 0x49, 0x4b, 0x45, 0x59, 0x2d, 0x53, 0x41, 0x4b,
    0x4b, 0x45, 0x2d, 0x55, 0x49, 0x44, 0x00, 0x0f
};
/* Size of UID hash prefix in bytes. */
#define UID_HASH_PREFIX_SZ    sizeof(uidHashPrefix)

/**
 * Generates the Mikey-Sakke UID.
 * 3GPP TS 133 180 - F.2.1.1.
 *
 * @param  [in]  id        Identity of initiator data.
 * @param  [in]  idSz      Size of identity in bytes.
 * @param  [in]  kmsId     KMS Identfier data.
 * @param  [in]  kmsSz     Size of KMS identifier in bytes.
 * @param  [in]  period    Key period length in seconds. (3 bytes worth of value
 *                         used.)
 * @param  [in]  offset    Key perioud offset in seconds.
 * @param  [in]  current   Current time to generate UID for.
 * @param  [in]  uid       Buffer to hold generated UID. Must be able to hold 32
 *                         bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when id, kmsId or uid is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
int wc_GenerateMikeySakkeUid(byte* id, word16 idSz, byte* kmsId, word16 kmsIdSz,
        word32 period, byte offset, time_t current, byte* uid)
{
    int err = 0;
    Sha256 sha256;
    word16 periodNum;
    byte len[2];
    byte periodEnc[3];
    byte one[2] = {0, 1};
    byte two[2] = {0, 2};

    if ((id == NULL) || (kmsId == NULL) || (uid == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = wc_InitSha256_ex(&sha256, NULL, INVALID_DEVID);
    }
    /* FC || P0 || L0 */
    if (err == 0) {
        err = wc_Sha256Update(&sha256, uidHashPrefix, UID_HASH_PREFIX_SZ);
    }
    /* P1 = Identifier */
    if (err == 0) {
        err = wc_Sha256Update(&sha256, id, idSz);
    }
    /* L1 = Length of Identifier */
    if (err == 0) {
        c16toa(idSz, len);
        err = wc_Sha256Update(&sha256, len, sizeof(len));
    }
    /* P2 = KMS Identifier */
    if (err == 0) {
        err = wc_Sha256Update(&sha256, kmsId, kmsIdSz);
    }
    /* L1 = Length of KMS Identifier */
    if (err == 0) {
        c16toa(kmsIdSz, len);
        err = wc_Sha256Update(&sha256, len, sizeof(len));
    }
    /* P3 = Key Period length in seconds */
    if (err == 0) {
        c32to24(period, periodEnc);
        err = wc_Sha256Update(&sha256, periodEnc, sizeof(periodEnc));
    }
    /* L3 = Length of Key Period length */
    if (err == 0) {
        c16toa(sizeof(periodEnc), len);
        err = wc_Sha256Update(&sha256, len, sizeof(len));
    }
    /* P4 = Key Period offset in seconds */
    if (err == 0) {
        err = wc_Sha256Update(&sha256, &offset, 1);
    }
    /* L4 = Length of Key Period offset */
    if (err == 0) {
        err = wc_Sha256Update(&sha256, one, sizeof(one));
    }
    /* P5 = Current Key Period No. */
    if (err == 0) {
        periodNum = (word16)((current - offset) / period);
        c16toa(periodNum, len);
        err = wc_Sha256Update(&sha256, len, sizeof(len));
    }
    /* L5 = Length of Current Key Period No. */
    if (err == 0) {
        err = wc_Sha256Update(&sha256, two, sizeof(two));
    }
    if (err == 0) {
        err = wc_Sha256Final(&sha256, uid);
    }
    if (err == 0) {
        wc_Sha256Free(&sha256);
    }

    return err;
}

#endif /* WOLFCRYPT_HAVE_SAKKE */

#endif /* WOLFCRYPT_MIKEY_KMS */

#ifdef WOLFCRYPT_MIKEY_CLIENT

#ifdef WOLFCRYPT_HAVE_SAKKE

/**
 * Initialize the MIKEY-SAKKE associated parameters object and set key type,
 * activation time and expiry.
 *
 * @param  [in]  params      MIKEY-SAKKE associated parameters object.
 * @param  [in]  keyType     Type of key. \ref MIKEY_KEY_TYPE
 * @param  [in]  activation  Activation date and time in seconds.
 *                           Use 0 to imply activation time is in timestamp
 *                           of MIKEY I_MESSAGE.
 * @param  [in]  expiry      Date and time in seconds after which key cannot be
 *                           used.
 *                           Use 0 to imply key never expires.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params is NULL.
 */
int wc_InitMikeySakkeParams(MikeySakkeParams* params, byte keyType,
        time_t activation, time_t expiry)
{
    int err = 0;

    if (params == NULL) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        XMEMSET(params, 0, sizeof(*params));
        params->keyType = keyType;
        /* Bit set indicated NOT revoked - TS 133 180 E.6.9. */
        params->status = 1 << MIKEY_STATUS_REVOKED;
        params->activation = activation;
        params->expiry = expiry;
    }

    return err;
}

/**
 * Get key type, time of activation, expiry time MIKEY-SAKKE associated
 * parameters.
 *
 * @param  [in]  params      MIKEY-SAKKE associated parameters object.
 * @param  [in]  keyType     Type of key. \ref MIKEY_KEY_TYPE
 * @param  [in]  activation  Activation date and time in seconds.
 *                           Use 0 to imply activation time is in timestamp
 *                           of MIKEY I_MESSAGE.
 * @param  [in]  expiry      Date and time in seconds after which key cannot be
 *                           used.
 *                           Use 0 to imply key never expires.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params, keyType, activation or expiry is NULL.
 */
int wc_GetMikeySakkeParamsKAE(MikeySakkeParams* params, byte* keyType,
        time_t* activation, time_t* expiry)
{
    int err = 0;

    if (params == NULL) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        *keyType = params->keyType;
        /* Bit set indicated NOT revoked - TS 133 180 E.6.9. */
        *activation = params->activation;
        *expiry = params->expiry;
    }

    return err;
}


/**
 * Set status to indicate the key has been revoked.
 *
 * @param  [in]  params  MIKEY-SAKKE associated parameters object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params is NULL.
 */
int wc_SetMikeySakkeParamsRevoked(MikeySakkeParams* params)
{
    int err = 0;

    if (params == NULL) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        /* Bit set indicated NOT revoked - TS 133 180 E.6.9. */
        params->status &= ~(1 << MIKEY_STATUS_REVOKED);
    }

    return err;
}

/**
 * Returns whether the key has been revoked.
 *
 * @param  [in]   params   MIKEY-SAKKE associated parameters object.
 * @param  [out]  revoked  1 return when revoked and 0 when not revoked.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params or revoked is NULL.
 */
int wc_IsMikeySakkeParamsRevoked(MikeySakkeParams* params, int* revoked)
{
    int err = 0;

    if ((params == NULL) || (revoked == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        /* Bit set indicated NOT revoked - TS 133 180 E.6.9. */
        *revoked = (params->status & (1 << MIKEY_STATUS_REVOKED)) == 0;
    }

    return err;
}

/**
 * Set status to indicate key has been shared with a security gateway.
 *
 * @param  [in]  params  MIKEY-SAKKE associated parameters object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params is NULL.
 */
int wc_SetMikeySakkeParamsShared(MikeySakkeParams* params)
{
    int err = 0;

    if (params == NULL) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        params->status |= 1 << MIKEY_STATUS_SHARED;
    }

    return err;
}

/**
 * Returns whether the key has been shared a security gateway.
 *
 * @param  [in]   params  MIKEY-SAKKE associated parameters object.
 * @param  [out]  shared  1 return when shared and 0 when not shared.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params or shared is NULL.
 */
int wc_IsMikeySakkeParamsShared(MikeySakkeParams* params, int* shared)
{
    int err = 0;

    if ((params == NULL) || (shared == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        *shared = (params->status & (1 << MIKEY_STATUS_REVOKED)) != 0;
    }

    return err;
}

/**
 * Set the human-readable name of the key.
 *
 * @param  [in]  params  MIKEY-SAKKE associated parameters object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params is NULL or the name is too long.
 */
int wc_SetMikeySakkeParamsName(MikeySakkeParams* params, char* name)
{
    int err = 0;

    if (params == NULL) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        params->textSz = XSTRLEN(name);
        if (params->textSz > MIKEY_TEXT_MAX_LEN) {
            err = BAD_FUNC_ARG;
        }
    }
    if (err == 0) {
        XMEMCPY(params->text, name, params->textSz);
    }

    return err;
}

/**
 * Get the human-readable name of the key.
 *
 * @param  [in]  params  MIKEY-SAKKE associated parameters object.
 * @param  [in]  name    Buffer to hold name.
 *                       Should be at least MIKEY_TEXT_MAX_LEN + 1 bytes in
 *                       length.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params or name is NULL.
 */
int wc_GetMikeySakkeParamsName(MikeySakkeParams* params, char* name)
{
    int err = 0;

    if ((params == NULL) || (name == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        XMEMCPY(name, params->text, params->textSz);
        name[params->textSz] = '\0';
    }

    return err;
}


/**
 * Add an MC Group Id to the associated parameters.
 *
 *
 * @param  [in]  params   MIKEY-SAKKE associated parameters object.
 * @param  [in]  iei      Destination of MC Group ID.
 * @param  [in]  content  Buffer holding contents. Buffer is not copied.
 * @param  [in]  len      Length of conent in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params is NULL or data is too big.
 * @return  BUFFER_E when adding a group id will exceed permissable count.
 */
int wc_AddMikeySakkeParamsGroupId(MikeySakkeParams* params, int iei,
        byte* content, word16 len)
{
    int err = 0;
    int i;

    if (params == NULL) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        if (params->groupIdCnt == MIKEY_GROUP_ID_MAX_CNT) {
            err = BUFFER_E;
        }
    }
    if (err == 0) {
        i = params->groupIdCnt;
        params->groupId[i].iei = iei;
        params->groupId[i].content = content;
        params->groupId[i].len = len;
        params->groupIdCnt++;
    }

    return err;
}

/**
 * Get no. MC Group Ids in the associated parameters.
 *
 * @param  [in]   params  MIKEY-SAKKE associated parameters object.
 * @param  [out]  count   No. MC Group Ids.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params or count is NULL.
 */
int wc_GetMikeySakkeParamsGroupIdCount(MikeySakkeParams* params, int* count)
{
    int err = 0;

    if ((params == NULL) || (count == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        *count = params->groupIdCnt;
    }

    return err;
}

/**
 * Get MC Group Id at index in the associated parameters.
 *
 * @param  [in]      params      MIKEY-SAKKE associated parameters object.
 * @param  [in]      idx         Index of MC Group ID to get.
 * @param  [out]     iei         Destination of MC Group ID.
 * @param  [in]      content     Buffer to put MC Group ID content into.
 * @param  [in,out]  len         On in, length of buffer.
 *                               On out, length of content.
 *                               Content will be no longer than
 *                               MIKEY_GROUP_ID_CONTENT_MAX_LEN bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when params, id, data or len is NULL; idx is not valid
 *          or len is too small.
 */
int wc_GetMikeySakkeParamsGroupId(MikeySakkeParams* params, int idx, int* id,
        byte* content, word16* len)
{
    int err = 0;

    if ((params == NULL) || (id == NULL) || (content == NULL) ||
            (len == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if ((err == 0) && (idx >= params->groupIdCnt)) {
        err = BAD_FUNC_ARG;
    }
    if ((err == 0) && (*len < params->groupId[idx].len)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        *id = params->groupId[idx].iei;
        *len = params->groupId[idx].len;
        XMEMCPY(content, params->groupId[idx].content, *len);
    }

    return err;
}

/**
 * Set the MIKEY-SAKKE UID.
 *
 * @param  [in]  mikey  MIKEY object.
 * @param  [in]  uid    UID data that must be MIKEY_SAKKE_UID_LEN bytes in
 *                      length.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or uid is NULL.
 */
int wc_SetMikeySakkeUid(Mikey* mikey, byte* uid)
{
    int err = 0;

    if ((mikey == NULL) || (uid == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        XMEMCPY(mikey->sakke.uid, uid, MIKEY_SAKKE_UID_LEN);
    }

    return err;
}

/**
 * Set the Initiator's identity and KMS identity.
 *
 * @param  [in]  mikey      MIKEY object.
 * @param  [in]  idri       Data of identity resource of initiator.
 * @param  [in]  idriSz     Size of identity resource of initiator in bytes.
 * @param  [in]  idrkmsi    Data of Identity resource of initiator's KMS.
 * @param  [in]  idrmksiSz  Size of identity resource of initiator's KMS in
 *                          bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey, idri or idrkmsi is NULL or when idriSz or
 *          idrkmsiSz are not big to store.
 */
int wc_SetMikeySakkeInitiator(Mikey* mikey, byte* idri, word32 idriSz,
        byte* idrkmsi, word32 idrkmsiSz)
{
    int err = 0;

    if ((mikey == NULL) || (idri == NULL) || (idrkmsi == NULL)) {
        err = BAD_FUNC_ARG;
    }
    if ((idriSz > MIKEY_ID_MAX_LEN) || (idrkmsiSz > MIKEY_ID_MAX_LEN)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        XMEMCPY(mikey->sakke.initiator.data, idri, idriSz);
        mikey->sakke.initiator.sz = idriSz;
        XMEMCPY(mikey->sakke.initiatorKMS.data, idrkmsi, idrkmsiSz);
        mikey->sakke.initiatorKMS.sz = idrkmsiSz;
    }

    return err;
}

/**
 * Set the Responder's identity and KMS identity.
 *
 * @param  [in]  mikey      MIKEY object.
 * @param  [in]  idri       Data of identity resource of responder.
 * @param  [in]  idriSz     Size of identity resource of responder in bytes.
 * @param  [in]  idrkmsi    Data of Identity resource of responder's KMS.
 * @param  [in]  idrmksiSz  Size of identity resource of responder's KMS in
 *                          bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey, idrr or idrkmsr is NULL or when idrrSz or
 *          idrkmsrSz are not big to store.
 */
int wc_SetMikeySakkeResponder(Mikey* mikey, byte* idrr, word32 idrrSz,
        byte* idrkmsr, word32 idrkmsrSz)
{
    int err = 0;

    if ((mikey == NULL) || (idrr == NULL) || (idrkmsr == NULL)) {
        err = BAD_FUNC_ARG;
    }
    if ((idrrSz > MIKEY_ID_MAX_LEN) || (idrkmsrSz > MIKEY_ID_MAX_LEN)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        XMEMCPY(mikey->sakke.responder.data, idrr, idrrSz);
        mikey->sakke.responder.sz = idrrSz;
        XMEMCPY(mikey->sakke.responderKMS.data, idrkmsr, idrkmsrSz);
        mikey->sakke.responderKMS.sz = idrkmsrSz;
    }

    return err;
}

#endif /* WOLFCRYPT_HAVE_SAKKE */

/* MIKEY message type error */
#define MIKEY_TYPE_ERROR                    6
/* MIKEY message type SAKKE */
#define MIKEY_TYPE_SAKKE_MSG               26

/* No next payload in MIKEY I_MESSAGE. */
#define MIKEY_PAYLOAD_LAST                  0
/* Next payload in MIKEY I_MESSAGE is type SIGN. */
#define MIKEY_PAYLOAD_SIGN                  4
/* Next payload in MIKEY I_MESSAGE is type Timestamp (T). */
#define MIKEY_PAYLOAD_T                     5
/* Next payload in MIKEY I_MESSAGE is type V. */
#define MIKEY_PAYLOAD_V                     9
/* Next payload in MIKEY I_MESSAGE is type RAND. */
#define MIKEY_PAYLOAD_RAND                 11
/* Next payload in MIKEY I_MESSAGE is type ERR. */
#define MIKEY_PAYLOAD_ERR                  12
/* Next payload in MIKEY I_MESSAGE is type IDR. */
#define MIKEY_PAYLOAD_IDR                  14
/* Next payload in MIKEY I_MESSAGE is type GENERAL_EXT. */
#define MIKEY_PAYLOAD_GENERAL_EXT          21
/* Next payload in MIKEY I_MESSAGE is type SAKKE. */
#define MIKEY_PAYLOAD_SAKKE                26

/* General extension type is SAKKE_TO_SELF */
#define MIKEY_GE_TYPE_SAKKE_TO_SELF         6
/* General extension type is PROTECTED APs */
#define MIKEY_GE_TYPE_PROTECTED_APS         7

/* Time is Network Time Protocol format at UTC. */
#define MIKEY_TIME_TYPE_NTP_UTC             0
/* Time is Network Time Protocol format at locale */
#define MIKEY_TIME_TYPE_NTP                 1

/* Default length of random placed into MIKEY I_MESSAGE. */
#define MIKEY_RAND_DEF_LEN                  8

/* Role of identity is the initiator. */
#define MIKEY_ID_ROLE_INITIATOR             1
/* Role of identity is the responder. */
#define MIKEY_ID_ROLE_RESPONDER             2
/* Role of identity is the initiator's KMS. */
#define MIKEY_ID_ROLE_INITIATORS_KMS        6
/* Role of identity is the responder's KMS. */
#define MIKEY_ID_ROLE_RESPONDERS_KMS        7

/* Encoding type of an ID is Network Access Identifier (NAI) */
#define MIKEY_ID_TYPE_NAI                   0
/* Encoding type of an ID is Universal Resource Identifier (URI) */
#define MIKEY_ID_TYPE_URI                   1

/* SAKKE parameters set 1 value. */
#define MIKEY_SAKKE_PARAMS_SET_1            1
/* SAKKE identifier checke is a URI that changes monthly. */
#define MIKEY_SAKKE_ID_SCHEME_URI_MONTHLY   1

/* MIKEY I_MESSAGE signed with an ECCSI key. */
#define MIKEY_SIGN_TYPE_ECCSI               2

/* HDR = version | data type | NP | V (1-bit) | PRF func (7-bit) |
 *       CSB ID (32-bit) | #CS | CS ID map type | CS ID map info (16-bit)
 * version = 1
 * data type = SAKKE msg = 26
 * NP = T
 * V = 0
 * PRF func = MIKEY-1 = 0
 * CSB ID = random
 * #CS = 0,
 * CS ID map = "Empty map" = 1
 * CS ID map info = 0
 */
/*
 * Write the I_MESSAGE Common Header (HDR) payload to the buffer.
 * RFC 3830, Section 6.1.
 *
 * @param  [in]      type    Type of MIKEY I_MESSAGE.
 * @param  [in]      np      Next payload type.
 * @param  [in]      id      Crypto Session Bundle (CSB) Identifier.
 * @param  [in]      out     Output buffer.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 */
static int mikey_write_hdr(byte type, byte np, byte id[4], byte* out,
        word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 12 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        out[i++] = 1;
        out[i++] = type;
        out[i++] = np;
        out[i++] = 0;
        XMEMCPY(out, id, 4);
        i += 4;
        out[i++] = 0;
        out[i++] = 1;
        out[i++] = 0;
        out[i++] = 0;
        *idx = i;
    }

    return err;
}

/* T = NP | type | current timestamp (64-bit)
 * NP = RAND
 * type = *NTP-UTC = 0 or NTP = 1
 * T = 5
 */
/*
 * Write the I_MESSAGE Timestamp (T) payload to the buffer.
 * RFC 3830, Section 6.6.
 *
 * @param  [in]      np       Next payload type.
 * @param  [in]      msgTime  Current time in seconds.
 * @param  [in]      out      Output buffer.
 * @param  [in,out]  idx      Current index into buffer.
 * @param  [in]      maxLen   Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 */
static int mikey_write_t(byte np, time_t msgTime, byte* out, word32* idx,
        word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 10 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        out[i++] = np;
        out[i++] = MIKEY_TIME_TYPE_NTP_UTC;
        if (sizeof(msgTime) == 8) {
            out[i++] = (byte)(msgTime >> 56);
            out[i++] = (byte)(msgTime >> 48);
            out[i++] = (byte)(msgTime >> 40);
            out[i++] = (byte)(msgTime >> 32);
        }
        else {
            out[i++] = 0;
            out[i++] = 0;
            out[i++] = 0;
            out[i++] = 0;
        }
        out[i++] = (byte)(msgTime >> 24);
        out[i++] = (byte)(msgTime >> 16);
        out[i++] = (byte)(msgTime >>  8);
        out[i++] = (byte)(msgTime >>  0);
        *idx = i;
    }

    return err;
}

/* RAND = NP | RAND len | RAND
 * RAND len = 8?
 * RAND = 8 bytes of random.
 * RAND = 11
 */
/*
 * Write the I_MESSAGE Random (RAND) payload to the buffer.
 *
 * @param  [in]      np      Next payload type.
 * @param  [in]      rand    Random data.
 * @param  [in]      randSz  Size of random in bytes.
 * @param  [in]      out     Output buffer.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 */
static int mikey_write_rand(byte np, byte* rand, byte randSz, byte* out,
        word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 2 + randSz > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        out[i++] = np;
        out[i++] = randSz;
        XMEMCPY(out + i, rand, randSz);
        *idx = i + randSz;
    }

    return err;
}

/* IDRi = IDRr = IDRkmsi = IDkmsr
 * IDRi = Initiator ID
 * IDRr = Responder ID
 * IDRkmsi = KMS ID for Initiator
 * IDRkmsr = KMS ID for Responder
 * IDR = NP | ID Role | ID type | ID len (16-bit) | ID Data
 * ID Role = Initiator =  1, Repsonder = 2,
 *           Initiator's KMS = 6, Responder's KMS = 7
 * ID type = NAI = 0, *URI = 1
 * IDR = 14
 */
/*
 * Write the I_MESSAGE Identifier with Role (IDR) payload to the buffer.
 * RFC 6509, Section 4.4.
 *
 * @param  [in]      np      Next payload type.
 * @param  [in]      role    MIKEY identifier role.
 * @param  [in]      id      MIKEY identifier.
 * @param  [in]      out     Output buffer.
 * @param  [in]      idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 */
static int mikey_write_idr(byte np, byte role, MikeyId* id, byte* out,
        word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 5 + id->sz > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        out[i++] = np;
        out[i++] = role;
        out[i++] = MIKEY_ID_TYPE_URI;
        out[i++] = (byte)(id->sz >> 8);
        out[i++] = (byte)id->sz;
        XMEMCPY(out + i, id->data, id->sz);
        *idx = i + id->sz;
    }

    return err;
}

#ifdef WOLFCRYPT_HAVE_SAKKE 
/* SAKKE = NP | SAKKE params | ID scheme | SAKKE data length | SAKKE data
 * NP = Next Payload
 * SAKKE params = Pameter set 1 = 1
 * ID scheme = tel URI with monthly keys = 1
 * SAKKE data length = 16-bits
 * SAKKE data = SAKKE Encapsulated Data.
 * SAKKE = 26
 */
/*
 * Write the I_MESSAGE SAKKE payload to the buffer.
 * RFC 6509, Section 4.2.
 *
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      np      Next payload type.
 * @param  [in]      data    Data to encapsulate.
 * @param  [in]      dataSz  Size of data in bytes.
 * @param  [in]      out     Output buffer.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  Other -ve value on internal failure.
 */
static int mikey_write_sakke(Mikey *mikey, byte np, byte* data, word16 dataSz,
        byte* out, word32* idx, word32 maxLen)
{
    int err;
    word32 i = *idx;
    word32 len;
    word16 authSz;
    MikeySakke* sakke = &mikey->sakke;

    err = wc_GetSakkeAuthSize(&sakke->key, &authSz);
    if ((err == 0) && (i + 3 + 2 + authSz + dataSz > maxLen)) {
        err = BUFFER_E;
    }
    if (err == 0) {
        len = authSz + dataSz;

        out[i++] = np;
        out[i++] = MIKEY_SAKKE_PARAMS_SET_1;
        out[i++] = MIKEY_SAKKE_ID_SCHEME_URI_MONTHLY;
        out[i++] = (byte)(len >> 8);
        out[i++] = (byte)len;

        /* Place data to encapsulate after auth data. */
        if (data != out + i + authSz) {
            XMEMCPY(out + i + authSz, data, dataSz);
            data = out + i + authSz;
        }
        /* Encrypt the data in place and calculate authentication data. */
        err = wc_MakeSakkeEncapsulatedSSV(&sakke->key, data, dataSz,
                WC_HASH_TYPE_SHA256, sakke->uid, 32, out, &authSz);
    }
    if (err == 0) {
        /* Go back and write length. */
        *idx = i + len;
    }

    return err;
}

/*
 * Write the protected associated SAKKE parameters to the buffer.
 * This is a General Extension payload.
 * RFC 3830, Section 6.15 - General Extension.
 * 3GPP TS 133 180, Section E.6.
 * The associated parameters are encapsulated and written as a SAKKE payload.
 *
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      np      Next payload type.
 * @param  [in]      params  MIKEY-SAKKE associated parameters.
 * @param  [in]      out     Output buffer.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  Other -ve value on internal failure.
 */
static int mikey_write_sakke_params(Mikey* mikey, byte np,
        MikeySakkeParams* params, byte* out, word32* idx, word32 maxLen)
{
    byte* paramData;
    int err;
    word32 i = *idx;
    byte c;
    word32 j = 0, groupIdLen;
    word32 len;
    word16 authSz;
    word16 maxParamLen;

    err = wc_GetSakkeAuthSize(&mikey->sakke.key, &authSz);
    if (err == 0) {
        out[i++] = np;
        out[i++] = MIKEY_GE_TYPE_PROTECTED_APS;
        *idx = i + 2;

        paramData = out + *idx + 5 + authSz;
        maxParamLen = maxLen - *idx - 5 - authSz;

        if (17 + params->textSz + 3 > maxParamLen ) {
            err = BUFFER_E;
        }
    }
    if (err == 0) {
        paramData[j++] = params->keyType;
        paramData[j++] = (byte)(params->status >> 24);
        paramData[j++] = (byte)(params->status >> 16);
        paramData[j++] = (byte)(params->status >>  8);
        paramData[j++] = (byte)(params->status >>  0);
        if (sizeof(time_t) == 8) {
            paramData[j++] = (byte)(params->activation >> 32);
        }
        else {
            paramData[j++] = 0;
        }
        paramData[j++] = (byte)(params->activation >> 24);
        paramData[j++] = (byte)(params->activation >> 16);
        paramData[j++] = (byte)(params->activation >>  8);
        paramData[j++] = (byte)(params->activation >>  0);
        if (sizeof(time_t) == 8) {
            paramData[j++] = (byte)(params->expiry >> 32);
        }
        else {
            paramData[j++] = 0;
        }
        paramData[j++] = (byte)(params->expiry >> 24);
        paramData[j++] = (byte)(params->expiry >> 16);
        paramData[j++] = (byte)(params->expiry >>  8);
        paramData[j++] = (byte)(params->expiry >>  0);
        paramData[j++] = (byte)(params->textSz >>  8);
        paramData[j++] = (byte)(params->textSz >>  0);
        XMEMCPY(paramData + j, params->text, params->textSz);
        j += params->textSz;
        groupIdLen = j;
        j += 2;
        paramData[j++] = params->groupIdCnt;
        for (c = 0; c < params->groupIdCnt; c++) {
            MikeyGroupId* groupId = &params->groupId[c];
            if (j + 3 + groupId->len > maxParamLen ) {
                err = BUFFER_E;
            }
            if (err == 0) {
                paramData[j++] = groupId->iei;
                paramData[j++] = (byte)(groupId->len >> 8);
                paramData[j++] = (byte)(groupId->len >> 0);
                XMEMCPY(paramData + j, groupId->content, groupId->len);
                j += groupId->len;
            }
        }
        if (err == 0) {
            /* Go back and put in length of MC Group IDs. */
            paramData[groupIdLen+0] = (byte)((j - 2 - groupIdLen) >> 8);
            paramData[groupIdLen+1] = (byte)((j - 2 - groupIdLen) >> 0);
        }
    }

    if (err == 0) {
        err = mikey_write_sakke(mikey, MIKEY_PAYLOAD_LAST, paramData, j, out,
                idx, maxLen);
    }
    if (err == 0) {
        /* Go back and put in length of encrypted associate parameters. */
        len = *idx - i - 2;
        out[i++] = (byte)(len >> 8);
        out[i++] = (byte)len;
    }

    return err;
}

/*
 * Write the SAKKE encrypted for self to the buffer.
 * RFC 3830, Section 6.15 - General Extension.
 * 3GPP TS 133 180, Section E.5.
 * This is a General Extension payload.
 * The SSV is encapsulated and written as a SAKKE payload.
 *
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      np      Next payload type.
 * @param  [in]      out     Output buffer.
 * @param  [in]      idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  Other -ve value on internal failure.
 */
static int mikey_write_sakke_to_self(Mikey *mikey, byte np, byte* out,
        word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;
    word32 len;

    out[i++] = np;
    out[i++] = MIKEY_GE_TYPE_SAKKE_TO_SELF;
    *idx = i + 2;

    err = mikey_write_sakke(mikey, MIKEY_PAYLOAD_LAST, mikey->sakke.ssv,
              mikey->sakke.ssvSz, out, idx, maxLen);
    if (err == 0) {
        len = *idx - i - 2;
        out[i++] = (byte)(len >> 8);
        out[i++] = (byte)len;
    }

    return err;
}
#endif /* WOLFCRYPT_HAVE_SAKKE */

#ifdef WOLFCRYPT_HAVE_ECCSI

/* SIGN = S type (4-bit) | Signature len (12-bit) | Signature
 * S Type = ECCSI = 2
 * Signture is ECCSI signature
 * SIGN = 4
 */
/*
 * Write the I_MESSAGE signature (SIGN) payload to the buffer.
 * RFC 6509, Section 4.3.
 * Signs the I_MESSAGE data up to this payload using an ECCSI key.
 *
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      rng     Random number generator.
 * @param  [in]      out     Output buffer.
 * @param  [in]      idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  Other -ve value on internal failure.
 */
static int mikey_write_sign(Mikey* mikey, WC_RNG* rng, byte* out, word32* idx,
        word32 maxLen)
{
    int err = 0;
    word32 i = *idx;
    word32 len;
    byte hash[MAX_ECC_BYTES];
    word32 hashSz = sizeof(hash);
    MikeyId* id = &mikey->sakke.initiator;

    if (err == 0) {
        err = wc_HashEccsiId(&mikey->eccsi.key, WC_HASH_TYPE_SHA256, id->data,
                id->sz, &mikey->eccsi.pvt, hash, &hashSz);
    }
    if (err == 0) {
        len = maxLen - i;
        err = wc_SignEccsiHash(&mikey->eccsi.key, rng, WC_HASH_TYPE_SHA256,
                hash, hashSz, out, *idx, &mikey->eccsi.ssk, &mikey->eccsi.pvt,
                out + i + 2, &len);
    }
    if (err == 0) {
        out[i++] = (MIKEY_SIGN_TYPE_ECCSI << 4) + (byte)(len >> 8);
        out[i++] = (byte)len;
        *idx = i + len;
    }

    return err;
}
#endif /* WOLFCRYPT_HAVE_ECCSI */

#if defined(WOLFCRYPT_HAVE_ECCSI) && defined(WOLFCRYPT_HAVE_SAKKE)

/*
 * I_MESSAGE = HDR | T | RAND | [IDRi] | [IDRr] | [IDRkmsi] | [IDRkmsr] |
 *             SAKKE | SIGN
 */
/**
 * Write a MIKEY-SAKKE I_MESSAGE to the buffer.
 *
 * @param  [in]  mikey    MIKEY object.
 * @param  [in]  rng      Random number generator.
 * @param  [in]  msgTime  Time of message in seconds.
 * @param  [in]  params   MIKEY-SAKKE associated parameters. NULL when no
 *                        parameters to be included in message.
 * @param  [in]  toSelf   1 indicates to include SAKKE-to-self data.
 *                        0 indicates otherwise.
 * @param  [in]  msg      Buffer to hold message.
 * @param  [in]  msgSz    Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  BAD_FUNC_ARG when mikey, rng, msg or msgSz is NULL.
 * @return  Other -ve value on internal failure.
 */
int wc_WriteMikeySakke(Mikey* mikey, WC_RNG* rng, time_t msgTime,
        MikeySakkeParams* params, int toSelf, byte* msg, word32* msgSz)
{
    int err = 0;
    byte np[7];
    int npCnt = 0;
    int npIdx = 0;
    word32 idx = 0;
    word32 len;

    if ((mikey == NULL) || (rng == NULL) || (msg == NULL) || (msgSz == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        len = *msgSz;

        if (mikey->sakke.initiator.sz != 0)     np[npCnt++] = MIKEY_PAYLOAD_IDR;
        if (mikey->sakke.responder.sz != 0)     np[npCnt++] = MIKEY_PAYLOAD_IDR;
        if (mikey->sakke.initiatorKMS.sz != 0)  np[npCnt++] = MIKEY_PAYLOAD_IDR;
        if (mikey->sakke.responderKMS.sz != 0)  np[npCnt++] = MIKEY_PAYLOAD_IDR;
                                        np[npCnt++] = MIKEY_PAYLOAD_GENERAL_EXT;
        if (params != NULL)             np[npCnt++] = MIKEY_PAYLOAD_GENERAL_EXT;
        if (toSelf)                     np[npCnt++] = MIKEY_PAYLOAD_GENERAL_EXT;
                                               np[npCnt++] = MIKEY_PAYLOAD_SIGN;

        err = mikey_write_hdr(MIKEY_TYPE_SAKKE_MSG, MIKEY_PAYLOAD_T,
                mikey->csbId, msg, &idx, len);
    }
    if (err == 0) {
        err = mikey_write_t(MIKEY_PAYLOAD_RAND, msgTime, msg, &idx, len);
    }
    if (err == 0) {
        err = wc_RNG_GenerateBlock(rng, mikey->rand, MIKEY_RAND_DEF_LEN);
    }
    if (err == 0) {
        mikey->randSz = MIKEY_RAND_DEF_LEN;
        err = mikey_write_rand(np[npIdx++], mikey->rand, MIKEY_RAND_DEF_LEN,
            msg, &idx, len);
    }
    if ((err == 0) && (mikey->sakke.initiator.sz != 0)) {
        err = mikey_write_idr(np[npIdx++], MIKEY_ID_ROLE_INITIATOR,
                &mikey->sakke.initiator, msg, &idx, len);
    }
    if ((err == 0) && (mikey->sakke.responder.sz != 0)) {
        err = mikey_write_idr(np[npIdx++], MIKEY_ID_ROLE_RESPONDER,
                &mikey->sakke.responder, msg, &idx, len);
    }
    if ((err == 0) && (mikey->sakke.initiatorKMS.sz != 0)) {
        err = mikey_write_idr(np[npIdx++], MIKEY_ID_ROLE_INITIATORS_KMS,
                &mikey->sakke.initiatorKMS, msg, &idx, len);
    }
    if ((err == 0) && (mikey->sakke.responderKMS.sz != 0)) {
        err = mikey_write_idr(np[npIdx++], MIKEY_ID_ROLE_RESPONDERS_KMS,
                &mikey->sakke.responderKMS, msg, &idx, len);
    }
    if (err == 0) {
        mikey->sakke.ssvSz = MIKEY_SAKKE_SSV_MAX_LEN;
        err =  wc_GenerateSakkeSSV(&mikey->sakke.key, rng, mikey->sakke.ssv,
            &mikey->sakke.ssvSz);
    }
    if (err == 0) {
        err = mikey_write_sakke(mikey, np[npIdx++], mikey->sakke.ssv,
                mikey->sakke.ssvSz, msg, &idx, len);
    }
    if ((err == 0) && params) {
        err = mikey_write_sakke_params(mikey, np[npIdx++], params, msg, &idx,
                len);
    }
    if ((err == 0) && toSelf) {
        err = mikey_write_sakke_to_self(mikey, np[npIdx++], msg, &idx, len);
    }
    if (err == 0) {
        err = mikey_write_sign(mikey, rng, msg, &idx, len);
    }

    return err;
}

#endif /* WOLFCRYPT_HAVE_ECCSI && WOLFCRYPT_HAVE_SAKKE */

/*
 * Write the I_MESSAGE Error (ERR) payload to the buffer.
 *
 * @param  [in]      np      Next payload type.
 * @param  [in]      error   Error value.
 * @param  [in]      out     Output buffer.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 */
static int mikey_write_err(byte np, byte error, byte* out, word32* idx,
        word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 4 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        out[i++] = np;
        out[i++] = error;
        out[i++] = 0;
        out[i++] = 0;
        *idx = i;
    }

    return err;
}

/**
 * Write a MIKEY Error I_MESSAGE to the buffer.
 *
 * @param  [in]  mikey  MIKEY object.
 * @param  [in]  error  Error value.
 * @param  [in]  msg    Buffer to hold message.
 * @param  [in]  msgSz  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey, msg or msgSz is NULL.
 * @return  BUFFER_E when the buffer is too small.
 * @return  Other -ve value on internal failure.
 */
int wc_WriteMikeyError(Mikey* mikey, int error, byte* msg, word32* msgSz)
{
    int err = 0;
    word32 idx = 0;
    word32 len;

    if ((mikey == NULL) || (msg == NULL) || (msgSz == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        len = *msgSz;
        err = mikey_write_hdr(MIKEY_TYPE_ERROR, MIKEY_PAYLOAD_ERR, mikey->csbId,
                msg, &idx, len);
    }
    if (err == 0) {
        err = mikey_write_err(MIKEY_PAYLOAD_LAST, error, msg, &idx, len);
    }
    if (err == 0) {
        *msgSz = idx;
    }

    return err;
}

/*
 * Read MIKEY I_MESSAGE Common Header (HDR) payload.
 * RFC 3830, Section 6.1.
 *
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      type    Type of message expected.
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      in      Input data.
 * @param  [in,out   idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_BAD_MSG_E when data is invalid.
 */
static int mikey_read_hdr(Mikey* mikey, byte type, byte* np, byte* in,
        word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 12 > maxLen) {
        err = BUFFER_E;
    }

    if ((err == 0) && (in[i++] != 1)) {
        err = MIKEY_BAD_MSG_E;
    }
    if ((err == 0) && (in[i++] != type)) {
        err = MIKEY_BAD_MSG_E;
    }
    if (err == 0) {
        *np = in[i++];
        mikey->v = in[i] >> 7;
        mikey->prfFunc = in[i++] & 0x7f;
        mikey->csbId[0] = in[i+0];
        mikey->csbId[1] = in[i+1];
        mikey->csbId[2] = in[i+2];
        mikey->csbId[3] = in[i+3];
        i += 4;
        mikey->csCnt = in[i++];
        mikey->csIdMapType = in[i++];
        mikey->csIdMapInfo = (((word16)in[i+0]) <<  8) +
                             (((word16)in[i+0]) <<  0);
        i += 2;
        *idx = i;

        if ((mikey->v != 0) ||
                (mikey->csIdMapType != MIKEY_CS_MAP_TYPE_SRTP_ID)) {
            err = MIKEY_BAD_MSG_E;
        }
    }

    return err;
}

/*
 * Read MIKEY I_MESSAGE Time (T) payload.
 * RFC 3830, Section 6.6.
 *
 * @param  [out]     np       Next payload type from payload.
 * @param  [out]     msgTime  Time of message in seconds.
 * @param  [in]      in       Input data.
 * @param  [in,out]  idx      Current index into buffer.
 * @param  [in]      maxLen   Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 */
static int mikey_read_t(byte* np, time_t* msgTime, byte* in, word32* idx,
        word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 10 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        *np = in[i++];
        if (in[i++] != MIKEY_TIME_TYPE_NTP_UTC) {
            err = MIKEY_SAKKE_MSG_E;
        }
    }
    if (err == 0) {
        if (sizeof(*msgTime) == 8) {
            *msgTime = (((time_t)in[i+0]) << 56) +
                       (((time_t)in[i+1]) << 48) +
                       (((time_t)in[i+2]) << 40) +
                       (((time_t)in[i+3]) << 32) +
                       (((time_t)in[i+4]) << 24) +
                       (((time_t)in[i+5]) << 16) +
                       (((time_t)in[i+6]) <<  8) +
                       (((time_t)in[i+7]) <<  0);
            i += 8;
        }
        else {
            i += 4;
            *msgTime = (((time_t)in[i+0]) << 24) +
                       (((time_t)in[i+1]) << 16) +
                       (((time_t)in[i+2]) <<  8) +
                       (((time_t)in[i+3]) <<  0);
            i += 4;
        }
        *idx = i;
    }

    return err;
}

/*
 * Read MIKEY I_MESSAGE Random (RAND) payload.
 * RFC 3830, Section 6.11.
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      rand    Buffer to hold random data.
 * @param  [out]     randSz  Siz of Buffer to hold random data.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 */
static int mikey_read_rand(byte* np, byte* rand, byte* randSz, byte* in,
        word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 2 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        *np = in[i++];
        /* Check that rand has enough space for data sent. */
        if (*randSz < in[i]) {
            err = MIKEY_SAKKE_MSG_E;
        }
    }
    if (err == 0) {
        *randSz = in[i++];
        if (i + *randSz > maxLen) {
            err = BUFFER_E;
        }
    }
    if (err == 0) {
        XMEMCPY(rand, in + i, *randSz);
        *idx = i + *randSz;
    }

    return err;
}

/*
 * Read MIKEY I_MESSAGE Identifier with Role (IDR) payload.
 * RFC 6509, Section 4.4.
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 */
static int mikey_read_idr(byte* np, Mikey* mikey, byte* in, word32* idx,
        word32 maxLen)
{
    int err = 0;
    word32 i = *idx;
    byte role;
    byte type;
    word16 len;
    byte* data;
    MikeyId* idr;

    if (i + 5 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        *np = in[i++];
        role = in[i++];
        type = in[i++];
        len = (((word16)in[i+0]) << 8) +
              (((word16)in[i+1]) << 0);
        i += 2;
        data = in + i;

        if (i + len > maxLen) {
            err = BUFFER_E;
        }
    }
    if (err == 0) {
        if (type != MIKEY_ID_TYPE_URI) {
            err = MIKEY_SAKKE_MSG_E;
        }
    }
    if (err == 0) {
        if (len > MIKEY_ID_MAX_LEN) {
            err = MIKEY_SAKKE_MSG_E;
        }
    }
    if (err == 0) {
        switch (role) {
            case MIKEY_ID_ROLE_INITIATOR:
                idr = &mikey->sakke.initiator;
                break;
            case MIKEY_ID_ROLE_RESPONDER:
                idr = &mikey->sakke.responder;
                break;
            case MIKEY_ID_ROLE_INITIATORS_KMS:
                idr = &mikey->sakke.initiatorKMS;
                break;
            case MIKEY_ID_ROLE_RESPONDERS_KMS:
                idr = &mikey->sakke.responderKMS;
                break;
            default:
                err = MIKEY_SAKKE_MSG_E;
                break;
        }
    }
    if (err == 0) {
        XMEMCPY(idr->data, data, len);
        idr->sz = len;
        *idx = i;
    }

    return err;
}

#ifdef WOLFCRYPT_HAVE_SAKKE

/*
 * Read MIKEY I_MESSAGE SAKKE payload.
 * RFC 6509, Section 4.2.
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      mikey   MIKEY object.
 * @param  [out]     data    SAKKE encapsulated data.
 * @param  [out]     len     Length of SAKKE encapsulated data in bytes.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 */
static int mikey_read_sakke(byte* np, Mikey* mikey, byte** data, word32* len,
        byte* in, word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;
    byte params;
    byte scheme;

    if (i + 5 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        *np = in[i++];
        params = in[i++];
        scheme = in[i++];
        *len = (((word16)in[i+0]) << 8) +
               (((word16)in[i+1]) << 0);
        i += 2;
        *data = in + i;

        if (i + *len > maxLen) {
            err = BUFFER_E;
        }
    }
    if ((err == 0) && (params != MIKEY_SAKKE_PARAMS_SET_1)) {
        err = MIKEY_SAKKE_MSG_E;
    }
    if ((err == 0) && (scheme != MIKEY_SAKKE_ID_SCHEME_URI_MONTHLY)) {
        err = MIKEY_SAKKE_MSG_E;
    }
    if ((err == 0) && (mikey->sakke.key.ecc.dp->id != ECC_SAKKE_1)) {
        err = BAD_STATE_E;
    }
    if (err == 0) {
        *idx = i;
    }

    return err;
}

/*
 * Read MIKEY I_MESSAGE SAKKE-to-self data that is in General Extension payload.
 * 3GPP TS 133 180, Section E.5.
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      mikey   MIKEY object.
 * @param  [out]     data    SAKKE encapsulated data.
 * @param  [out]     len     Length of SAKKE encapsulated data in bytes.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 */
static int mikey_read_sakke_to_self(Mikey* mikey, byte** data, word32* len,
        byte* in, word32* idx, word32 maxLen)
{
    int err;
    byte fakeNP;

    err = mikey_read_sakke(&fakeNP, mikey, data, len, in, idx, maxLen);
    if ((err == 0) && (fakeNP != MIKEY_PAYLOAD_LAST)) {
        err = MIKEY_SAKKE_MSG_E;
    }

    return err;
}

/*
 * Read MIKEY I_MESSAGE associated SAKKE parameters data in General Ext payload.
 * 3GPP TS 133 180, Section E.6.
 * Encapsulated data pointer is stored in encData field of MikeSakkeParams.
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 */
static int mikey_read_sakke_params(Mikey* mikey, byte* in, word32* idx,
        word32 maxLen)
{
    int err;
    byte fakeNP;
    word32 len;
    MikeySakke* sakke = &mikey->sakke;

    err = mikey_read_sakke(&fakeNP, mikey, &sakke->encData, &len, in, idx,
            maxLen);
    if ((err == 0) && (fakeNP != MIKEY_PAYLOAD_LAST)) {
        err = MIKEY_SAKKE_MSG_E;
    }
    if (err == 0) {
        sakke->encDataLen = len;
    }

    return err;
}

/*
 * Process associated SAKKE parameters data that was been derived.
 * 3GPP TS 133 180, Section E.6.
 * Encapsulated data pointer was stored in encData field of MikeSakkeParams.
 * See mikey_read_sakke_params()
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 * @return  SAKKE_VERIFY_FAIL_E when calculated R doesn't match the encapsulated
 *          data's R.
 * @return  Other -ve value on internal failure.
 */
static int mikey_do_sakke_params(Mikey* mikey)
{
    int err;
    MikeySakke* sakke = &mikey->sakke;
    MikeySakkeParams* params = &mikey->sakke.params;
    byte* authData = sakke->encData;
    word16 authSz;
    byte* ssv;
    word32 ssvSz;
    word16 len = MIKEY_SAKKE_SSV_MAX_LEN;
    word32 sz;
    word32 i = 0, c;

    err = wc_GetSakkeAuthSize(&sakke->key, &authSz);
    if (err == 0) {
        ssv = sakke->encData + authSz;
        ssvSz = sakke->encDataLen - authSz;
        err = wc_DeriveSakkeSSV(&sakke->key, WC_HASH_TYPE_SHA256,
                sakke->responder.data, sakke->responder.sz, sakke->rsk,
                ssv, ssvSz, authData, authSz);
    }
    if ((err == 0) && (17 > len)) {
        err = MIKEY_SAKKE_MSG_E;
    }
    if (err == 0) {
        params->keyType = ssv[i++];
        params->status = (((word32)ssv[i+0]) << 24) +
                         (((word32)ssv[i+1]) << 16) +
                         (((word32)ssv[i+2]) <<  8) +
                         (((word32)ssv[i+3]) <<  0);
        i += 4;
        if (sizeof(params->activation) == 8) {
            params->activation = (((time_t)ssv[i+0]) << 32) +
                                 (((time_t)ssv[i+1]) << 24) +
                                 (((time_t)ssv[i+2]) << 16) +
                                 (((time_t)ssv[i+3]) <<  8) +
                                 (((time_t)ssv[i+4]) <<  0);
            params->expiry     = (((time_t)ssv[i+5]) << 32) +
                                 (((time_t)ssv[i+6]) << 24) +
                                 (((time_t)ssv[i+7]) << 16) +
                                 (((time_t)ssv[i+8]) <<  8) +
                                 (((time_t)ssv[i+9]) <<  0);
        }
        else {
            params->activation = (((time_t)ssv[i+1]) << 24) +
                                 (((time_t)ssv[i+2]) << 16) +
                                 (((time_t)ssv[i+3]) <<  8) +
                                 (((time_t)ssv[i+4]) <<  0);
            params->expiry     = (((time_t)ssv[i+6]) << 24) +
                                 (((time_t)ssv[i+7]) << 16) +
                                 (((time_t)ssv[i+8]) <<  8) +
                                 (((time_t)ssv[i+9]) <<  0);
        }
        i += 10;

        params->textSz = (((word32)ssv[i+0]) <<  8) +
                         (((word32)ssv[i+1]) <<  0);
        i += 2;
        if (params->textSz > sizeof(params->text)) {
            err = MIKEY_SAKKE_MSG_E;
        }
    }
    if ((err == 0) && (i + params->textSz > len)) {
        err = MIKEY_SAKKE_MSG_E;
    }
    if (err == 0) {
        XMEMCPY(params->text, ssv + i, params->textSz);

        sz = (((word32)ssv[i+0]) <<  8) +
             (((word32)ssv[i+1]) <<  0);
        i += 2;

        if (i + sz > len) {
            err = MIKEY_SAKKE_MSG_E;
        }
    }
    if (err == 0) {
        params->groupIdCnt = ssv[i++];

        for (c = 0; (err == 0) && (c < params->groupIdCnt); c++) {
            MikeyGroupId* groupId = &params->groupId[c];

            if (i + 3 > ssvSz) {
                err = MIKEY_SAKKE_MSG_E;
            }
            if (err == 0) {
                groupId->iei = ssv[i++];
                groupId->len = (((word32)ssv[i+0]) <<  8) +
                               (((word32)ssv[i+1]) <<  0);
                i += 2;
                if (groupId->len > len) {
                    err = MIKEY_SAKKE_MSG_E;
                }
            }
            if ((err == 0) && (i + groupId->len > ssvSz)) {
                err = MIKEY_SAKKE_MSG_E;
            }
            if (err == 0) {
                groupId->content = ssv + i;
                i += groupId->len;
            }
        }
    }

    return err;
}

/*
 * Read MIKEY I_MESSAGE Generat Extension payload.
 * RFC 3830, Section 6.15.
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [in]      mikey   MIKEY object.
 * @param  [out]     data    SAKKE encapsulated data.
 * @param  [out]     len     Length of SAKKE encapsulated data in bytes.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 */
static int mikey_read_general_ext(byte* np, Mikey* mikey, byte** data,
        word32* len, byte* in, word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;
    byte type;
    word16 sakkeLen;

    if (i + 4 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        *np = in[i++];
        type = in[i++];
        sakkeLen = (((word16)in[i+0]) << 8) +
                   (((word16)in[i+0]) << 0);
        i += 2;

        *idx += 4;
        if (type == MIKEY_GE_TYPE_SAKKE_TO_SELF) {
            err = mikey_read_sakke_to_self(mikey, data, len, in, idx,
                    sakkeLen);
        }
        else if (type == MIKEY_GE_TYPE_PROTECTED_APS) {
            err = mikey_read_sakke_params(mikey, in, idx, sakkeLen);
        }
        else {
            err = MIKEY_SAKKE_MSG_E;
        }
    }

    return err;
}

#endif /* WOLFCRYPT_HAVE_SAKKE */

#ifdef WOLFCRYPT_HAVE_ECCSI

/*
 * Read MIKEY I_MESSAGE Signature (SIGN) payload.
 * RFC 6509, Section 4.3.
 *
 * @param  [in]      mikey   MIKEY object.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 * @return  MIKEY_SAKKE_MSG_E when data is invalid for a MIKEY-SAKKE message.
 * @return  SIG_VERIFY_E when the signature cannot be verified.
 */
static int mikey_read_sign(Mikey* mikey, byte* in, word32* idx, word32 maxLen)
{
    int err = 0;
    word32 i = *idx;
    byte type;
    word16 len;
    byte* data;
    byte hash[MAX_ECC_BYTES];
    word32 hashSz = sizeof(hash);
    MikeyId* idr = &mikey->sakke.initiator;
    int verified;

    if (i + 2 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        type = in[i] >> 4;
        len = ((((word16)in[i+0]) & 0x0f) << 8) +
              ((((word16)in[i+1]) & 0xff) << 0);
        i += 2;
        data = in + i;

        if (i + len > maxLen) {
            err = BUFFER_E;
        }
    }
    if ((err == 0) && (type != MIKEY_SIGN_TYPE_ECCSI)) {
        err = MIKEY_SAKKE_MSG_E;
    }
    if (err == 0) {
        err = wc_HashEccsiId(&mikey->eccsi.key, WC_HASH_TYPE_SHA256, idr->data,
                idr->sz, &mikey->eccsi.pvt, hash, &hashSz);
    }
    if (err == 0) {
        len = maxLen - i;
        err = wc_VerifyEccsiHash(&mikey->eccsi.key, WC_HASH_TYPE_SHA256,
                hash, hashSz, in, *idx, data, len, &verified);
    }
    if (err == 0) {
        if (!verified) {
            err = SIG_VERIFY_E;
        }
    }
    if (err == 0) {
        *idx = i + len;
    }

    return err;
}

#endif /* WOLFCRYPT_HAVE_SAKKE */

#ifdef WOLFCRYPT_HAVE_SAKKE

/*
 * Derives the Shared Secret Value (SSV) from the encapsulated SAKKE data.
 * SSV stored in ssv field of MikeySakke.
 *
 * @param  [in]   mikey  MIKEY object.
 * @param  [in]   enc    Encapsulated data.
 * @param  [in]   encSz  Size of encapsulated data in bytes.
 * @param  [out]  ssv    Pointer to SSV.
 * @param  [out]  ssvSz  Size of SSV.
 * @return  0 on success.
 * @return  SAKKE_VERIFY_FAIL_E when calculated R doesn't match the encapsulated
 *          data's R.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
static int mikey_derive_ssv(Mikey* mikey, byte* enc, word32 encSz, byte** ssv,
        word32* ssvSz)
{
    int err;
    byte* authData;
    word16 authSz;
    MikeySakke* sakke = &mikey->sakke;

    err = wc_GetSakkeAuthSize(&sakke->key, &authSz);
    if (err == 0) {
        authData = enc;
        *ssv = enc + authSz;
        *ssvSz = encSz - authSz;

        /* Calculate SSV */
        sakke->ssvSz = sizeof(sakke->ssv);
        err = wc_DeriveSakkeSSV(&sakke->key, WC_HASH_TYPE_SHA256,
                      sakke->uid, MIKEY_SAKKE_UID_LEN, sakke->rsk,
                      *ssv, *ssvSz, authData, authSz);
    }

    return err;
}

/**
 * Read a MIKEY-SAKKE I_MESSAGE.
 * All components are stored in the MIKEY object.
 *
 * @param  [in]  mikey      MIKEY object.
 * @param  [in]  responder  1 when responder reading message.
 *                          0 when initiator reading message.
 * @param  [in]  msg        MIKEY-SAKKE message data.
 * @param  [in]  msgSz      Size of message in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or msg is NULL.
 * @return  MIKEY_SAKKE_MSG_E when the message is invalid.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  SIG_VERIFY_E when the signature cannot be verified.
 * @return  SAKKE_VERIFY_FAIL_E when calculated R doesn't match the encapsulated
 *          data's R.
 * @return  Other -ve value on internal failure.
 */
int wc_ReadMikeySakke(Mikey* mikey, int responder, byte* msg, word32 msgSz)
{
    int err = 0;
    byte np = 0;
    word32 idx = 0;
    time_t msgTime = 0;
    byte* enc = NULL;
    word32 encSz = 0;
    byte* encSelf = NULL;
    word32 encSelfSz = 0;
    byte* ssv = NULL;
    word32 ssvSz = 0;

    if ((mikey == NULL) || (msg == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = mikey_read_hdr(mikey, MIKEY_TYPE_SAKKE_MSG, &np, msg, &idx,
                msgSz);
    }

    while ((err == 0) && (np != MIKEY_PAYLOAD_LAST)) {
        switch (np) {
            case MIKEY_PAYLOAD_T:
                err = mikey_read_t(&np, &msgTime, msg, &idx, msgSz);
                if (err == 0) {
                    time_t current = mikey->sakke.current;
                    time_t skew = mikey->sakke.skew;
                    if ((msgTime < current - skew) ||
                            (msgTime > current + skew)) {
                        err = MIKEY_SAKKE_MSG_E;
                    }
                }
                break;
            case MIKEY_PAYLOAD_RAND:
                mikey->randSz = MIKEY_RAND_MAX_LEN;
                err = mikey_read_rand(&np, mikey->rand, &mikey->randSz, msg,
                        &idx, msgSz);
                break;
            case MIKEY_PAYLOAD_IDR:
                err = mikey_read_idr(&np, mikey, msg, &idx, msgSz);
                break;
            case MIKEY_PAYLOAD_SAKKE:
                err = mikey_read_sakke(&np, mikey, &enc, &encSz, msg, &idx, 
                        msgSz);
                break;
            case MIKEY_PAYLOAD_GENERAL_EXT:
                err = mikey_read_general_ext(&np, mikey, &encSelf, &encSelfSz,
                        msg, &idx, msgSz);
                break;
            case MIKEY_PAYLOAD_SIGN:
                err = mikey_read_sign(mikey, msg, &idx, msgSz);
                if (err == 0) {
                    /* SIGN must be last payload */
                    np = 0;
                    if (idx != msgSz) {
                        err = MIKEY_SAKKE_MSG_E;
                    }
                }
                break;
            default:
                err = MIKEY_SAKKE_MSG_E;
                break;
        }
    }

    if (err == 0) {
        if (responder) {
            err = mikey_derive_ssv(mikey, enc, encSz, &ssv, &ssvSz);
        }
        else {
            err = mikey_derive_ssv(mikey, encSelf, encSelfSz, &ssv, &ssvSz);
        }
    }
    if (err == 0 && (mikey->sakke.encDataLen > 0)) {
        err = mikey_do_sakke_params(mikey);
    }
    if (err == 0) {
        XMEMCPY(mikey->sakke.ssv, ssv, ssvSz);
        mikey->sakke.ssvSz = ssvSz;
    }

    return err;
}

#endif /* WOLFCRYPT_HAVE_SAKKE */

/*
 * Read MIKEY I_MESSAGE Error (ERR) payload.
 *
 * @param  [out]     np      Next payload type from payload.
 * @param  [out]     error   Error number in payload.
 * @param  [in]      in      Input data.
 * @param  [in,out]  idx     Current index into buffer.
 * @param  [in]      maxLen  Total size of input data in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the buffer is too small.
 */
static int mikey_read_err(byte* np, byte* error, byte* in, word32* idx,
        word32 maxLen)
{
    int err = 0;
    word32 i = *idx;

    if (i + 4 > maxLen) {
        err = BUFFER_E;
    }

    if (err == 0) {
        *np = in[i++];
        *error = in[i++];
    }

    return err;
}

/**
 * Read a MIKEY-SAKKE I_MESSAGE.
 * Error value stored in the MIKEY object.
 *
 * @param  [in]  mikey  MIKEY object.
 * @param  [in]  msg    MIKEY-SAKKE message data.
 * @param  [in]  msgSz  Size of message in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or msg is NULL.
 * @return  MIKEY_BAD_MSG_E when the message is invalid.
 * @return  BUFFER_E when the message buffer is too small for a length value.
 * @return  Other -ve value on internal failure.
 */
int wc_ReadMikeyError(Mikey* mikey, byte* msg, word32 msgSz)
{
    int err = 0;
    word32 idx = 0;
    byte np = 0;

    if ((mikey == NULL) || (msg == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = mikey_read_hdr(mikey, MIKEY_TYPE_ERROR, &np, msg, &idx, msgSz);
    }

    if ((err == 0) && (np != MIKEY_PAYLOAD_ERR)) {
        err = MIKEY_BAD_MSG_E;
    }

    if (err == 0) {
        err = mikey_read_err(&np, &mikey->err, msg, &idx, msgSz);
    }

    while ((err == 0) && (np != MIKEY_PAYLOAD_LAST)) {
        switch (np) {
            default:
                err = MIKEY_BAD_MSG_E;
                break;
        }
    }

    if ((err == 0) && (idx != msgSz)) {
        err = BUFFER_E;
    }

    return err;
}

/**
 * Read a MIKEY I_MESSAGE.
 * Only MIKEY-SAKKE and Error message types supported.
 *
 * @param  [in]  mikey      MIKEY object.
 * @param  [in]  responder  1 when responder reading message.
 *                          0 when initiator reading message.
 * @param  [in]  msg        MIKEY-SAKKE message data.
 * @param  [in]  msgSz      Size of message in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or msg is NULL.
 * @return  MIKEY_BAD_MSG_E when the message is invalid.
 * @return  BUFFER_E when the message buffer is too small for a length value.
 * @return  SIG_VERIFY_E when the signature cannot be verified.
 * @return  SAKKE_VERIFY_FAIL_E when calculated R doesn't match the encapsulated
 *          data's R.
 * @return  Other -ve value on internal failure.
 */
int wc_ReadMikey(Mikey* mikey, int responder, byte* msg, word32 msgSz)
{
    int err = 0;

    if ((mikey == NULL) || (msg == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (3 > msgSz) {
        err = BUFFER_E;
    }

    /* Check version */
    if ((err == 0) && (msg[0] != 1)) {
        err = MIKEY_BAD_MSG_E;
    }
    if (err == 0) {
        switch (msg[1]) {
            case MIKEY_TYPE_ERROR:
                wc_ReadMikeyError(mikey, msg, msgSz);
                break;
#if defined(WOLFCRYPT_HAVE_ECCSI) && defined(WOLFCRYPT_HAVE_SAKKE)
            case MIKEY_TYPE_SAKKE_MSG:
                wc_ReadMikeySakke(mikey, responder, msg, msgSz);
                break;
#endif
            default:
                err = MIKEY_BAD_MSG_E;
                break;
        }
    }

    return err;
}


/**
 * Retrieve a copy of the Shared Secret Value.
 *
 * @param  [in]      mikey  MIKEY object.
 * @param  [in]      ssv    Buffer to place SSV in.
 *                          NULL when needing the length only.
 * @param  [in,out]  ssvSz  On in, length of SSV buffer in bytes.
 *                          On out, length of SSV data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or params is NULL.
 */
int wc_GetMikeySakkeSSV(Mikey* mikey, byte* ssv, word16* ssvSz)
{
    int err = 0;

    if ((mikey == NULL) || (ssvSz == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if ((err == 0) && (ssv == NULL)) {
        *ssvSz = mikey->sakke.ssvSz;

        err = LENGTH_ONLY_E;
    }

    if (err == 0) {
        XMEMCPY(ssv, mikey->sakke.ssv, mikey->sakke.ssvSz);
    }

    return err;
}

/**
 * Retrieve a reference to the MikeSakkeParameters from reading MIKEY I_MESSAGE.
 *
 * @param  [in]   mikey   MIKEY object.
 * @param  [out]  params  MIKEY-SAKKE parameters read.
 *                        NULL when no associated parameters received.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or params is NULL.
 */
int wc_GetMikeySakkeParams(Mikey* mikey, MikeySakkeParams** params)
{
    int err = 0;

    if ((mikey == NULL) || (params == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        if (mikey->sakke.encDataLen > 0) {
            *params = &mikey->sakke.params;
        }
        else {
            *params = NULL;
        }
    }

    return err;
}

/**
 * Make a random K-ID (CSB-ID).
 *
 * @param  [in]  mikey    MIKEY object.
 * @param  [in]  rng      Random number generator.
 * @param  [in]  purpose  Purpose tag. \ref MIKEY_Purpose
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey or msg is NULL.
 * @return  Other -ve value on internal failure.
 */
int wc_MakeMikeyKId(Mikey* mikey, WC_RNG* rng, byte purpose)
{
    int err = 0;

    if ((mikey == NULL) || (rng == NULL)) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = wc_RNG_GenerateBlock(rng, mikey->csbId, 4);
    }
    if (err == 0) {
        /* Set the purpose tag. */
        mikey->csbId[0] &= 0x0f;
        mikey->csbId[0] |= purpose << 4;
    }

    return err;
}

/*
 * HMAC-SHA-256 of vectorized data.
 *
 * @param  [in]  key    HMAC key data.
 * @param  [in]  keySz  Size of the HMAC key in bytes.
 * @param  [in]  fc     First character to HMAC.
 * @param  [in]  p      Data elements to HMAC.
 * @param  [in]  l      Length of each data element in bytes.
 * @param  [in]  cnt    Number of data elements to HMAC.
 * @param  [in]  out    Buffer to hold HMAC result.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
static int mikey_kdf_sha256(byte* key, word32 keySz, byte fc, byte* p[],
        word16 l[], int cnt, byte* out)
{
    Hmac hmac;
    int err;
    int i;
    byte len[2];

    err = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (err == 0) {
        err = wc_HmacSetKey(&hmac, WC_SHA256, key, keySz);
        if (err == 0) {
            err = wc_HmacUpdate(&hmac, &fc, 1);
        }
        for (i = 0; (err == 0) && (i < cnt); i++) {
            err = wc_HmacUpdate(&hmac, p[i], l[i]);
            if (err == 0) {
                len[0] = (byte)(l[i] >> 8);
                len[1] = (byte)l[i];
                err = wc_HmacUpdate(&hmac, len, sizeof(len));
            }
        }
        if (err == 0) {
            err = wc_HmacFinal(&hmac, out);
        }

        wc_HmacFree(&hmac);
    }

    return err;
}

/**
 * Converts the K-ID to a UK-ID or UK-ID to K-ID by calculating salt and
 * XORing it in to CSB-ID.
 *
 * @param  [in]  mikey  Mikey protocol object.
 * @return 0 on success.
 * @return BAD_FUNC when mikey is NULL.
 * @return MEMORY_E when dynamic memory allocation fails.
 */
int wc_AddMikeySalt(Mikey* mikey)
{
    int err = 0;
    byte* p[1] = { mikey->sakke.responder.data };
    word16 l[1] = { mikey->sakke.responder.sz };
    byte salt[WC_SHA256_DIGEST_SIZE];

    if (mikey == NULL) {
        err = BAD_FUNC_ARG;
    }

    if (err == 0) {
        err = mikey_kdf_sha256(mikey->sakke.ssv, mikey->sakke.ssvSz, 0x50, p, l,
                1, salt);
    }
    if (err == 0) {
        /* Clear space for purpose */
        salt[0] &= 0x0f;

        mikey->csbId[0] ^= salt[0];
        mikey->csbId[1] ^= salt[1];
        mikey->csbId[2] ^= salt[2];
        mikey->csbId[3] ^= salt[3];
    }

    return err;
}


/* Size of the SRTP constant used in the PRF-HMAC-SHA-256. */
#define SRTP_CONSTANT_SIZE     4

/* The const to use when deriving an encryption key. */
static const byte srtpEncConstant[SRTP_CONSTANT_SIZE] = {
    0x15, 0x79, 0x8c, 0xef
};
/* The const to use when deriving a salt key. */
static const byte srtpSaltConstant[SRTP_CONSTANT_SIZE] = {
    0x39, 0xa2, 0xc1, 0x4b
};

/*
 * Generate a block of prf output P
 * RFC 3830. Section 4.1.2.
 *
 * @param  [in]  hmac     HMAC object.
 * @param  [in]  a        A - additional data to be HMACed.
 * @param  [in]  label    Label to be HMACed.
 * @param  [in]  labelSz  Size of label in bytes.
 * @return  0 on success.
 * @return  Other -ve value on internal failure.
 */
static int mikey_prf_sha256_pi(Hmac* hmac, byte* a, byte* label, word16 labelSz,
        byte* mac)
{
    int err = 0;

    if (a != NULL) {
        err = wc_HmacUpdate(hmac, a, WC_SHA256_DIGEST_SIZE);
    }
    if (err == 0) {
        err = wc_HmacUpdate(hmac, label, labelSz);
    }
    if (err == 0) {
        err = wc_HmacFinal(hmac, mac);
    }

    return err;
}

/*
 * XOR into key the derived data.
 * RFC 3830. Section 4.1.2.
 *
 * @param  [in]  hmac     HMAC object.
 * @param  [in]  mac      Previous HMAC result - A.
 * @param  [in]  label    Label to be HMACed.
 * @param  [in]  labelSz  Size of label in bytes.
 * @param  [in]  key      Key to XOR into.
 * @param  [in]  keySz    Size of key in bytes.
 * @return  0 on success.
 * @return  Other -ve value on internal failure.
 */
static int mikey_prf_sha256_xor_p(Hmac* hmac, byte* mac, byte* label,
        byte labelSz, byte* key, int keySz)
{
    int err;
    byte i;
    byte sz;
    byte o = 0;

    do {
        /* P_i = HMAC-SHA-256(A_(i+1) || label) */
        err = mikey_prf_sha256_pi(hmac, mac, label, labelSz, mac);
        if (err == 0) {
            sz = WC_SHA256_DIGEST_SIZE;
            if (keySz - o < sz) {
                sz = keySz - o;
            }
            /* XOR in next P block  */
            for (i = 0; i < sz; i++) {
                key[o + i] ^= mac[i];
            }
            o += sz;
        }
    }
    while ((err == 0) && (o < keySz));

    return err;
}

/*
 * Setup inputs and XOR into key the derived data.
 * RFC 3830. Section 4.1.2.
 *
 * @param  [in]  hmac     HMAC object.
 * @param  [in]  csId     CS-ID.
 * @param  [in]  csbId    CSB-ID.
 * @param  [in]  rand     Random to be HMACed.
 * @param  [in]  randSz   Size of random in bytes.
 * @param  [in]  label    Label to be HMACed.
 * @param  [in]  labelSz  Size of label in bytes.
 * @param  [in]  key      Key to XOR into.
 * @param  [in]  keySz    Size of key in bytes.
 * @return  0 on success.
 * @return  Other -ve value on internal failure.
 */
static int mikey_prf_sha256_xor_out(Hmac* hmac, const byte* constant, byte csId,
        byte* csbId, byte* rand, byte randSz, byte* label, byte* key,
        word16 keySz)
{
    int err;
    byte o = 0;
    byte mac[WC_SHA256_DIGEST_SIZE];
    byte labelSz;

    /* Label = constant || cs_id || csb_id || RAND */
    XMEMCPY(label + o, constant, SRTP_CONSTANT_SIZE);
    o += SRTP_CONSTANT_SIZE;
    label[o++] = csId;
    XMEMCPY(label + o, csbId, MIKEY_CSB_ID_LEN); 
    o += MIKEY_CSB_ID_LEN;
    XMEMCPY(label + o, rand, randSz);
    labelSz = o + randSz;

    /* A_1 = HMAC (s, A_0), where A_0 = label */
    err = mikey_prf_sha256_pi(hmac, NULL, label, labelSz, mac);
    if (err == 0) {
        err = mikey_prf_sha256_xor_p(hmac, mac, label, labelSz, key, keySz);
    }

    return err;
}


/**
 * Derive the Secure Real-time Transport Protocol (SRTP) master key and salt
 * for private call.
 *
 * @param  [in]  mikey   MIKEY object.
 * @param  [in]  tgk     Traffic Generating Key (TGK) - PCK or GMK - data.
 * @param  [in]  tgkSz   Size of TGK in bytes.
 * @param  [in]  csId    CS-ID.
 * @param  [in]  key     Buffer to hold key data.
 * @param  [in]  keySz   Szie of key to derive in bytes.
 * @param  [in]  salt    Buffer to hold salt data.
 * @param  [in]  saltSz  Size of salt to derive in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when mikey, tgk, key or salt is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other -ve value on internal failure.
 */
int wc_DeriveMikeySrtp(Mikey* mikey, byte* tgk, word32 tgkSz, byte csId,
        byte* key, byte keySz, byte* salt, byte saltSz)
{
    int err = 0;
    Hmac hmac;
    Hmac* pHmac = NULL;
    int sz;
    byte label[4 + 1 + 4 + MIKEY_RAND_MAX_LEN];

    if ((mikey == NULL) || (tgk == NULL) || (key == NULL) || (salt == NULL)) {
        err = BAD_FUNC_ARG;
    }

    XMEMSET(key, 0, keySz);
    XMEMSET(salt, 0, saltSz);

    /* TGK, RAND, CSB-ID, CS-ID -> PRF-HMAC-SHA-256 */
    if (err == 0) {
        err = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    }
    if (err == 0) {
        pHmac = &hmac;

        do {
            /* Key is next up to 32 bytes of tgk. */ 
            sz = WC_SHA256_BLOCK_SIZE / 2;
            if (tgkSz < (word32)sz) {
                sz = tgkSz;
            }
            err = wc_HmacSetKey(&hmac, WC_SHA256, tgk, tgkSz);
            if (err == 0) {
                tgkSz -= sz;

                /* XOR into key more data */
                err = mikey_prf_sha256_xor_out(&hmac, srtpEncConstant, csId,
                        mikey->csbId, mikey->rand, mikey->randSz, label, key,
                        keySz);
            }
            if (err == 0) {
                /* XOR into salt more data */
                err = mikey_prf_sha256_xor_out(&hmac, srtpSaltConstant, csId,
                        mikey->csbId, mikey->rand, mikey->randSz, label, salt,
                        saltSz);
            }
        }
        while ((err == 0) && (tgkSz != 0));
    }

    if (pHmac != NULL) {
        wc_HmacFree(&hmac);
    }

    return err;    
}

#endif /* WOLFCRYPT_MIKEY_CLIENT */

#endif /* WOLFCRYPT_HAVE_MIKEY */

