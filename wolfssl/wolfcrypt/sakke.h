/* sakke.h
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
    \file wolfssl/wolfcrypt/sakke.h
*/


#ifndef WOLF_CRYPT_SAKKE_H
#define WOLF_CRYPT_SAKKE_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFCRYPT_HAVE_SAKKE

#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>

#define WOLFCRYPT_SAKKE_KMS
#define WOLFCRYPT_SAKKE_CLIENT

#define SAKKE_ID_MAX_SIZE       128

/** MP integer in projective form. */
typedef ecc_point mp_proj;

/**
 * SAKKE key.
 */
typedef struct SakkeKey {
    /** ECC key to perform elliptic curve operations with. */
    ecc_key ecc;
    /** Prime as an MP integer. */
    mp_int prime;
    /** Q (order) as an MP integer. */
    mp_int q;
    /** G (pairing base) as an MP integer. */
    mp_int g;
    /** Temporary MP integer used during operations. */
    mp_int a;
    /** Temporary MP integer used during operations. */
    mp_int tm1;
    /** Temporary MP integer used during operations. */
    mp_int tm2;
    /** Base point for elliptic curve operations as an ECC point. */
    ecc_point* base;
#ifdef WOLFCRYPT_SAKKE_CLIENT
    /** Temporary elliptic curve point for use in operations. */
    ecc_point* tp1;
    /** Temporary elliptic curve point for use in operations. */
    ecc_point* tp2;
    /** Temporary MP projective integer for use in operations. */
    mp_proj* tp3;
    /** Temporary elliptic curve point for use in operations. */
    ecc_point* i;
    /** Table associated with point I. */
    byte* iTable;
    /** Length of table */
    int iTableLen;
    /** Identity associated with point I. */
    byte id[SAKKE_ID_MAX_SIZE];
    /** Size of identity associated with point I. */
    word16 idSz;
    /** Generic hash algorithm object. */
    wc_HashAlg hash;
    /** Temporary buffer for use in operations. */
    byte data[(MAX_ECC_BYTES * 2) + 1];
#endif
    /** Heap hint for dynamic memory allocation. */
    void* heap;
    /** Bit indicate prime is set as an MP integer in SAKKE key. */
    word16 havePrime:1;
    /** Bit indicates q (order) is set as an MP integer in SAKKE key. */
    word16 haveQ:1;
    /** Bit indicates a is set as an MP integer in SAKKE key. */
    word16 haveA:1;
    /** Bit indicates g (pairing base) is set as an MP integer in SAKKE key. */
    word16 haveG:1;
    /** Bit indicates base point is set as an ECC point in SAKKE key. */
    word16 haveBase:1;
    /** Bit indicates Z is in montgomery form. */
    word16 zMont:1;
    /** Bit indicate MP integers have been initialized. */
    word16 mpInit:1;
} SakkeKey;


WOLFSSL_API int wc_InitSakkeKey(SakkeKey* key, void* heap, int devId);
WOLFSSL_API int wc_InitSakkeKey_ex(SakkeKey* key, int keySize, int curveId,
        void* heap, int devId);
WOLFSSL_API void wc_FreeSakkeKey(SakkeKey* key);

WOLFSSL_API int wc_MakeSakkeKey(SakkeKey* key, WC_RNG* rng);
WOLFSSL_API int wc_MakeSakkePublicKey(SakkeKey* key, ecc_point* pub);

WOLFSSL_API int wc_MakeSakkeRsk(SakkeKey* key, const byte* id, word32 idSz,
        ecc_point* rsk);
WOLFSSL_API int wc_ValidateSakkeRsk(SakkeKey* key, const byte* id, word32 idSz,
        ecc_point* rsk, int* valid);

WOLFSSL_API int wc_ExportSakkeKey(SakkeKey* key, byte* data, word32* sz);
WOLFSSL_API int wc_ImportSakkeKey(SakkeKey* key, const byte* data, word32 sz);
WOLFSSL_API int wc_ExportSakkePrivateKey(SakkeKey* key, byte* data, word32* sz);
WOLFSSL_API int wc_ImportSakkePrivateKey(SakkeKey* key, const byte* data,
        word32 sz);

WOLFSSL_API int wc_EncodeSakkeRsk(SakkeKey* key, ecc_point* rsk, byte* out,
        word32* sz);
WOLFSSL_API int wc_DecodeSakkeRsk(SakkeKey* key, const byte* data, word32 sz,
        ecc_point* rsk);

WOLFSSL_API int wc_ExportSakkePublicKey(SakkeKey* key, byte* data,
        word32* sz);
WOLFSSL_API int wc_ImportSakkePublicKey(SakkeKey* key, const byte* data,
        word32 sz, int trusted);

WOLFSSL_API int wc_GetSakkeAuthSize(SakkeKey* key, word16* authSz);
WOLFSSL_API int wc_MakeSakkePointI(SakkeKey* key, const byte* id, word32 idSz);
WOLFSSL_API int wc_GetSakkePointI(SakkeKey* key, byte* data, word32* sz);
WOLFSSL_API int wc_SetSakkePointI(SakkeKey* key, const byte* id, word32 idSz,
        const byte* data, word32 sz);
WOLFSSL_API int wc_GenerateSakkePointITable(SakkeKey* key, byte* table,
        word32* len);
WOLFSSL_API int wc_SetSakkePointITable(SakkeKey* key, byte* table, word32 len);
WOLFSSL_API int wc_ClearSakkePointITable(SakkeKey* key);

WOLFSSL_API int wc_MakeSakkeEncapsulatedSSV(SakkeKey* key, byte* ssv,
        word16 ssvSz, enum wc_HashType hashType, const byte* id, word32 idSz,
        byte* auth, word16* authSz);
WOLFSSL_API int wc_GenerateSakkeSSV(SakkeKey* key, WC_RNG* rng, byte* ssv,
        word16* ssvSz);
WOLFSSL_API int wc_GenerateSakkeRskTable(SakkeKey* key, ecc_point* rsk,
        byte* table, word32* len);
WOLFSSL_API int wc_DeriveSakkeSSV(SakkeKey* key, enum wc_HashType hashType,
        const byte* id, word32 idSz, ecc_point* rsk, byte* ssv, word16 ssvSz,
        const byte* auth, word16 authSz);
WOLFSSL_API int wc_DeriveSakkeSSVPrecomp(SakkeKey* key,
        enum wc_HashType hashType, const byte* id, word32 idSz, ecc_point* rsk,
        byte* table, word32 len, byte* ssv, word16 ssvSz, const byte* auth,
        word16 authSz);

#endif /* WOLFCRYPT_HAVE_SAKKE */

#endif /* WOLF_CRYPT_SAKKE_H */

