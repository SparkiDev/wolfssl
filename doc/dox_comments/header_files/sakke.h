
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_InitSakkeKey(SakkeKey* key, void* heap, int devId);
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_InitSakkeKey_ex(SakkeKey* key, int keySize, int curveId,
        void* heap, int devId);
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API void wc_FreeSakkeKey(SakkeKey* key);

/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_MakeSakkeKey(SakkeKey* key, WC_RNG* rng);
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_MakeSakkePublicKey(SakkeKey* key, ecc_point* pub);

/*!
    \ingroup SAKKE_RSK
*/
WOLFSSL_API int wc_MakeSakkeRsk(SakkeKey* key, const byte* id, word32 idSz,
        ecc_point* rsk);
/*!
    \ingroup SAKKE_RSK
*/
WOLFSSL_API int wc_ValidateSakkeRsk(SakkeKey* key, const byte* id, word32 idSz,
        ecc_point* rsk, int* valid);
/*!
    \ingroup SAKKE_RSK
*/
WOLFSSL_API int wc_GenerateSakkeRskTable(SakkeKey* key, ecc_point* rsk,
         byte* table, word32* len);

/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_ExportSakkeKey(SakkeKey* key, byte* data, word32* sz);
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_ImportSakkeKey(SakkeKey* key, const byte* data, word32 sz);
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_ExportSakkePrivateKey(SakkeKey* key, byte* data, word32* sz);
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_ImportSakkePrivateKey(SakkeKey* key, const byte* data,
        word32 sz);

/*!
    \ingroup SAKKE_RSK
*/
WOLFSSL_API int wc_EncodeSakkeRsk(SakkeKey* key, ecc_point* rsk, byte* out,
        word32* sz);
/*!
    \ingroup SAKKE_RSK
*/
WOLFSSL_API int wc_DecodeSakkeRsk(SakkeKey* key, const byte* data, word32 sz,
        ecc_point* rsk);

/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_ExportSakkePublicKey(SakkeKey* key, byte* data,
        word32* sz);
/*!
    \ingroup SAKKE_Setup
*/
WOLFSSL_API int wc_ImportSakkePublicKey(SakkeKey* key, const byte* data,
        word32 sz, int trusted);

/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_GetSakkeAuthSize(SakkeKey* key, word16* authSz);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_MakeSakkePointI(SakkeKey* key, const byte* id, word32 idSz);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_GetSakkePointI(SakkeKey* key, byte* data, word32* sz);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_SetSakkePointI(SakkeKey* key, const byte* id, word32 idSz,
        const byte* data, word32 sz);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_GenerateSakkePointITable(SakkeKey* key, byte* table,
         word32* len);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_SetSakkePointITable(SakkeKey* key, byte* table, word32 len);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_ClearSakkePointITable(SakkeKey* key);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_MakeSakkeEncapsulatedSSV(SakkeKey* key, byte* ssv,
        word16 ssvSz, enum wc_HashType hashType, const byte* id, word32 idSz,
        byte* auth, word16* authSz);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_GenerateSakkeSSV(SakkeKey* key, WC_RNG* rng, byte* ssv,
        word16* ssvSz);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_DeriveSakkeSSV(SakkeKey* key, enum wc_HashType hashType,
        const byte* id, word32 idSz, ecc_point* rsk, byte* ssv, word16 ssvSz,
        const byte* auth, word16 authSz);
/*!
    \ingroup SAKKE_Operations
*/
WOLFSSL_API int wc_DeriveSakkeSSVPrecomp(SakkeKey* key,
         enum wc_HashType hashType, const byte* id, word32 idSz, ecc_point* rsk,
         byte* table, word32 len, byte* ssv, word16 ssvSz, const byte* auth,
         word16 authSz);
