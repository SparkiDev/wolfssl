
/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API int wc_InitEccsiKey(EccsiKey* key, void* heap, int devId);
/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API int wc_InitEccsiKey_ex(EccsiKey* key, int keySz, int curveId,
        void* heap, int devId);
/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API void wc_FreeEccsiKey(EccsiKey* key);

/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API int wc_MakeEccsiKey(EccsiKey* key, WC_RNG* rng);

/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_MakeEccsiPair(EccsiKey* key, WC_RNG* rng,
        enum wc_HashType hashType, const byte* id, word32 idSz, mp_int* ssk,
        ecc_point* pvt);
/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_ValidateEccsiPair(EccsiKey* key, enum wc_HashType hashType,
        const byte* id, word32 idSz, mp_int* ssk, ecc_point* pvt, int* valid);
/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_ValidateEccsiPvt(EccsiKey* key, ecc_point* pvt, int* valid);
/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_EncodeEccsiPair(EccsiKey* key, mp_int* ssk, ecc_point* pvt,
        byte* data, word32* sz);
/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_EncodeEccsiPvt(EccsiKey* key, ecc_point* pvt, byte* data,
        word32* sz);
/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_DecodeEccsiPair(EccsiKey* key, const byte* data, word32 sz,
        mp_int* ssk, ecc_point* pvt);
/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_DecodeEccsiPvt(EccsiKey* key, const byte* data, word32 sz,
        ecc_point* pvt);

/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API int wc_ExportEccsiKey(EccsiKey* key, byte* data, word32* sz);
/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API int wc_ImportEccsiKey(EccsiKey* key, const byte* data, word32 sz);

/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API int wc_ExportEccsiPublicKey(EccsiKey* key, byte* data, word32* sz);
/*!
    \ingroup ECCSI_Setup
*/
WOLFSSL_API int wc_ImportEccsiPublicKey(EccsiKey* key, const byte* data,
        word32 sz, int trusted);

/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_HashEccsiId(EccsiKey* key, enum wc_HashType hashType,
        const byte* id, word32 idSz, ecc_point* pvt, byte* hash,
        word32* hashSz);

/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_SignEccsiHash(EccsiKey* key, WC_RNG* rng,
        enum wc_HashType hashType, const byte* hash, word32 hashSz,
        const byte* msg, word32 msgSz, mp_int* ssk, ecc_point* pvt, byte* sig,
        word32* sigSz);
/*!
    \ingroup ECCSI_Operations
*/
WOLFSSL_API int wc_VerifyEccsiHash(EccsiKey* key, enum wc_HashType hashType,
        const byte* hash, word32 hashSz, const byte* msg, word32 msgSz,
        const byte* sig, word32 sigSz, int* verified);


