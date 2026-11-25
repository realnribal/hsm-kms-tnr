#ifndef HSM_KMS_TNR_PKCS11_H
#define HSM_KMS_TNR_PKCS11_H

/*
 * PKCS#11 v2.40 ABI subset for LP64 (Linux x86_64 / aarch64).
 * SoftHSM2 exports the C_* symbols. Only the types this campaign passes
 * by value need an exact layout; CK_TOKEN_INFO is written by the library
 * into a caller buffer of 512 bytes.
 */

#include <stddef.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_BYTE CK_BBOOL;
typedef CK_BYTE CK_UTF8CHAR;

#define CK_TRUE 1
#define CK_FALSE 0

#define CKR_OK 0x00000000UL
#define CKR_GENERAL_ERROR 0x00000005UL
#define CKR_ATTRIBUTE_SENSITIVE 0x00000011UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED 0x00000068UL
#define CKR_KEY_TYPE_INCONSISTENT 0x00000063UL
#define CKR_KEY_UNEXTRACTABLE 0x0000006AUL
#define CKR_MECHANISM_INVALID 0x00000070UL
#define CKR_PIN_INCORRECT 0x000000A0UL
#define CKR_OPERATION_ACTIVE 0x00000090UL
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL

#define CKF_RW_SESSION 0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL
#define CKF_OS_LOCKING_OK 0x00000002UL

#define CKU_USER 1UL

#define CKO_PUBLIC_KEY 0x00000002UL
#define CKO_PRIVATE_KEY 0x00000003UL
#define CKO_SECRET_KEY 0x00000004UL

#define CKK_AES 0x0000001FUL

#define CKA_CLASS 0x00000000UL
#define CKA_TOKEN 0x00000001UL
#define CKA_PRIVATE 0x00000002UL
#define CKA_LABEL 0x00000003UL
#define CKA_VALUE 0x00000011UL
#define CKA_KEY_TYPE 0x00000100UL
#define CKA_SENSITIVE 0x00000103UL
#define CKA_ENCRYPT 0x00000104UL
#define CKA_DECRYPT 0x00000105UL
#define CKA_EXTRACTABLE 0x00000162UL
#define CKA_VALUE_LEN 0x00000161UL

#define CKM_AES_KEY_GEN 0x00001080UL
#define CKM_AES_CBC_PAD 0x00001085UL

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    void *pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void *pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct CK_C_INITIALIZE_ARGS {
    void *CreateMutex;
    void *DestroyMutex;
    void *LockMutex;
    void *UnlockMutex;
    CK_FLAGS flags;
    void *pReserved;
} CK_C_INITIALIZE_ARGS;

_Static_assert(sizeof(void *) == 8, "LP64 only");
_Static_assert(sizeof(CK_ATTRIBUTE) == 24, "CK_ATTRIBUTE ABI");
_Static_assert(sizeof(CK_MECHANISM) == 24, "CK_MECHANISM ABI");
_Static_assert(sizeof(CK_C_INITIALIZE_ARGS) == 48, "CK_C_INITIALIZE_ARGS ABI");

CK_RV C_Initialize(CK_C_INITIALIZE_ARGS *pInitArgs);
CK_RV C_Finalize(void *pReserved);
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, void *pInfo);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, void *pApplication, void *Notify,
                    CK_SESSION_HANDLE *phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR *pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_ATTRIBUTE *pTemplate,
                    CK_ULONG ulCount, CK_OBJECT_HANDLE *phKey);
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen,
                CK_BYTE *pEncryptedData, CK_ULONG *pulEncryptedDataLen);
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE *pData, CK_ULONG *pulDataLen);
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount,
                    CK_ULONG *pulObjectCount);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

#endif
