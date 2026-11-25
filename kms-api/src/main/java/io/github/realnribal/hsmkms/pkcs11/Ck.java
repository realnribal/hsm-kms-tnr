package io.github.realnribal.hsmkms.pkcs11;

/**
 * PKCS#11 v2.40 constants used by the lab KMS. Values match the header in {@code native/include/pkcs11.h}.
 */
public final class Ck {

    public static final long CKR_OK = 0x00000000L;
    public static final long CKR_GENERAL_ERROR = 0x00000005L;
    public static final long CKR_ATTRIBUTE_READ_ONLY = 0x00000010L;
    public static final long CKR_ATTRIBUTE_SENSITIVE = 0x00000011L;
    public static final long CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012L;
    public static final long CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013L;
    public static final long CKR_KEY_HANDLE_INVALID = 0x00000060L;
    public static final long CKR_KEY_TYPE_INCONSISTENT = 0x00000063L;
    public static final long CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068L;
    public static final long CKR_KEY_UNEXTRACTABLE = 0x0000006AL;
    public static final long CKR_MECHANISM_INVALID = 0x00000070L;
    public static final long CKR_MECHANISM_PARAM_INVALID = 0x00000071L;
    public static final long CKR_PIN_INCORRECT = 0x000000A0L;
    public static final long CKR_PIN_LOCKED = 0x000000A4L;
    public static final long CKR_SIGNATURE_INVALID = 0x000000C0L;
    public static final long CKR_SIGNATURE_LEN_RANGE = 0x000000C1L;
    public static final long CKR_TEMPLATE_INCOMPLETE = 0x000000D0L;
    public static final long CKR_TEMPLATE_INCONSISTENT = 0x000000D1L;
    public static final long CKR_OPERATION_ACTIVE = 0x00000090L;
    public static final long CKR_OPERATION_NOT_INITIALIZED = 0x00000091L;
    public static final long CKR_USER_ALREADY_LOGGED_IN = 0x00000100L;
    public static final long CKR_USER_NOT_LOGGED_IN = 0x00000101L;
    public static final long CKR_BUFFER_TOO_SMALL = 0x00000150L;
    public static final long CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190L;
    public static final long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191L;

    public static final long CKF_RW_SESSION = 0x00000002L;
    public static final long CKF_SERIAL_SESSION = 0x00000004L;
    public static final long CKF_OS_LOCKING_OK = 0x00000002L;

    public static final long CKU_USER = 1L;

    public static final long CKO_PUBLIC_KEY = 0x00000002L;
    public static final long CKO_PRIVATE_KEY = 0x00000003L;
    public static final long CKO_SECRET_KEY = 0x00000004L;

    public static final long CKK_RSA = 0x00000000L;
    public static final long CKK_EC = 0x00000003L;
    public static final long CKK_AES = 0x0000001FL;

    public static final long CKA_CLASS = 0x00000000L;
    public static final long CKA_TOKEN = 0x00000001L;
    public static final long CKA_PRIVATE = 0x00000002L;
    public static final long CKA_LABEL = 0x00000003L;
    public static final long CKA_VALUE = 0x00000011L;
    public static final long CKA_KEY_TYPE = 0x00000100L;
    public static final long CKA_ID = 0x00000102L;
    public static final long CKA_SENSITIVE = 0x00000103L;
    public static final long CKA_ENCRYPT = 0x00000104L;
    public static final long CKA_DECRYPT = 0x00000105L;
    public static final long CKA_WRAP = 0x00000106L;
    public static final long CKA_UNWRAP = 0x00000107L;
    public static final long CKA_SIGN = 0x00000108L;
    public static final long CKA_VERIFY = 0x0000010AL;
    public static final long CKA_MODULUS_BITS = 0x00000121L;
    public static final long CKA_PUBLIC_EXPONENT = 0x00000122L;
    public static final long CKA_PRIVATE_EXPONENT = 0x00000123L;
    public static final long CKA_EC_PARAMS = 0x00000180L;
    public static final long CKA_VALUE_LEN = 0x00000161L;
    public static final long CKA_EXTRACTABLE = 0x00000162L;

    public static final long CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000L;
    public static final long CKM_RSA_PKCS = 0x00000001L;
    public static final long CKM_SHA256_RSA_PKCS = 0x00000040L;
    public static final long CKM_EC_KEY_PAIR_GEN = 0x00001040L;
    public static final long CKM_ECDSA = 0x00001041L;
    public static final long CKM_AES_KEY_GEN = 0x00001080L;
    public static final long CKM_AES_CBC_PAD = 0x00001085L;
    public static final long CKM_AES_KEY_WRAP = 0x00002109L;

    /** secp256r1 / prime256v1, DER-encoded OID 1.2.840.10045.3.1.7. */
    public static final byte[] SECP256R1 = new byte[] {
            0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07
    };

    public static final byte[] RSA_PUBLIC_EXPONENT = new byte[] {0x01, 0x00, 0x01};

    private Ck() {
    }

    public static String name(long rv) {
        if (rv == CKR_OK) return "CKR_OK";
        if (rv == CKR_GENERAL_ERROR) return "CKR_GENERAL_ERROR";
        if (rv == CKR_ATTRIBUTE_READ_ONLY) return "CKR_ATTRIBUTE_READ_ONLY";
        if (rv == CKR_ATTRIBUTE_SENSITIVE) return "CKR_ATTRIBUTE_SENSITIVE";
        if (rv == CKR_ATTRIBUTE_TYPE_INVALID) return "CKR_ATTRIBUTE_TYPE_INVALID";
        if (rv == CKR_ATTRIBUTE_VALUE_INVALID) return "CKR_ATTRIBUTE_VALUE_INVALID";
        if (rv == CKR_KEY_HANDLE_INVALID) return "CKR_KEY_HANDLE_INVALID";
        if (rv == CKR_KEY_TYPE_INCONSISTENT) return "CKR_KEY_TYPE_INCONSISTENT";
        if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) return "CKR_KEY_FUNCTION_NOT_PERMITTED";
        if (rv == CKR_KEY_UNEXTRACTABLE) return "CKR_KEY_UNEXTRACTABLE";
        if (rv == CKR_MECHANISM_INVALID) return "CKR_MECHANISM_INVALID";
        if (rv == CKR_MECHANISM_PARAM_INVALID) return "CKR_MECHANISM_PARAM_INVALID";
        if (rv == CKR_PIN_INCORRECT) return "CKR_PIN_INCORRECT";
        if (rv == CKR_PIN_LOCKED) return "CKR_PIN_LOCKED";
        if (rv == CKR_SIGNATURE_INVALID) return "CKR_SIGNATURE_INVALID";
        if (rv == CKR_SIGNATURE_LEN_RANGE) return "CKR_SIGNATURE_LEN_RANGE";
        if (rv == CKR_TEMPLATE_INCOMPLETE) return "CKR_TEMPLATE_INCOMPLETE";
        if (rv == CKR_TEMPLATE_INCONSISTENT) return "CKR_TEMPLATE_INCONSISTENT";
        if (rv == CKR_OPERATION_ACTIVE) return "CKR_OPERATION_ACTIVE";
        if (rv == CKR_OPERATION_NOT_INITIALIZED) return "CKR_OPERATION_NOT_INITIALIZED";
        if (rv == CKR_USER_ALREADY_LOGGED_IN) return "CKR_USER_ALREADY_LOGGED_IN";
        if (rv == CKR_USER_NOT_LOGGED_IN) return "CKR_USER_NOT_LOGGED_IN";
        if (rv == CKR_BUFFER_TOO_SMALL) return "CKR_BUFFER_TOO_SMALL";
        if (rv == CKR_CRYPTOKI_NOT_INITIALIZED) return "CKR_CRYPTOKI_NOT_INITIALIZED";
        if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        return "CKR_0x" + Long.toHexString(rv);
    }
}
