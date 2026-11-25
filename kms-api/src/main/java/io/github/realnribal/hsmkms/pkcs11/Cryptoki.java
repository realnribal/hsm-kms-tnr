package io.github.realnribal.hsmkms.pkcs11;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

/**
 * Direct binding of the SoftHSM2 {@code C_*} exports. LP64 only: {@code CK_ULONG} is a Java {@code long}.
 */
public interface Cryptoki extends Library {

    long C_Initialize(CkInitializeArgs args);

    long C_Finalize(Pointer reserved);

    long C_GetInfo(Pointer info);

    long C_GetSlotList(byte tokenPresent, Pointer slotList, LongByReference count);

    long C_GetTokenInfo(long slotId, Pointer info);

    long C_OpenSession(long slotId, long flags, Pointer application, Pointer notify, LongByReference session);

    long C_CloseSession(long session);

    long C_Login(long session, long userType, byte[] pin, long pinLen);

    long C_Logout(long session);

    long C_GenerateKey(long session, Mechanism mechanism, CK_ATTRIBUTE[] template, long count, LongByReference key);

    long C_GenerateKeyPair(
            long session,
            Mechanism mechanism,
            CK_ATTRIBUTE[] publicTemplate,
            long publicCount,
            CK_ATTRIBUTE[] privateTemplate,
            long privateCount,
            LongByReference publicKey,
            LongByReference privateKey);

    long C_SignInit(long session, Mechanism mechanism, long key);

    long C_Sign(long session, byte[] data, long dataLen, byte[] signature, LongByReference signatureLen);

    long C_VerifyInit(long session, Mechanism mechanism, long key);

    long C_Verify(long session, byte[] data, long dataLen, byte[] signature, long signatureLen);

    long C_EncryptInit(long session, Mechanism mechanism, long key);

    long C_Encrypt(long session, byte[] data, long dataLen, byte[] encrypted, LongByReference encryptedLen);

    long C_DecryptInit(long session, Mechanism mechanism, long key);

    long C_Decrypt(long session, byte[] encrypted, long encryptedLen, byte[] data, LongByReference dataLen);

    long C_WrapKey(
            long session,
            Mechanism mechanism,
            long wrappingKey,
            long key,
            byte[] wrapped,
            LongByReference wrappedLen);

    long C_UnwrapKey(
            long session,
            Mechanism mechanism,
            long unwrappingKey,
            byte[] wrapped,
            long wrappedLen,
            CK_ATTRIBUTE[] template,
            long attributeCount,
            LongByReference key);

    long C_FindObjectsInit(long session, CK_ATTRIBUTE[] template, long count);

    long C_FindObjects(long session, Pointer objects, long max, LongByReference count);

    long C_FindObjectsFinal(long session);

    long C_GetAttributeValue(long session, long object, CK_ATTRIBUTE attribute, long count);

    long C_DestroyObject(long session, long object);
}
