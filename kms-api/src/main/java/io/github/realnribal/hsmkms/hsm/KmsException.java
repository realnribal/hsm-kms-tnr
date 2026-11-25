package io.github.realnribal.hsmkms.hsm;

import io.github.realnribal.hsmkms.pkcs11.Ck;
import io.github.realnribal.hsmkms.pkcs11.CkException;

public final class KmsException extends RuntimeException {

    private final String code;
    private final int status;
    private final String ckR;

    private KmsException(String code, int status, String ckR, String message) {
        super(message);
        this.code = code;
        this.status = status;
        this.ckR = ckR;
    }

    public String code() {
        return code;
    }

    public int status() {
        return status;
    }

    public String ckR() {
        return ckR;
    }

    public static KmsException notFound(String alias) {
        return new KmsException("KEY_NOT_FOUND", 404, null, "No key with alias '" + alias + "'");
    }

    public static KmsException duplicate(String alias) {
        return new KmsException("DUPLICATE_ALIAS", 409, null, "Alias '" + alias + "' already exists");
    }

    public static KmsException validation(String message) {
        return new KmsException("VALIDATION", 400, null, message);
    }

    public static KmsException mechanismMismatch(String message) {
        return new KmsException("MECHANISM_MISMATCH", 400, null, message);
    }

    public static KmsException fromCk(CkException ex) {
        long rv = ex.rv();
        if (rv == Ck.CKR_KEY_UNEXTRACTABLE) {
            return new KmsException("KEY_NOT_EXTRACTABLE", 400, ex.rvName(), ex.getMessage());
        }
        if (rv == Ck.CKR_KEY_FUNCTION_NOT_PERMITTED
                || rv == Ck.CKR_KEY_TYPE_INCONSISTENT
                || rv == Ck.CKR_MECHANISM_INVALID
                || rv == Ck.CKR_MECHANISM_PARAM_INVALID
                || rv == Ck.CKR_KEY_HANDLE_INVALID) {
            return new KmsException("MECHANISM_MISMATCH", 400, ex.rvName(), ex.getMessage());
        }
        return new KmsException("HSM_ERROR", 502, ex.rvName(), ex.getMessage());
    }
}
