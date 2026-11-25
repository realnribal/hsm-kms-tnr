package io.github.realnribal.hsmkms.pkcs11;

public final class CkException extends RuntimeException {

    private final long rv;

    public CkException(long rv, String operation) {
        super(operation + " failed: " + Ck.name(rv));
        this.rv = rv;
    }

    public long rv() {
        return rv;
    }

    public String rvName() {
        return Ck.name(rv);
    }
}
