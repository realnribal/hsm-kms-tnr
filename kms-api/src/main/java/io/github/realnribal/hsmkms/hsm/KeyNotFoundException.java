package io.github.realnribal.hsmkms.hsm;

public final class KeyNotFoundException extends RuntimeException {

    public KeyNotFoundException(String alias) {
        super(alias);
    }
}
