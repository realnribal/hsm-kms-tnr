package io.github.realnribal.hsmkms.hsm;

public final class DuplicateAliasException extends RuntimeException {

    public DuplicateAliasException(String alias) {
        super(alias);
    }
}
