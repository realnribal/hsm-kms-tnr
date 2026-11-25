package io.github.realnribal.hsmkms.hsm;

import java.util.List;

public record StoredKey(
        String alias,
        String algorithm,
        String objectType,
        int sizeBits,
        String curve,
        boolean sensitive,
        boolean extractable,
        boolean token,
        List<String> usages) {
}
