package io.github.realnribal.hsmkms.hsm;

import java.util.Set;

public record KeyUse(
        boolean extractable,
        boolean encrypt,
        boolean decrypt,
        boolean wrap,
        boolean unwrap,
        boolean sign,
        boolean verify) {

    public static KeyUse of(boolean extractable, Set<Usage> usages) {
        return new KeyUse(
                extractable,
                usages.contains(Usage.ENCRYPT),
                usages.contains(Usage.DECRYPT),
                usages.contains(Usage.WRAP),
                usages.contains(Usage.UNWRAP),
                usages.contains(Usage.SIGN),
                usages.contains(Usage.VERIFY));
    }
}
