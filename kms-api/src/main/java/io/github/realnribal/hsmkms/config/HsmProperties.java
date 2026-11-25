package io.github.realnribal.hsmkms.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "hsm")
public record HsmProperties(String library, String tokenLabel, String userPin) {

    @Override
    public String toString() {
        return "HsmProperties[library=" + library + ", tokenLabel=" + tokenLabel + ", userPin=***]";
    }
}
