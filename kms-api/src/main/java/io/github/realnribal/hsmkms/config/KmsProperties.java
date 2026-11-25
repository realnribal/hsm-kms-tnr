package io.github.realnribal.hsmkms.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "kms")
public record KmsProperties(String apiKey) {

    @Override
    public String toString() {
        return "KmsProperties[apiKey=***]";
    }
}
