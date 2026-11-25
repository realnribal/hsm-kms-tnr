package io.github.realnribal.hsmkms.logging;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * Last-line redaction of the lab PIN and API key. The campaign also asserts that rejected
 * secrets which are not in the environment are never logged in the first place.
 */
public final class RedactingConverter extends MessageConverter {

    private static final List<String> SECRETS = load();

    private static List<String> load() {
        List<String> values = new ArrayList<>();
        for (String key : List.of("HSM_PIN", "HSM_SO_PIN", "KMS_API_KEY")) {
            String value = System.getenv(key);
            if (value != null && value.length() >= 6) {
                values.add(value);
            }
        }
        return List.copyOf(values);
    }

    @Override
    public String convert(ILoggingEvent event) {
        String message = event.getFormattedMessage();
        for (String secret : SECRETS) {
            if (message.contains(secret)) {
                message = message.replace(secret, "***");
            }
        }
        return message;
    }
}
