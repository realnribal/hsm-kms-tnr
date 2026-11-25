package io.github.realnribal.hsmkms.campaign;

import io.github.realnribal.hsmkms.hsm.Algorithm;
import io.github.realnribal.hsmkms.hsm.SignMechanism;
import io.github.realnribal.hsmkms.hsm.Usage;
import io.github.realnribal.hsmkms.web.dto.ApiModels.SignRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("non-functional")
class NonFunctionalCampaignTest extends CampaignSupport {

    private static final long BUDGET_MS = 2000;

    @Test
    @Requirement("REQ-NFR-001")
    @DisplayName("REQ-NFR-001 AES key generation stays inside the lab budget")
    void aesKeyGenerationBudget() throws Exception {
        String warmup = alias("nfr-warm");
        assertThat(createKey(warmup, Algorithm.AES, 256, null, false, List.of(Usage.ENCRYPT)).getStatusCode().value())
                .isEqualTo(201);
        long[] samples = new long[5];
        for (int i = 0; i < samples.length; i++) {
            String name = alias("nfr-aes");
            long start = System.nanoTime();
            int status = createKey(name, Algorithm.AES, 256, null, false, List.of(Usage.ENCRYPT))
                    .getStatusCode().value();
            samples[i] = (System.nanoTime() - start) / 1_000_000L;
            assertThat(status).isEqualTo(201);
        }
        double mean = mean(samples);
        writeMetric("REQ-NFR-001", mean);
        assertThat(mean).isLessThan(BUDGET_MS);
    }

    @Test
    @Requirement("REQ-NFR-002")
    @DisplayName("REQ-NFR-002 RSA sign stays inside the lab budget")
    void rsaSignBudget() throws Exception {
        String name = alias("nfr-rsa");
        assertThat(createKey(name, Algorithm.RSA, 2048, null, false, List.of(Usage.SIGN, Usage.VERIFY))
                .getStatusCode().value()).isEqualTo(201);
        String payload = Base64.getEncoder().encodeToString("latency-sample".getBytes(StandardCharsets.UTF_8));
        post("/api/v1/crypto/sign", new SignRequest(name, SignMechanism.SHA256withRSA, payload));
        long[] samples = new long[5];
        for (int i = 0; i < samples.length; i++) {
            long start = System.nanoTime();
            int status = post("/api/v1/crypto/sign", new SignRequest(name, SignMechanism.SHA256withRSA, payload))
                    .getStatusCode().value();
            samples[i] = (System.nanoTime() - start) / 1_000_000L;
            assertThat(status).isEqualTo(200);
        }
        double mean = mean(samples);
        writeMetric("REQ-NFR-002", mean);
        assertThat(mean).isLessThan(BUDGET_MS);
    }

    private static double mean(long[] samples) {
        long total = 0;
        for (long sample : samples) {
            total += sample;
        }
        return total / (double) samples.length;
    }

    private static void writeMetric(String id, double meanMs) throws Exception {
        Path path = Path.of("target", "tnr", "metric-" + id + ".json");
        Files.createDirectories(path.getParent());
        Files.writeString(path, "{\"id\":\"" + id + "\",\"meanMs\":" + meanMs
                + ",\"budgetMs\":" + BUDGET_MS + ",\"samples\":5}");
    }
}
