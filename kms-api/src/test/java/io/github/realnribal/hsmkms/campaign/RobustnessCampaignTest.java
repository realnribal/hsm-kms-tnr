package io.github.realnribal.hsmkms.campaign;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.realnribal.hsmkms.hsm.Algorithm;
import io.github.realnribal.hsmkms.hsm.SignMechanism;
import io.github.realnribal.hsmkms.hsm.Usage;
import io.github.realnribal.hsmkms.pkcs11.Ck;
import io.github.realnribal.hsmkms.web.dto.ApiModels.SignRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("negative")
class RobustnessCampaignTest extends CampaignSupport {

    @Value("${hsm.token-label}")
    private String tokenLabel;

    @Test
    @Tag("functional")
    @Requirement("REQ-HSM-001")
    @DisplayName("REQ-HSM-001 health identifies the SoftHSM token")
    void healthIdentifiesSoftHsm() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<String> response = rest.exchange("/api/v1/health", HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        JsonNode body = json(response);
        assertThat(body.get("status").asText()).isEqualTo("UP");
        assertThat(body.get("pkcs11").get("tokenLabel").asText()).isEqualTo(tokenLabel);
        assertThat(body.get("pkcs11").get("manufacturerId").asText()).contains("SoftHSM");
        assertThat(body.get("pkcs11").get("library").asText()).contains("softhsm");
    }

    @Test
    @Requirement("REQ-SEC-001")
    @DisplayName("REQ-SEC-001 the lab API key gates key calls")
    void apiKeyIsRequired() throws Exception {
        HttpHeaders missing = new HttpHeaders();
        missing.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> noKey = rest.exchange("/api/v1/keys", HttpMethod.POST,
                new HttpEntity<>("{}", missing), String.class);
        assertThat(noKey.getStatusCode().value()).isEqualTo(401);
        assertThat(noKey.getBody()).doesNotContain(WRONG_KEY);

        HttpHeaders wrong = new HttpHeaders();
        wrong.setContentType(MediaType.APPLICATION_JSON);
        wrong.set("X-API-Key", WRONG_KEY);
        ResponseEntity<String> rejected = rest.exchange("/api/v1/keys", HttpMethod.POST,
                new HttpEntity<>("{}", wrong), String.class);
        assertThat(rejected.getStatusCode().value()).isEqualTo(401);
        assertThat(rejected.getBody()).doesNotContain(WRONG_KEY);
        assertThat(json(rejected).get("code").asText()).isEqualTo("UNAUTHORIZED");

        ResponseEntity<String> health = rest.exchange("/api/v1/health", HttpMethod.GET,
                new HttpEntity<>(new HttpHeaders()), String.class);
        assertThat(health.getStatusCode().value()).isEqualTo(200);
    }

    @Test
    @Requirement("REQ-NEG-001")
    @DisplayName("REQ-NEG-001 unknown alias")
    void unknownAlias() throws Exception {
        ResponseEntity<String> response = get("/api/v1/keys/missing-alias-404");
        assertThat(response.getStatusCode().value()).isEqualTo(404);
        assertThat(json(response).get("code").asText()).isEqualTo("KEY_NOT_FOUND");
    }

    @Test
    @Requirement("REQ-NEG-002")
    @DisplayName("REQ-NEG-002 an RSA mechanism on an AES key is rejected")
    void mechanismDoesNotMatchTheKey() throws Exception {
        String name = alias("aes-sign");
        createKey(name, Algorithm.AES, 256, null, false, List.of(Usage.ENCRYPT, Usage.DECRYPT));
        String payload = Base64.getEncoder().encodeToString("abc".getBytes(StandardCharsets.UTF_8));
        ResponseEntity<String> response = post("/api/v1/crypto/sign",
                new SignRequest(name, SignMechanism.SHA256withRSA, payload));
        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(json(response).get("code").asText()).isEqualTo("MECHANISM_MISMATCH");

        long rv = tokenClient.signAttempt(name, Ck.CKM_SHA256_RSA_PKCS, "abc".getBytes(StandardCharsets.UTF_8));
        assertThat(rv).isNotEqualTo(Ck.CKR_OK);
        assertThat(Ck.name(rv)).startsWith("CKR_");
    }

    @Test
    @Requirement("REQ-NEG-003")
    @DisplayName("REQ-NEG-003 wrong user PIN is rejected and the session is restored")
    void wrongPinIsRejected() throws Exception {
        long rv = tokenClient.probeUserPin(WRONG_PIN);
        assertThat(rv).isEqualTo(Ck.CKR_PIN_INCORRECT);
        String name = alias("after-pin");
        ResponseEntity<String> created = createKey(name, Algorithm.AES, 128, null, false, List.of(Usage.ENCRYPT));
        assertThat(created.getStatusCode().value()).isEqualTo(201);
    }

    @Test
    @Requirement("REQ-NEG-004")
    @DisplayName("REQ-NEG-004 sign with a missing key")
    void signMissingKey() throws Exception {
        String payload = Base64.getEncoder().encodeToString("abc".getBytes(StandardCharsets.UTF_8));
        ResponseEntity<String> response = post("/api/v1/crypto/sign",
                new SignRequest("missing-sign-key", SignMechanism.SHA256withRSA, payload));
        assertThat(response.getStatusCode().value()).isEqualTo(404);
        assertThat(json(response).get("code").asText()).isEqualTo("KEY_NOT_FOUND");
    }

    @Test
    @Requirement("REQ-LOG-001")
    @DisplayName("REQ-LOG-001 logs keep the CKR and the trace id, not the secrets")
    void logsDoNotContainSecrets() throws Exception {
        tokenClient.probeUserPin(WRONG_PIN);
        String name = alias("missing-log");
        ResponseEntity<String> missing = get("/api/v1/keys/" + name);
        String traceId = missing.getHeaders().getFirst("X-Trace-Id");
        assertThat(traceId).isNotBlank();

        HttpHeaders wrong = new HttpHeaders();
        wrong.set("X-API-Key", WRONG_KEY);
        rest.exchange("/api/v1/keys", HttpMethod.GET, new HttpEntity<>(wrong), String.class);

        String log = Files.readString(Path.of("target", "tnr", "kms-test.log"));
        assertThat(log).contains("CKR_PIN_INCORRECT");
        assertThat(log).contains(traceId);
        assertThat(log).contains(name);
        assertThat(log).doesNotContain(WRONG_PIN);
        assertThat(log).doesNotContain(userPin);
        assertThat(log).doesNotContain(apiKey);
        assertThat(log).doesNotContain(WRONG_KEY);
        String soPin = System.getenv("HSM_SO_PIN");
        if (soPin != null && soPin.length() >= 6) {
            assertThat(log).doesNotContain(soPin);
        }
    }
}
