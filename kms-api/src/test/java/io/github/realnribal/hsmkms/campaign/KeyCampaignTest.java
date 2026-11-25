package io.github.realnribal.hsmkms.campaign;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.realnribal.hsmkms.hsm.Algorithm;
import io.github.realnribal.hsmkms.hsm.Usage;
import io.github.realnribal.hsmkms.pkcs11.Ck;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("functional")
class KeyCampaignTest extends CampaignSupport {

    @Test
    @Requirement("REQ-KEY-001")
    @DisplayName("REQ-KEY-001 AES-256 key is a sensitive token object")
    void aes256IsTokenBound() throws Exception {
        String name = alias("aes");
        ResponseEntity<String> response = createKey(name, Algorithm.AES, 256, null, false,
                List.of(Usage.ENCRYPT, Usage.DECRYPT));
        assertThat(response.getStatusCode().value()).isEqualTo(201);
        JsonNode body = json(response);
        assertThat(body.get("algorithm").asText()).isEqualTo("AES");
        assertThat(body.get("objectType").asText()).isEqualTo("SECRET");
        assertThat(body.get("sizeBits").asInt()).isEqualTo(256);
        assertThat(body.get("sensitive").asBoolean()).isTrue();
        assertThat(body.get("extractable").asBoolean()).isFalse();
        assertThat(body.get("token").asBoolean()).isTrue();
        assertThat(body.has("value")).isFalse();
        assertThat(response.getBody()).doesNotContain("keyMaterial");
        assertThat(tokenClient.attributeRv(name, Ck.CKA_VALUE)).isEqualTo(Ck.CKR_ATTRIBUTE_SENSITIVE);
    }

    @Test
    @Requirement("REQ-KEY-002")
    @DisplayName("REQ-KEY-002 RSA-2048 private key stays on the token")
    void rsa2048IsTokenBound() throws Exception {
        String name = alias("rsa");
        ResponseEntity<String> response = createKey(name, Algorithm.RSA, 2048, null, false,
                List.of(Usage.SIGN, Usage.VERIFY));
        assertThat(response.getStatusCode().value()).isEqualTo(201);
        JsonNode body = json(response);
        assertThat(body.get("algorithm").asText()).isEqualTo("RSA");
        assertThat(body.get("objectType").asText()).isEqualTo("KEY_PAIR");
        assertThat(body.get("sizeBits").asInt()).isEqualTo(2048);
        assertThat(body.get("sensitive").asBoolean()).isTrue();
        assertThat(body.get("extractable").asBoolean()).isFalse();
        assertThat(tokenClient.attributeRv(name, Ck.CKA_PRIVATE_EXPONENT)).isEqualTo(Ck.CKR_ATTRIBUTE_SENSITIVE);
    }

    @Test
    @Requirement("REQ-KEY-003")
    @DisplayName("REQ-KEY-003 EC P-256 key pair reports its curve")
    void ecP256ReportsCurve() throws Exception {
        String name = alias("ec");
        ResponseEntity<String> response = createKey(name, Algorithm.EC, null, "secp256r1", false,
                List.of(Usage.SIGN, Usage.VERIFY));
        assertThat(response.getStatusCode().value()).isEqualTo(201);
        JsonNode body = json(response);
        assertThat(body.get("algorithm").asText()).isEqualTo("EC");
        assertThat(body.get("curve").asText()).isEqualTo("secp256r1");
        assertThat(body.get("sizeBits").asInt()).isEqualTo(256);
        assertThat(body.get("sensitive").asBoolean()).isTrue();
    }

    @Test
    @Requirement("REQ-KEY-004")
    @DisplayName("REQ-KEY-004 listing returns metadata only")
    void listingIsMetadataOnly() throws Exception {
        String aes = alias("list-aes");
        String rsa = alias("list-rsa");
        assertThat(createKey(aes, Algorithm.AES, 256, null, true, List.of(Usage.ENCRYPT)).getStatusCode().value())
                .isEqualTo(201);
        assertThat(createKey(rsa, Algorithm.RSA, 2048, null, false, List.of(Usage.SIGN, Usage.VERIFY))
                .getStatusCode().value()).isEqualTo(201);
        ResponseEntity<String> response = get("/api/v1/keys");
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        JsonNode body = json(response);
        assertThat(body.get("keys").toString()).contains(aes).contains(rsa);
        assertNoMaterial(body);
        assertThat(response.getBody()).doesNotContain("BEGIN");
    }

    @Test
    @Requirement("REQ-KEY-005")
    @DisplayName("REQ-KEY-005 lookup by alias")
    void lookupByAlias() throws Exception {
        String name = alias("lookup");
        createKey(name, Algorithm.AES, 128, null, false, List.of(Usage.ENCRYPT, Usage.DECRYPT));
        ResponseEntity<String> response = get("/api/v1/keys/" + name);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(json(response).get("alias").asText()).isEqualTo(name);
        assertThat(json(response).get("sizeBits").asInt()).isEqualTo(128);
    }

    @Test
    @Requirement("REQ-KEY-006")
    @DisplayName("REQ-KEY-006 delete removes the token object")
    void deleteRemovesTheObject() throws Exception {
        String name = alias("delete");
        createKey(name, Algorithm.AES, 256, null, false, List.of(Usage.ENCRYPT));
        ResponseEntity<String> deleted = rest.exchange("/api/v1/keys/" + name,
                org.springframework.http.HttpMethod.DELETE,
                new org.springframework.http.HttpEntity<>(headers()), String.class);
        assertThat(deleted.getStatusCode().value()).isEqualTo(204);
        ResponseEntity<String> missing = get("/api/v1/keys/" + name);
        assertThat(missing.getStatusCode().value()).isEqualTo(404);
        assertThat(json(missing).get("code").asText()).isEqualTo("KEY_NOT_FOUND");
    }

    @Test
    @Tag("negative")
    @Requirement("REQ-NEG-005")
    @DisplayName("REQ-NEG-005 duplicate alias is rejected")
    void duplicateAliasIsRejected() throws Exception {
        String name = alias("dup");
        assertThat(createKey(name, Algorithm.AES, 256, null, false, List.of(Usage.ENCRYPT)).getStatusCode().value())
                .isEqualTo(201);
        ResponseEntity<String> again = createKey(name, Algorithm.RSA, 2048, null, false,
                List.of(Usage.SIGN, Usage.VERIFY));
        assertThat(again.getStatusCode().value()).isEqualTo(409);
        assertThat(json(again).get("code").asText()).isEqualTo("DUPLICATE_ALIAS");
        assertThat(json(get("/api/v1/keys/" + name)).get("algorithm").asText()).isEqualTo("AES");
    }

    private void assertNoMaterial(JsonNode node) {
        if (node.isObject()) {
            assertThat(node.has("value")).isFalse();
            assertThat(node.has("keyMaterial")).isFalse();
            assertThat(node.has("modulus")).isFalse();
            assertThat(node.has("privateExponent")).isFalse();
            node.fields().forEachRemaining(entry -> assertNoMaterial(entry.getValue()));
        } else if (node.isArray()) {
            node.forEach(this::assertNoMaterial);
        }
    }
}
