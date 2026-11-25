package io.github.realnribal.hsmkms.campaign;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.realnribal.hsmkms.hsm.Algorithm;
import io.github.realnribal.hsmkms.hsm.EncryptMechanism;
import io.github.realnribal.hsmkms.hsm.SignMechanism;
import io.github.realnribal.hsmkms.hsm.Usage;
import io.github.realnribal.hsmkms.hsm.WrapMechanism;
import io.github.realnribal.hsmkms.web.dto.ApiModels.DecryptRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.EncryptRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.SignRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.UnwrapRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.VerifyRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.WrapRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("functional")
class CryptoCampaignTest extends CampaignSupport {

    private static final String PLAIN = "The validation bench seals this payload.";

    @Test
    @Requirement("REQ-ENC-001")
    @DisplayName("REQ-ENC-001 AES-CBC-PAD round trip")
    void aesCbcRoundTrip() throws Exception {
        String name = alias("dek");
        createKey(name, Algorithm.AES, 256, null, false, List.of(Usage.ENCRYPT, Usage.DECRYPT));
        ResponseEntity<String> encrypted = post("/api/v1/crypto/encrypt",
                new EncryptRequest(name, EncryptMechanism.AES_CBC_PAD, b64(PLAIN), null));
        assertThat(encrypted.getStatusCode().value()).isEqualTo(200);
        JsonNode cipher = json(encrypted);
        assertThat(cipher.get("iv").asText()).isNotBlank();
        ResponseEntity<String> decrypted = post("/api/v1/crypto/decrypt", new DecryptRequest(
                name, EncryptMechanism.AES_CBC_PAD, cipher.get("ciphertext").asText(), cipher.get("iv").asText()));
        assertThat(decrypted.getStatusCode().value()).isEqualTo(200);
        assertThat(decode(json(decrypted).get("plaintext").asText())).isEqualTo(PLAIN);
    }

    @Test
    @Requirement("REQ-WRAP-001")
    @DisplayName("REQ-WRAP-001 AES key wrap survives deletion of the original key")
    void aesKeyWrapRoundTrip() throws Exception {
        String kek = alias("kek");
        String dek = alias("dek");
        createKey(kek, Algorithm.AES, 256, null, false, List.of(Usage.WRAP, Usage.UNWRAP));
        createKey(dek, Algorithm.AES, 256, null, true, List.of(Usage.ENCRYPT, Usage.DECRYPT));
        JsonNode cipher = json(post("/api/v1/crypto/encrypt",
                new EncryptRequest(dek, EncryptMechanism.AES_CBC_PAD, b64(PLAIN), null)));
        ResponseEntity<String> wrapped = post("/api/v1/crypto/wrap",
                new WrapRequest(kek, dek, WrapMechanism.AES_KEY_WRAP));
        assertThat(wrapped.getStatusCode().value()).isEqualTo(200);
        rest.exchange("/api/v1/keys/" + dek, org.springframework.http.HttpMethod.DELETE,
                new org.springframework.http.HttpEntity<>(headers()), String.class);
        String restored = alias("dek-restored");
        ResponseEntity<String> unwrapped = post("/api/v1/crypto/unwrap", new UnwrapRequest(
                kek, json(wrapped).get("wrappedKey").asText(), WrapMechanism.AES_KEY_WRAP, restored,
                Algorithm.AES, 256, true, List.of(Usage.ENCRYPT, Usage.DECRYPT)));
        assertThat(unwrapped.getStatusCode().value()).isEqualTo(201);
        JsonNode plain = json(post("/api/v1/crypto/decrypt", new DecryptRequest(
                restored, EncryptMechanism.AES_CBC_PAD, cipher.get("ciphertext").asText(), cipher.get("iv").asText())));
        assertThat(decode(plain.get("plaintext").asText())).isEqualTo(PLAIN);
    }

    @Test
    @Tag("negative")
    @Requirement("REQ-WRAP-002")
    @DisplayName("REQ-WRAP-002 a non-extractable key cannot be wrapped")
    void nonExtractableKeyCannotBeWrapped() throws Exception {
        String kek = alias("kek");
        String locked = alias("locked");
        createKey(kek, Algorithm.AES, 256, null, false, List.of(Usage.WRAP, Usage.UNWRAP));
        createKey(locked, Algorithm.AES, 256, null, false, List.of(Usage.ENCRYPT, Usage.DECRYPT));
        ResponseEntity<String> wrapped = post("/api/v1/crypto/wrap",
                new WrapRequest(kek, locked, WrapMechanism.AES_KEY_WRAP));
        assertThat(wrapped.getStatusCode().value()).isEqualTo(400);
        JsonNode body = json(wrapped);
        assertThat(body.get("code").asText()).isEqualTo("KEY_NOT_EXTRACTABLE");
        assertThat(body.get("ckR").asText()).isEqualTo("CKR_KEY_UNEXTRACTABLE");
    }

    @Test
    @Requirement("REQ-WRAP-003")
    @DisplayName("REQ-WRAP-003 RSA-PKCS wrap of an AES key")
    void rsaWrapRoundTrip() throws Exception {
        String rsa = alias("rsa-wrap");
        String dek = alias("dek");
        createKey(rsa, Algorithm.RSA, 2048, null, false,
                List.of(Usage.WRAP, Usage.UNWRAP, Usage.SIGN, Usage.VERIFY));
        createKey(dek, Algorithm.AES, 256, null, true, List.of(Usage.ENCRYPT, Usage.DECRYPT));
        JsonNode cipher = json(post("/api/v1/crypto/encrypt",
                new EncryptRequest(dek, EncryptMechanism.AES_CBC_PAD, b64(PLAIN), null)));
        ResponseEntity<String> wrapped = post("/api/v1/crypto/wrap",
                new WrapRequest(rsa, dek, WrapMechanism.RSA_PKCS));
        assertThat(wrapped.getStatusCode().value()).isEqualTo(200);
        String restored = alias("dek-rsa");
        ResponseEntity<String> unwrapped = post("/api/v1/crypto/unwrap", new UnwrapRequest(
                rsa, json(wrapped).get("wrappedKey").asText(), WrapMechanism.RSA_PKCS, restored,
                Algorithm.AES, 256, true, List.of(Usage.DECRYPT)));
        assertThat(unwrapped.getStatusCode().value()).isEqualTo(201);
        JsonNode plain = json(post("/api/v1/crypto/decrypt", new DecryptRequest(
                restored, EncryptMechanism.AES_CBC_PAD, cipher.get("ciphertext").asText(), cipher.get("iv").asText())));
        assertThat(decode(plain.get("plaintext").asText())).isEqualTo(PLAIN);
    }

    @Test
    @Requirement("REQ-SIG-001")
    @DisplayName("REQ-SIG-001 RSA SHA-256 sign and verify")
    void rsaSignAndVerify() throws Exception {
        String name = alias("rsa-sign");
        createKey(name, Algorithm.RSA, 2048, null, false, List.of(Usage.SIGN, Usage.VERIFY));
        JsonNode signed = json(post("/api/v1/crypto/sign",
                new SignRequest(name, SignMechanism.SHA256withRSA, b64(PLAIN))));
        ResponseEntity<String> verified = post("/api/v1/crypto/verify", new VerifyRequest(
                name, SignMechanism.SHA256withRSA, b64(PLAIN), signed.get("signature").asText()));
        assertThat(verified.getStatusCode().value()).isEqualTo(200);
        assertThat(json(verified).get("valid").asBoolean()).isTrue();
    }

    @Test
    @Requirement("REQ-SIG-002")
    @DisplayName("REQ-SIG-002 ECDSA SHA-256 sign and verify")
    void ecdsaSignAndVerify() throws Exception {
        String name = alias("ec-sign");
        createKey(name, Algorithm.EC, null, "secp256r1", false, List.of(Usage.SIGN, Usage.VERIFY));
        JsonNode signed = json(post("/api/v1/crypto/sign",
                new SignRequest(name, SignMechanism.SHA256withECDSA, b64(PLAIN))));
        byte[] signature = Base64.getDecoder().decode(signed.get("signature").asText());
        assertThat(signature).hasSize(64);
        ResponseEntity<String> verified = post("/api/v1/crypto/verify", new VerifyRequest(
                name, SignMechanism.SHA256withECDSA, b64(PLAIN), signed.get("signature").asText()));
        assertThat(json(verified).get("valid").asBoolean()).isTrue();
    }

    @Test
    @Tag("negative")
    @Requirement("REQ-SIG-003")
    @DisplayName("REQ-SIG-003 a tampered signature does not verify")
    void tamperedSignatureIsRejected() throws Exception {
        String name = alias("tamper");
        createKey(name, Algorithm.RSA, 2048, null, false, List.of(Usage.SIGN, Usage.VERIFY));
        JsonNode signed = json(post("/api/v1/crypto/sign",
                new SignRequest(name, SignMechanism.SHA256withRSA, b64(PLAIN))));
        byte[] signature = Base64.getDecoder().decode(signed.get("signature").asText());
        signature[signature.length - 1] ^= 0x01;
        JsonNode verified = json(post("/api/v1/crypto/verify", new VerifyRequest(
                name, SignMechanism.SHA256withRSA, b64(PLAIN), Base64.getEncoder().encodeToString(signature))));
        assertThat(verified.get("valid").asBoolean()).isFalse();
    }

    @Test
    @Tag("negative")
    @Requirement("REQ-SIG-004")
    @DisplayName("REQ-SIG-004 the wrong key does not verify")
    void wrongKeyDoesNotVerify() throws Exception {
        String first = alias("sign-a");
        String second = alias("sign-b");
        createKey(first, Algorithm.EC, null, null, false, List.of(Usage.SIGN, Usage.VERIFY));
        createKey(second, Algorithm.EC, null, null, false, List.of(Usage.SIGN, Usage.VERIFY));
        JsonNode signed = json(post("/api/v1/crypto/sign",
                new SignRequest(first, SignMechanism.SHA256withECDSA, b64(PLAIN))));
        JsonNode verified = json(post("/api/v1/crypto/verify", new VerifyRequest(
                second, SignMechanism.SHA256withECDSA, b64(PLAIN), signed.get("signature").asText())));
        assertThat(verified.get("valid").asBoolean()).isFalse();
    }

    private static String b64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
