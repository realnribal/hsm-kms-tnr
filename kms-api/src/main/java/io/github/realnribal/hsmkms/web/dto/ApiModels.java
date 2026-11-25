package io.github.realnribal.hsmkms.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.github.realnribal.hsmkms.hsm.Algorithm;
import io.github.realnribal.hsmkms.hsm.EncryptMechanism;
import io.github.realnribal.hsmkms.hsm.SignMechanism;
import io.github.realnribal.hsmkms.hsm.TokenInfo;
import io.github.realnribal.hsmkms.hsm.Usage;
import io.github.realnribal.hsmkms.hsm.WrapMechanism;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.List;

public final class ApiModels {

    public static final String ALIAS = "[A-Za-z0-9][A-Za-z0-9._-]{0,63}";

    private ApiModels() {
    }

    public record CreateKeyRequest(
            @NotBlank @Pattern(regexp = ALIAS) String alias,
            @NotNull Algorithm algorithm,
            Integer size,
            String curve,
            boolean extractable,
            @NotEmpty List<Usage> usages) {
    }

    public record EncryptRequest(
            @NotBlank @Pattern(regexp = ALIAS) String alias,
            @NotNull EncryptMechanism mechanism,
            @NotBlank String data,
            String iv) {
    }

    public record EncryptResponse(String mechanism, String iv, String ciphertext) {
    }

    public record DecryptRequest(
            @NotBlank @Pattern(regexp = ALIAS) String alias,
            @NotNull EncryptMechanism mechanism,
            @NotBlank String data,
            @NotBlank String iv) {
    }

    public record DecryptResponse(String plaintext) {
    }

    public record SignRequest(
            @NotBlank @Pattern(regexp = ALIAS) String alias,
            @NotNull SignMechanism mechanism,
            @NotBlank String data) {
    }

    public record SignResponse(String mechanism, String signature) {
    }

    public record VerifyRequest(
            @NotBlank @Pattern(regexp = ALIAS) String alias,
            @NotNull SignMechanism mechanism,
            @NotBlank String data,
            @NotBlank String signature) {
    }

    public record VerifyResponse(String mechanism, boolean valid) {
    }

    public record WrapRequest(
            @NotBlank @Pattern(regexp = ALIAS) String wrappingKeyAlias,
            @NotBlank @Pattern(regexp = ALIAS) String targetKeyAlias,
            @NotNull WrapMechanism mechanism) {
    }

    public record WrapResponse(String mechanism, String wrappedKey) {
    }

    public record UnwrapRequest(
            @NotBlank @Pattern(regexp = ALIAS) String wrappingKeyAlias,
            @NotBlank String wrappedKey,
            @NotNull WrapMechanism mechanism,
            @NotBlank @Pattern(regexp = ALIAS) String targetAlias,
            @NotNull Algorithm targetAlgorithm,
            Integer targetSize,
            boolean extractable,
            @NotEmpty List<Usage> usages) {
    }

    public record KeysResponse(List<io.github.realnribal.hsmkms.hsm.StoredKey> keys) {
    }

    public record HealthResponse(String status, TokenInfo pkcs11) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ErrorResponse(String code, String message, String traceId, String ckR) {
    }
}
