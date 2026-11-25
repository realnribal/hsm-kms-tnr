package io.github.realnribal.hsmkms.hsm;

import io.github.realnribal.hsmkms.pkcs11.Ck;
import io.github.realnribal.hsmkms.pkcs11.CkException;
import io.github.realnribal.hsmkms.web.dto.ApiModels.CreateKeyRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.DecryptRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.DecryptResponse;
import io.github.realnribal.hsmkms.web.dto.ApiModels.EncryptRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.EncryptResponse;
import io.github.realnribal.hsmkms.web.dto.ApiModels.SignRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.SignResponse;
import io.github.realnribal.hsmkms.web.dto.ApiModels.UnwrapRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.VerifyRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.VerifyResponse;
import io.github.realnribal.hsmkms.web.dto.ApiModels.WrapRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.WrapResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

@Service
public class KmsService {

    private static final Logger log = LoggerFactory.getLogger(KmsService.class);
    private static final int MAX_PAYLOAD = 1_048_576;
    private static final Set<Usage> AES_USAGES = EnumSet.of(Usage.ENCRYPT, Usage.DECRYPT, Usage.WRAP, Usage.UNWRAP);
    private static final Set<Usage> RSA_USAGES = EnumSet.of(Usage.SIGN, Usage.VERIFY, Usage.WRAP, Usage.UNWRAP);
    private static final Set<Usage> EC_USAGES = EnumSet.of(Usage.SIGN, Usage.VERIFY);

    private final TokenClient token;
    private final SecureRandom random = new SecureRandom();

    public KmsService(TokenClient token) {
        this.token = token;
    }

    public TokenInfo tokenInfo() {
        return op("health", null, token::info);
    }

    public StoredKey create(CreateKeyRequest request) {
        String alias = request.alias();
        return op("createKey", alias, () -> {
            Set<Usage> usages = usages(request.usages());
            StoredKey created = switch (request.algorithm()) {
                case AES -> {
                    int size = request.size() == null ? 0 : request.size();
                    if (size != 128 && size != 256) {
                        throw KmsException.validation("AES size must be 128 or 256");
                    }
                    requireUsages(usages, AES_USAGES, "AES");
                    yield token.createAes(alias, size, KeyUse.of(request.extractable(), usages));
                }
                case RSA -> {
                    int size = request.size() == null ? 0 : request.size();
                    if (size != 2048) {
                        throw KmsException.validation("RSA size must be 2048");
                    }
                    if (request.extractable()) {
                        throw KmsException.validation("RSA private keys are not extractable in this lab");
                    }
                    requireUsages(usages, RSA_USAGES, "RSA");
                    yield token.createRsa(alias, size, KeyUse.of(false, usages));
                }
                case EC -> {
                    String curve = request.curve() == null ? "secp256r1" : request.curve();
                    if (!"secp256r1".equals(curve)) {
                        throw KmsException.validation("EC curve must be secp256r1");
                    }
                    if (request.extractable()) {
                        throw KmsException.validation("EC private keys are not extractable in this lab");
                    }
                    requireUsages(usages, EC_USAGES, "EC");
                    yield token.createEc(alias, KeyUse.of(false, usages));
                }
            };
            log.info("key created algorithm={} objectType={}", created.algorithm(), created.objectType());
            return created;
        });
    }

    public List<StoredKey> list() {
        return op("listKeys", null, token::list);
    }

    public StoredKey get(String alias) {
        return op("getKey", alias, () -> token.require(alias));
    }

    public void delete(String alias) {
        op("deleteKey", alias, () -> {
            token.delete(alias);
            log.info("key deleted");
            return null;
        });
    }

    public EncryptResponse encrypt(EncryptRequest request) {
        return op("encrypt", request.alias(), () -> {
            StoredKey key = token.require(request.alias());
            if (!"AES".equals(key.algorithm())) {
                throw KmsException.mechanismMismatch("AES_CBC_PAD does not apply to " + key.algorithm());
            }
            byte[] plaintext = decode(request.data(), MAX_PAYLOAD);
            byte[] iv = request.iv() == null ? randomIv() : decode(request.iv(), 16);
            if (iv.length != 16) {
                throw KmsException.validation("AES-CBC IV must be 16 bytes");
            }
            byte[] cipher = token.encrypt(request.alias(), iv, plaintext);
            log.info("encrypt plaintextBytes={} cipherBytes={}", plaintext.length, cipher.length);
            return new EncryptResponse("AES_CBC_PAD", b64(iv), b64(cipher));
        });
    }

    public DecryptResponse decrypt(DecryptRequest request) {
        return op("decrypt", request.alias(), () -> {
            StoredKey key = token.require(request.alias());
            if (!"AES".equals(key.algorithm())) {
                throw KmsException.mechanismMismatch("AES_CBC_PAD does not apply to " + key.algorithm());
            }
            byte[] iv = decode(request.iv(), 16);
            if (iv.length != 16) {
                throw KmsException.validation("AES-CBC IV must be 16 bytes");
            }
            byte[] cipher = decode(request.data(), MAX_PAYLOAD);
            byte[] plain = token.decrypt(request.alias(), iv, cipher);
            log.info("decrypt cipherBytes={} plaintextBytes={}", cipher.length, plain.length);
            return new DecryptResponse(b64(plain));
        });
    }

    public SignResponse sign(SignRequest request) {
        return op("sign", request.alias(), () -> {
            StoredKey key = token.require(request.alias());
            byte[] message = decode(request.data(), MAX_PAYLOAD);
            PreparedSign prepared = prepareSign(request.mechanism(), key, message);
            byte[] signature = token.sign(request.alias(), prepared.mechanism(), prepared.payload(), prepared.size());
            log.info("sign mechanism={} dataBytes={} signatureBytes={}", request.mechanism(), message.length, signature.length);
            return new SignResponse(request.mechanism().name(), b64(signature));
        });
    }

    public VerifyResponse verify(VerifyRequest request) {
        return op("verify", request.alias(), () -> {
            StoredKey key = token.require(request.alias());
            byte[] message = decode(request.data(), MAX_PAYLOAD);
            byte[] signature = decode(request.signature(), 1024);
            PreparedSign prepared = prepareSign(request.mechanism(), key, message);
            boolean valid = token.verify(request.alias(), prepared.mechanism(), prepared.payload(), signature);
            log.info("verify mechanism={} valid={}", request.mechanism(), valid);
            return new VerifyResponse(request.mechanism().name(), valid);
        });
    }

    public WrapResponse wrap(WrapRequest request) {
        return op("wrap", request.targetKeyAlias(), () -> {
            StoredKey wrapping = token.require(request.wrappingKeyAlias());
            boolean rsa = request.mechanism() == WrapMechanism.RSA_PKCS;
            if (rsa && !"RSA".equals(wrapping.algorithm())) {
                throw KmsException.mechanismMismatch("RSA_PKCS wrap requires an RSA key");
            }
            if (!rsa && !"AES".equals(wrapping.algorithm())) {
                throw KmsException.mechanismMismatch("AES_KEY_WRAP requires an AES key");
            }
            long mechanism = rsa ? Ck.CKM_RSA_PKCS : Ck.CKM_AES_KEY_WRAP;
            byte[] wrapped = token.wrap(request.wrappingKeyAlias(), mechanism, request.targetKeyAlias(), rsa);
            log.info("wrap mechanism={} wrappedBytes={}", request.mechanism(), wrapped.length);
            return new WrapResponse(request.mechanism().name(), b64(wrapped));
        });
    }

    public StoredKey unwrap(UnwrapRequest request) {
        return op("unwrap", request.targetAlias(), () -> {
            if (request.targetAlgorithm() != Algorithm.AES) {
                throw KmsException.validation("unwrap target must be AES");
            }
            StoredKey wrapping = token.require(request.wrappingKeyAlias());
            boolean rsa = request.mechanism() == WrapMechanism.RSA_PKCS;
            if (rsa && !"RSA".equals(wrapping.algorithm())) {
                throw KmsException.mechanismMismatch("RSA_PKCS unwrap requires an RSA key");
            }
            if (!rsa && !"AES".equals(wrapping.algorithm())) {
                throw KmsException.mechanismMismatch("AES_KEY_WRAP unwrap requires an AES key");
            }
            Set<Usage> usages = usages(request.usages());
            requireUsages(usages, AES_USAGES, "AES");
            byte[] wrapped = decode(request.wrappedKey(), 4096);
            long mechanism = rsa ? Ck.CKM_RSA_PKCS : Ck.CKM_AES_KEY_WRAP;
            StoredKey restored = token.unwrapAes(
                    request.wrappingKeyAlias(), mechanism, wrapped, request.targetAlias(),
                    KeyUse.of(request.extractable(), usages), rsa);
            if (request.targetSize() != null && restored.sizeBits() > 0
                    && request.targetSize() != restored.sizeBits()) {
                token.delete(request.targetAlias());
                throw KmsException.validation("unwrapped key size does not match targetSize");
            }
            if (restored.sizeBits() == 0 && request.targetSize() != null) {
                restored = new StoredKey(restored.alias(), restored.algorithm(), restored.objectType(),
                        request.targetSize(), restored.curve(), restored.sensitive(), restored.extractable(),
                        restored.token(), restored.usages());
            }
            log.info("unwrap mechanism={} sizeBits={}", request.mechanism(), restored.sizeBits());
            return restored;
        });
    }

    /**
     * SoftHSM 2.6 advertises {@code CKM_ECDSA} and not {@code CKM_ECDSA_SHA256}.
     * The service hashes with SHA-256 and the token signs the 32-byte digest.
     * RSA uses {@code CKM_SHA256_RSA_PKCS}, which hashes inside the token.
     */
    private PreparedSign prepareSign(SignMechanism mechanism, StoredKey key, byte[] message) {
        return switch (mechanism) {
            case SHA256withRSA -> {
                if (!"RSA".equals(key.algorithm())) {
                    throw KmsException.mechanismMismatch("SHA256withRSA does not apply to " + key.algorithm());
                }
                yield new PreparedSign(Ck.CKM_SHA256_RSA_PKCS, message, key.sizeBits() / 8);
            }
            case SHA256withECDSA -> {
                if (!"EC".equals(key.algorithm())) {
                    throw KmsException.mechanismMismatch("SHA256withECDSA does not apply to " + key.algorithm());
                }
                yield new PreparedSign(Ck.CKM_ECDSA, sha256(message), 64);
            }
        };
    }

    private byte[] sha256(byte[] message) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private byte[] randomIv() {
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

    private static Set<Usage> usages(List<Usage> requested) {
        if (requested == null || requested.isEmpty() || requested.contains(null)) {
            throw KmsException.validation("usages are required");
        }
        return EnumSet.copyOf(requested);
    }

    private static void requireUsages(Set<Usage> actual, Set<Usage> allowed, String algorithm) {
        if (!allowed.containsAll(actual)) {
            throw KmsException.validation("usages are not allowed for " + algorithm);
        }
    }

    private static byte[] decode(String value, int max) {
        if (value == null || value.isBlank()) {
            throw KmsException.validation("expected base64");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length == 0 || decoded.length > max) {
                throw KmsException.validation("payload size is out of range");
            }
            return decoded;
        } catch (IllegalArgumentException ex) {
            throw KmsException.validation("expected base64");
        }
    }

    private static String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private <T> T op(String name, String alias, Supplier<T> work) {
        MDC.put("op", name);
        if (alias != null) {
            MDC.put("alias", alias);
        }
        try {
            return work.get();
        } catch (KeyNotFoundException ex) {
            log.info("key not found");
            throw KmsException.notFound(alias == null ? ex.getMessage() : alias);
        } catch (DuplicateAliasException ex) {
            log.info("duplicate alias");
            throw KmsException.duplicate(alias == null ? ex.getMessage() : alias);
        } catch (CkException ex) {
            log.warn("hsm rejected ckR={} ckRv=0x{}", ex.rvName(), Long.toHexString(ex.rv()));
            throw KmsException.fromCk(ex);
        } finally {
            MDC.remove("op");
            MDC.remove("alias");
        }
    }

    private record PreparedSign(long mechanism, byte[] payload, int size) {
    }
}
