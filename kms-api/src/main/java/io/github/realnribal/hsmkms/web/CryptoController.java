package io.github.realnribal.hsmkms.web;

import io.github.realnribal.hsmkms.hsm.KmsService;
import io.github.realnribal.hsmkms.hsm.StoredKey;
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
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

    private final KmsService kms;

    public CryptoController(KmsService kms) {
        this.kms = kms;
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@Valid @RequestBody EncryptRequest request) {
        return kms.encrypt(request);
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@Valid @RequestBody DecryptRequest request) {
        return kms.decrypt(request);
    }

    @PostMapping("/sign")
    public SignResponse sign(@Valid @RequestBody SignRequest request) {
        return kms.sign(request);
    }

    @PostMapping("/verify")
    public VerifyResponse verify(@Valid @RequestBody VerifyRequest request) {
        return kms.verify(request);
    }

    @PostMapping("/wrap")
    public WrapResponse wrap(@Valid @RequestBody WrapRequest request) {
        return kms.wrap(request);
    }

    @PostMapping("/unwrap")
    public ResponseEntity<StoredKey> unwrap(@Valid @RequestBody UnwrapRequest request) {
        StoredKey restored = kms.unwrap(request);
        return ResponseEntity.created(URI.create("/api/v1/keys/" + restored.alias())).body(restored);
    }
}
