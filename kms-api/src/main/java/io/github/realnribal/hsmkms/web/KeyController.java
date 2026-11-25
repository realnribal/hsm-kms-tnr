package io.github.realnribal.hsmkms.web;

import io.github.realnribal.hsmkms.hsm.KmsService;
import io.github.realnribal.hsmkms.hsm.StoredKey;
import io.github.realnribal.hsmkms.web.dto.ApiModels.CreateKeyRequest;
import io.github.realnribal.hsmkms.web.dto.ApiModels.KeysResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/keys")
public class KeyController {

    private final KmsService kms;

    public KeyController(KmsService kms) {
        this.kms = kms;
    }

    @PostMapping
    public ResponseEntity<StoredKey> create(@Valid @RequestBody CreateKeyRequest request) {
        StoredKey created = kms.create(request);
        return ResponseEntity.created(URI.create("/api/v1/keys/" + created.alias())).body(created);
    }

    @GetMapping
    public KeysResponse list() {
        return new KeysResponse(kms.list());
    }

    @GetMapping("/{alias:[A-Za-z0-9][A-Za-z0-9._-]{0,63}}")
    public StoredKey get(@PathVariable String alias) {
        return kms.get(alias);
    }

    @DeleteMapping("/{alias:[A-Za-z0-9][A-Za-z0-9._-]{0,63}}")
    public ResponseEntity<Void> delete(@PathVariable String alias) {
        kms.delete(alias);
        return ResponseEntity.noContent().build();
    }
}
