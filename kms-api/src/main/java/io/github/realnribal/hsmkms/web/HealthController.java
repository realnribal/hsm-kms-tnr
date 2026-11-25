package io.github.realnribal.hsmkms.web;

import io.github.realnribal.hsmkms.hsm.KmsService;
import io.github.realnribal.hsmkms.web.dto.ApiModels.HealthResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/health")
public class HealthController {

    private final KmsService kms;

    public HealthController(KmsService kms) {
        this.kms = kms;
    }

    @GetMapping
    public HealthResponse health() {
        return new HealthResponse("UP", kms.tokenInfo());
    }
}
