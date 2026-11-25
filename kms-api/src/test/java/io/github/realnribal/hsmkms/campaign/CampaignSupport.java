package io.github.realnribal.hsmkms.campaign;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.realnribal.hsmkms.hsm.Algorithm;
import io.github.realnribal.hsmkms.hsm.TokenClient;
import io.github.realnribal.hsmkms.hsm.Usage;
import io.github.realnribal.hsmkms.web.dto.ApiModels.CreateKeyRequest;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class CampaignSupport {

    static final String WRONG_PIN = "WRONG-PIN-SENTINEL";
    static final String WRONG_KEY = "super-secret-wrong-key-zzz";

    @Autowired
    protected TestRestTemplate rest;

    @Autowired
    protected ObjectMapper mapper;

    @Autowired
    protected TokenClient tokenClient;

    @Value("${kms.api-key}")
    protected String apiKey;

    @Value("${hsm.user-pin}")
    protected String userPin;

    private final List<String> aliases = new ArrayList<>();

    @AfterEach
    void deleteCreatedKeys() {
        for (String alias : aliases) {
            rest.exchange("/api/v1/keys/" + alias, HttpMethod.DELETE, new HttpEntity<>(headers()), String.class);
        }
        aliases.clear();
    }

    protected String alias(String prefix) {
        String value = prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
        aliases.add(value);
        return value;
    }

    protected void track(String alias) {
        aliases.add(alias);
    }

    protected HttpHeaders headers() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-API-Key", apiKey);
        return headers;
    }

    protected ResponseEntity<String> post(String path, Object body) {
        return rest.exchange(path, HttpMethod.POST, new HttpEntity<>(body, headers()), String.class);
    }

    protected ResponseEntity<String> get(String path) {
        return rest.exchange(path, HttpMethod.GET, new HttpEntity<>(headers()), String.class);
    }

    protected JsonNode json(ResponseEntity<String> response) throws Exception {
        return mapper.readTree(response.getBody());
    }

    protected ResponseEntity<String> createKey(String alias, Algorithm algorithm, Integer size, String curve,
                                               boolean extractable, List<Usage> usages) {
        return post("/api/v1/keys", new CreateKeyRequest(alias, algorithm, size, curve, extractable, usages));
    }
}
