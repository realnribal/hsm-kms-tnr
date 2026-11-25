package io.github.realnribal.hsmkms.config;

import io.github.realnribal.hsmkms.hsm.TokenClient;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({HsmProperties.class, KmsProperties.class})
public class HsmConfiguration {

    @Bean(destroyMethod = "close")
    public TokenClient tokenClient(HsmProperties properties) {
        return TokenClient.open(properties.library(), properties.tokenLabel(), properties.userPin());
    }
}
