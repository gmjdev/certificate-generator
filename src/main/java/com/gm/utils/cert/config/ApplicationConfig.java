package com.gm.utils.cert.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.gm.utils.cert.CertificateAuthority;

@Configuration
public class ApplicationConfig {

    @Bean
    CertificateAuthority authority() {
        return new CertificateAuthority();
    }
}
