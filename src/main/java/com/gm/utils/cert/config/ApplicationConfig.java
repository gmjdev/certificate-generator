package com.gm.utils.cert.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.gm.utils.cert.CertificateAuthority;
import com.gm.utils.cert.CertificateInstaller;

@Configuration
public class ApplicationConfig {

    @Bean
    CertificateAuthority authority() {
        return new CertificateAuthority();
    }

    @Bean
    CertificateInstaller certificateInstaller() {
        return new CertificateInstaller();
    }

}
