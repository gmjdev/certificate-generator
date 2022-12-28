package com.gm.utils.cert.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@ConfigurationProperties(prefix = "certs", ignoreUnknownFields = true)
public class CertsProperties {
    private String orgPrefix = "LocalhostDev";
    private String phrase = "changeit";
    private CertificateProperties rootCa = new CertificateProperties(5, "rootca", phrase);
    private CertificateProperties intermediateCa = new CertificateProperties(2, "intermediateca", phrase);
    private CertificateProperties issuedTo = new CertificateProperties(1, "server", phrase);
    private SanEntries san = new SanEntries("accounts.intern", true, true, true);
}
