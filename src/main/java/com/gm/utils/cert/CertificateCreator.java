package com.gm.utils.cert;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public interface CertificateCreator {
    KeyPair generateKeyPair(String algorithm, int keySize);

    X509Certificate createRootCa();

    X509Certificate createIntermediateRootCa();

    X509Certificate createCertificate(X509Certificate issuerCertificate, int expiryInDays);
}
