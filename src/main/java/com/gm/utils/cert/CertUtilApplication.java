package com.gm.utils.cert;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.annotation.PostConstruct;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.gm.utils.cert.util.SystemUtil;

@SpringBootApplication
public class CertUtilApplication {
    @Autowired
    private CertificateAuthority authority;
    private static final char[] DEFAULT_PHRASE = "changeit".toCharArray();
    private static final String KEY_ALGORITHM = "RSA";
    @Value("${certs.org-prefix:localhost}")
    private String org;

    public static void main(String[] args) {
        SpringApplication.run(CertUtilApplication.class, args);
    }

    @PostConstruct
    public void generateCertificate() {
        try {
            KeyPair kp = authority.generateKeyPair(KEY_ALGORITHM, 2048);
            String baseDirectory = FileUtils.getUserDirectoryPath();
            File certBaseDirectory = new File(baseDirectory, "certificates");
            Files.createDirectories(certBaseDirectory.toPath());
            X509Certificate rootCaCert = authority.createRootCaCertificate(kp, 365);
            CertificateWriter.getInstance().writePrivateKeyToPem(kp, new File(certBaseDirectory, "rootCa.key").getPath(), DEFAULT_PHRASE);
            CertificateWriter.getInstance().writeToPem(rootCaCert, new File(certBaseDirectory, "rootCa.cer").getPath());
            CertificateWriter.getInstance().writeToPkcs12Keystore(kp, new Certificate[] { rootCaCert }, org.concat("RootCA"),
                    new File(certBaseDirectory, "rootCa.pfx").getPath(), DEFAULT_PHRASE);

            KeyPair intermediatKp = authority.generateKeyPair(KEY_ALGORITHM, 2048);
            X509Certificate intermediateRootCaCert = authority.createIntermediateRootCa(rootCaCert, intermediatKp, kp.getPrivate(), 365);
            CertificateWriter.getInstance().writePrivateKeyToPem(intermediatKp, new File(certBaseDirectory, "intermediateRootCa.key").getPath(),
                    DEFAULT_PHRASE);
            CertificateWriter.getInstance().writeToPem(intermediateRootCaCert, new File(certBaseDirectory, "intermediateRootCa.cer").getPath());
            CertificateWriter.getInstance().writeToPkcs12Keystore(intermediatKp, new Certificate[] { intermediateRootCaCert },
                    org.concat("IntermediateRootCA"), new File(certBaseDirectory, "intermediateRootCa.pfx").getPath(), DEFAULT_PHRASE);

            KeyPair issuedCertificateKp = authority.generateKeyPair(KEY_ALGORITHM, 2048);
            String hostname = SystemUtil.getHostname();
            PKCS10CertificationRequest csrRequest = authority.createCsr(hostname, issuedCertificateKp, intermediatKp);
            if (null != csrRequest) {
                CertificateWriter.getInstance().writePrivateKeyToPem(issuedCertificateKp,
                        new File(certBaseDirectory, hostname.concat(".key")).getPath(), DEFAULT_PHRASE);
                CertificateWriter.getInstance().writeCsr(new File(certBaseDirectory, hostname.concat(".csr")).getPath(), csrRequest);
                X509Certificate issuedCertificate = authority.signCsrAndGenerateCertificate(csrRequest, intermediatKp.getPrivate(),
                        intermediateRootCaCert, hostname);
                CertificateWriter.getInstance().writeToPem(issuedCertificate, new File(certBaseDirectory, hostname.concat(".cer")).getPath());

                String certificatePath = new File(certBaseDirectory, hostname.concat(".pfx")).getPath();
                Files.deleteIfExists(Paths.get(certificatePath));
                CertificateWriter.getInstance().writeToPkcs12Keystore(kp, new Certificate[] { rootCaCert }, org.concat("RootCA"), certificatePath,
                        DEFAULT_PHRASE);
                CertificateWriter.getInstance().writeToPkcs12Keystore(intermediatKp, new Certificate[] { intermediateRootCaCert, rootCaCert },
                        org.concat("IntermediateRootCA"), certificatePath, DEFAULT_PHRASE);
                X509Certificate[] chain = new X509Certificate[] { issuedCertificate, intermediateRootCaCert, rootCaCert };
                CertificateWriter.getInstance().writeToPkcs12Keystore(issuedCertificateKp, chain, hostname, certificatePath, DEFAULT_PHRASE);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
