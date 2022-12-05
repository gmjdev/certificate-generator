package com.gm.utils.cert;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Optional;

import javax.annotation.PostConstruct;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.Assert;

import com.gm.utils.cert.dto.CertificateDetailHolder;
import com.gm.utils.cert.exception.CertificateCreationException;
import com.gm.utils.cert.util.KeyStoreUtil;
import com.gm.utils.cert.util.SystemUtil;

@SpringBootApplication
public class CertUtilApplication {
    private static final int DEFAULT_KEYSIZE = 2048;
    private static final String INTERMEDIATE_ROOT_CA_PFX_FILE_NAME = "intermediateRootCa.pfx";
    private static final String ROOT_CA_PFX_FILE_NAME = "rootCa.pfx";
    @Autowired
    private CertificateAuthority authority;
    @Value("${certs.org-prefix:localhost}")
    private String org;
    @Value("${certs.phrase:changeit}")
    private String phrase;
    private static final Logger LOG = LoggerFactory.getLogger(CertUtilApplication.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(CertUtilApplication.class, args);
    }

    @PostConstruct
    public void generateCertificate() {
        createCertificate();
    }

    private void createRootCaAndWriteToFile(String directory, char[] phrase) {
        File rootCaPfx = new File(directory, ROOT_CA_PFX_FILE_NAME);
        if (rootCaPfx.exists()) {
            LOG.warn("RootCA Authority already exists skipping creating new.");
            return;
        }

        try {
            LOG.info("RootCA Keystore file does not exists creating new RootCA Authority.");
            KeyPair rootCaKp = KeyPairGeneratorUtil.generateBcRsaKeyPair(DEFAULT_KEYSIZE);
            X509Certificate rootCaCert = authority.createRootCaCertificate(rootCaKp, 365 * 10);
            CertificateWriter.getInstance().writePrivateKeyToPem(rootCaKp, new File(directory, "rootCa.key").getPath(), phrase);
            CertificateWriter.getInstance().toPEM(rootCaCert, new File(directory, "rootCa.cer").getPath());
            CertificateWriter.getInstance().writeToPkcs12Keystore(rootCaKp, new Certificate[] { rootCaCert }, org.concat("RootCA"),
                    rootCaPfx.getPath(), phrase);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createIntermediateCaAndWriteToFile(String directory, char[] phrase, PrivateKey issuerKey, X509Certificate[] issuerCertificate) {
        File intermediatRootCaPfx = new File(directory, INTERMEDIATE_ROOT_CA_PFX_FILE_NAME);
        if (intermediatRootCaPfx.exists()) {
            LOG.warn("IntermediateRootCA Authority already exists skipping creating new.");
            return;
        }

        try {
            Assert.notNull(issuerKey, "Issuer PrivateKey is null");
            Assert.notNull(issuerCertificate, "Issuer Certificate is null");
            LOG.info("IntermediateRootCA Keystore file does not exists creating new IntermediateRootCA Authority.");
            KeyPair intermediatKp = KeyPairGeneratorUtil.generateBcRsaKeyPair(DEFAULT_KEYSIZE);
            X509Certificate intermediateRootCaCert = authority.createIntermediateRootCa(issuerCertificate[0], intermediatKp, issuerKey, 365 * 5);
            CertificateWriter.getInstance().writePrivateKeyToPem(intermediatKp, new File(directory, "intermediateRootCa.key").getPath(), phrase);
            CertificateWriter.getInstance().toPEM(intermediateRootCaCert, new File(directory, "intermediateRootCa.cer").getPath());
            X509Certificate[] chain = ArrayUtils.addAll(new X509Certificate[] { intermediateRootCaCert }, issuerCertificate);
            CertificateWriter.getInstance().writeToPkcs12Keystore(intermediatKp, chain, org.concat("IntermediateRootCA"),
                    intermediatRootCaPfx.getPath(), phrase);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createIssuedToCertificateAndWriteToFile(String directory, String issuedTo, char[] phrase, PrivateKey issuerKey,
            X509Certificate[] issuerCertificate) {
        File issuedCertificateFile = new File(directory, issuedTo.concat(".pfx"));
        if (issuedCertificateFile.exists()) {
            LOG.warn("Certificate for Hostname: {} already exists, skipping creating new", issuedTo);
            return;
        }

        try {
            LOG.warn("Creating Certificate for Hostname: {}", issuedTo);

            KeyPair issuedCertificateKp = KeyPairGeneratorUtil.generateBcRsaKeyPair(DEFAULT_KEYSIZE);
            PKCS10CertificationRequest csrRequest = authority.createCsr(issuedTo, issuedCertificateKp, "SHA256withRSA");
            if (null == csrRequest) {
                throw new CertificateCreationException("No valid CSR exists");
            }
            CertificateWriter.getInstance().writePrivateKeyToPem(issuedCertificateKp, new File(directory, issuedTo.concat(".key")).getPath(), phrase);
            CertificateWriter.getInstance().writeCsr(new File(directory, issuedTo.concat(".csr")).getPath(), csrRequest);
            X509Certificate issuedCertificate = authority.signCsrAndGenerateCertificate(csrRequest, issuerKey, issuerCertificate[0], issuedTo);
            CertificateWriter.getInstance().toPEM(issuedCertificate, new File(directory, issuedTo.concat(".cer")).getPath());

            String certificatePath = issuedCertificateFile.getPath();
            Files.deleteIfExists(Paths.get(certificatePath));
            X509Certificate[] chain = ArrayUtils.addAll(new X509Certificate[] { issuedCertificate }, issuerCertificate);
            CertificateWriter.getInstance().writeToPkcs12Keystore(issuedCertificateKp, chain, issuedTo, certificatePath, phrase);
            KeyStoreUtil.storeCertificate(certificatePath, phrase, new X509Certificate[] { issuedCertificate });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createCertificate() {
        char[] phraseArr = phrase.toCharArray();
        String baseDirectory = FileUtils.getUserDirectoryPath();
        File certBaseDirectory = new File(baseDirectory, "certificates");
        try {
            Files.createDirectories(certBaseDirectory.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }

        createRootCaAndWriteToFile(certBaseDirectory.getPath(), phraseArr);

        Optional<CertificateDetailHolder> issuerKeyOpt = KeyStoreUtil
                .getPrivateKeyAnCertificateChain(new File(certBaseDirectory, ROOT_CA_PFX_FILE_NAME).getPath(), org.concat("RootCA"), phraseArr);
        if (!issuerKeyOpt.isPresent()) {
            throw new IllegalArgumentException("Issuer does not exists");
        }

        createIntermediateCaAndWriteToFile(certBaseDirectory.getPath(), phraseArr, issuerKeyOpt.get().getPrivateKey(),
                (X509Certificate[]) issuerKeyOpt.get().getCertificateChain());

        String hostname = SystemUtil.getHostname();
        Optional<CertificateDetailHolder> intermediateIssuerDetailOpt = KeyStoreUtil.getPrivateKeyAnCertificateChain(
                new File(certBaseDirectory, INTERMEDIATE_ROOT_CA_PFX_FILE_NAME).getPath(), org.concat("IntermediateRootCA"), phraseArr);
        if (!intermediateIssuerDetailOpt.isPresent()) {
            throw new IllegalArgumentException("Unable to get issuer certificate to generate certificate");
        }
        createIssuedToCertificateAndWriteToFile(certBaseDirectory.getPath(), hostname, phraseArr, intermediateIssuerDetailOpt.get().getPrivateKey(),
                (X509Certificate[]) intermediateIssuerDetailOpt.get().getCertificateChain());

    }
}
