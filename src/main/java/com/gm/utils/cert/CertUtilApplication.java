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

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.util.Assert;

import com.gm.utils.cert.constants.Constants;
import com.gm.utils.cert.dto.CertificateDetailHolder;
import com.gm.utils.cert.exception.CertificateCreationException;
import com.gm.utils.cert.properties.CertsProperties;
import com.gm.utils.cert.util.KeyStoreUtil;
import com.gm.utils.cert.util.SystemUtil;

import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@ConfigurationPropertiesScan(basePackages = { "com.gm.utils.cert.properties" })
@Slf4j
public class CertUtilApplication {
    @Autowired
    private CertificateAuthority authority;
    private static final Logger LOG = LoggerFactory.getLogger(CertUtilApplication.class);
    @Autowired
    private CertsProperties certProp;
    @Autowired
    private CertificateInstaller certificateInstaller;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(CertUtilApplication.class, args);
    }

    @Bean
    ApplicationRunner consoleRunner() {
        return args -> {
            if (args.containsOption("createCertificate")) {
                log.info("Creating Certificates...");
                createCertificate();
                log.debug("Creation of certificates completed successfully");
            } else if (args.containsOption("installCertificate")) {
                log.info("Validating server reachability...");
                certificateInstaller.performHostReachability(args.getOptionValues("host").get(0),
                        Integer.parseInt(args.getOptionValues("port").get(0)));
            }
        };
    }

    private void createRootCaAndWriteToFile(String directory, char[] phrase) {
        File rootCaPfx = new File(directory, certProp.getRootCa().getFileName().concat(Constants.PFX_EXTENSION));
        if (rootCaPfx.exists()) {
            LOG.warn("RootCA Authority already exists skipping creating new.");
            return;
        }

        try {
            LOG.info("RootCA Keystore file does not exists creating new RootCA Authority.");
            KeyPair rootCaKp = KeyPairGeneratorUtil.generateBcRsaKeyPair(Constants.DEFAULT_KEYSIZE);
            X509Certificate rootCaCert = authority.createRootCaCertificate(rootCaKp, certProp.getRootCa().getValidityInYear() * 365);
            CertificateWriter.getInstance().writePrivateKeyToPem(rootCaKp,
                    new File(directory, certProp.getRootCa().getFileName().concat(Constants.KEY_EXTENSION)).getPath(), phrase);
            CertificateWriter.getInstance().toPEM(rootCaCert,
                    new File(directory, certProp.getRootCa().getFileName().concat(Constants.CER_EXTENSION)).getPath());
            CertificateWriter.getInstance().writeToPkcs12Keystore(rootCaKp, new Certificate[] { rootCaCert },
                    certProp.getOrgPrefix().concat("RootCA"), rootCaPfx.getPath(), phrase);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createIntermediateCaAndWriteToFile(String directory, char[] phrase, PrivateKey issuerKey, X509Certificate[] issuerCertificate) {
        File intermediatRootCaPfx = new File(directory, certProp.getIntermediateCa().getFileName().concat(Constants.PFX_EXTENSION));
        if (intermediatRootCaPfx.exists()) {
            LOG.warn("IntermediateRootCA Authority already exists skipping creating new.");
            return;
        }

        try {
            Assert.notNull(issuerKey, "Issuer PrivateKey is null");
            Assert.notNull(issuerCertificate, "Issuer Certificate is null");
            LOG.info("IntermediateRootCA Keystore file does not exists creating new IntermediateRootCA Authority.");
            KeyPair intermediatKp = KeyPairGeneratorUtil.generateBcRsaKeyPair(Constants.DEFAULT_KEYSIZE);
            X509Certificate intermediateRootCaCert = authority.createIntermediateRootCa(issuerCertificate[0], intermediatKp, issuerKey,
                    certProp.getIntermediateCa().getValidityInYear() * 365);
            CertificateWriter.getInstance().writePrivateKeyToPem(intermediatKp,
                    new File(directory, certProp.getIntermediateCa().getFileName().concat(Constants.KEY_EXTENSION)).getPath(), phrase);
            CertificateWriter.getInstance().toPEM(intermediateRootCaCert,
                    new File(directory, certProp.getIntermediateCa().getFileName().concat(Constants.CER_EXTENSION)).getPath());
            X509Certificate[] chain = ArrayUtils.addAll(new X509Certificate[] { intermediateRootCaCert }, issuerCertificate);
            CertificateWriter.getInstance().writeToPkcs12Keystore(intermediatKp, chain, certProp.getOrgPrefix().concat("IntermediateRootCA"),
                    intermediatRootCaPfx.getPath(), phrase);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createIssuedToCertificateAndWriteToFile(String directory, String issuedTo, char[] phrase, PrivateKey issuerKey,
            X509Certificate[] issuerCertificate) {
        File issuedCertificateFile = new File(directory, issuedTo.concat(Constants.PFX_EXTENSION));
        if (issuedCertificateFile.exists()) {
            LOG.warn("Certificate for Hostname: {} already exists, skipping creating new", issuedTo);
            return;
        }

        try {
            LOG.warn("Creating Certificate for Hostname: {}", issuedTo);
            KeyPair issuedCertificateKp = KeyPairGeneratorUtil.generateBcRsaKeyPair(Constants.DEFAULT_KEYSIZE);
            PKCS10CertificationRequest csrRequest = authority.createCsr(issuedTo, issuedCertificateKp, Constants.SIGNATURE_ALGORITHM);
            if (null == csrRequest) {
                throw new CertificateCreationException("No valid CSR exists");
            }
            CertificateWriter.getInstance().writePrivateKeyToPem(issuedCertificateKp,
                    new File(directory, issuedTo.concat(Constants.KEY_EXTENSION)).getPath(), phrase);
            CertificateWriter.getInstance().writeCsr(new File(directory, issuedTo.concat(Constants.CSR_EXTENSION)).getPath(), csrRequest);
            X509Certificate issuedCertificate = authority.signCsrAndGenerateCertificate(csrRequest, issuerKey, issuerCertificate[0], issuedTo);
            CertificateWriter.getInstance().toPEM(issuedCertificate, new File(directory, issuedTo.concat(Constants.CER_EXTENSION)).getPath());

            String certificatePath = issuedCertificateFile.getPath();
            Files.deleteIfExists(Paths.get(certificatePath));
            X509Certificate[] chain = ArrayUtils.addAll(new X509Certificate[] { issuedCertificate }, issuerCertificate);
            CertificateWriter.getInstance().writeToPkcs12Keystore(issuedCertificateKp, chain, issuedTo, certificatePath, phrase);
            KeyStoreUtil.storeCertificateUsingBC(certificatePath, phrase, new X509Certificate[] { issuedCertificate });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createCertificate() {
        char[] phraseArr = certProp.getPhrase().toCharArray();
        String baseDirectory = FileUtils.getUserDirectoryPath();
        File certBaseDirectory = new File(baseDirectory, "certificates");
        try {
            Files.createDirectories(certBaseDirectory.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }

        createRootCaAndWriteToFile(certBaseDirectory.getPath(), phraseArr);

        Optional<CertificateDetailHolder> issuerKeyOpt = KeyStoreUtil.getPrivateKeyAndCertificateChainUsingBC(
                new File(certBaseDirectory, certProp.getRootCa().getFileName().concat(Constants.PFX_EXTENSION)).getPath(),
                certProp.getOrgPrefix().concat("RootCA"), phraseArr);
        if (!issuerKeyOpt.isPresent()) {
            throw new IllegalArgumentException("Issuer does not exists");
        }

        createIntermediateCaAndWriteToFile(certBaseDirectory.getPath(), phraseArr, issuerKeyOpt.get().getPrivateKey(),
                (X509Certificate[]) issuerKeyOpt.get().getCertificateChain());

        String hostname = SystemUtil.getHostname();
        Optional<CertificateDetailHolder> intermediateIssuerDetailOpt = KeyStoreUtil.getPrivateKeyAndCertificateChainUsingBC(
                new File(certBaseDirectory, certProp.getIntermediateCa().getFileName().concat(Constants.PFX_EXTENSION)).getPath(),
                certProp.getOrgPrefix().concat("IntermediateRootCA"), phraseArr);
        if (!intermediateIssuerDetailOpt.isPresent()) {
            throw new IllegalArgumentException("Unable to get issuer certificate to generate certificate");
        }
        createIssuedToCertificateAndWriteToFile(certBaseDirectory.getPath(), hostname, phraseArr, intermediateIssuerDetailOpt.get().getPrivateKey(),
                (X509Certificate[]) intermediateIssuerDetailOpt.get().getCertificateChain());

    }
}
