package com.gm.utils.cert;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificateWriter {
    private static final String DEFAULT_PHRASE_ENCRYPTION_ALGO = "AES-256-CBC";

    private static class CertificateWriterHolder {
        private static final CertificateWriter instance = new CertificateWriter();
    }

    public static CertificateWriter getInstance() {
        return CertificateWriterHolder.instance;
    }

    public void writeToPem(Certificate certificate, String filePath) throws IOException {
        log.debug("Writing certificate to file: {}", filePath);
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
        }
        FileUtils.writeStringToFile(new File(filePath), stringWriter.toString(), StandardCharsets.UTF_8);
    }

    public void writePrivateKeyToPem(KeyPair keyPair, String filePath, char[] phrase) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder(DEFAULT_PHRASE_ENCRYPTION_ALGO).build(phrase);
            JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(keyPair.getPrivate(), encryptor);
            pemWriter.writeObject(gen);
        }
        FileUtils.writeStringToFile(new File(filePath), sw.toString(), StandardCharsets.UTF_8);
    }

    public void writeToPkcs12Keystore(KeyPair keyPair, Certificate[] certificate, String alias, String filePath, char[] storePass) {
        writeUsingBouncyCastleKeystore(keyPair, certificate, alias, filePath, "PKCS12", storePass);
    }

    private void writeUsingBouncyCastleKeystore(KeyPair keyPair, Certificate[] certificate, String alias, String filePath, String storeType,
            char[] storePass) {
        File ksFile = new File(filePath);
        try {
            KeyStore sslKeyStore = KeyStore.getInstance(storeType, BouncyCastleProvider.PROVIDER_NAME);
            if (ksFile.exists()) {
                sslKeyStore.load(new FileInputStream(ksFile), storePass);
            } else {
                sslKeyStore.load(null, null);
            }
            sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), null, certificate);
            FileOutputStream keyStoreOs = new FileOutputStream(filePath);
            sslKeyStore.store(keyStoreOs, storePass);
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
            log.error("Failed to create keystore", e);
        }
    }

    public void writeCsr(String filePath, PKCS10CertificationRequest csr) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(csr);
        }
        FileUtils.writeStringToFile(new File(filePath), sw.toString(), StandardCharsets.UTF_8);
    }
}
