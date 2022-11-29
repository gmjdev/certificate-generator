package com.gm.utils.cert.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.util.Assert;

import com.gm.utils.cert.dto.CertificateDetailHolder;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class KeyStoreUtil {
    private static final String PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE = "Password is required to open keystore";
    private static final String KEY_ALIAS_IS_REQUIRED = "key alias is required";
    private static final String KEYSTORE_PATH_IS_REQUIRED = "Keystore path is required";
    private static final String KEYSTORE_TYPE = "PKCS12";

    public static Optional<PrivateKey> getPrivateKey(String keystorePath, String alias, char[] phrase) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(alias, KEY_ALIAS_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        PrivateKey key = null;
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KEYSTORE_TYPE, BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new FileInputStream(keystorePath), phrase);
            if (!ks.containsAlias(alias)) {
                throw new IllegalArgumentException("Keystore file does not have alias: " + alias);
            }

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(phrase));
            key = pkEntry.getPrivateKey();
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to read keystore", e);
        }
        return Optional.ofNullable(key);
    }

    public static Optional<CertificateDetailHolder> getPrivateKeyAnCertificateChain(String keystorePath, String alias, char[] phrase) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        Assert.notNull(alias, KEY_ALIAS_IS_REQUIRED);
        CertificateDetailHolder certificateDetailHolder = null;
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KEYSTORE_TYPE, BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new FileInputStream(keystorePath), phrase);
            if (!ks.containsAlias(alias)) {
                throw new IllegalArgumentException("Keystore file does not have alias: " + alias);
            }

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(phrase));
            certificateDetailHolder = new CertificateDetailHolder(pkEntry.getPrivateKey(), null, pkEntry.getCertificateChain());
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to read keystore", e);
        }
        return Optional.ofNullable(certificateDetailHolder);
    }

    public static void storeCertificate(String keystorePath, char[] phrase, X509Certificate[] certs) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        log.info("Updating Keystore: {} for updating certificate entries", keystorePath);
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KEYSTORE_TYPE, BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new FileInputStream(keystorePath), phrase);
            for (X509Certificate x509Certificate : certs) {
                String[] tokens = StringUtils.split(x509Certificate.getSubjectX500Principal().getName(), ',');
                if (null == tokens || tokens.length == 0) {
                    continue;
                }

                Optional<String> cnEntry = Stream.of(tokens).filter(x -> x.startsWith("CN=")).map(x -> x.replace("CN=", "")).findFirst();
                if (cnEntry.isPresent()) {
                    addCertificateToKeystore(ks, x509Certificate, cnEntry.get());
                }
            }
            ks.store(new FileOutputStream(keystorePath), phrase);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to read keystore", e);
        }
    }

    private static void addCertificateToKeystore(KeyStore ks, X509Certificate x509Certificate, String entry) throws KeyStoreException {
        try {
            if (!ks.containsAlias(entry + "Cert")) {
                log.info("Adding certificate entry: {}", entry);
                ks.setEntry(entry + "Cert", new KeyStore.TrustedCertificateEntry(x509Certificate), null);
            }
        } catch (KeyStoreException e) {
            log.error("Failed to store certificate entry", e);
        }
    }
}
