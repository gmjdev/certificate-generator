package com.gm.utils.cert.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.util.Assert;

import com.gm.utils.cert.constants.Constants;
import com.gm.utils.cert.dto.CertificateDetailHolder;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public final class KeyStoreUtil {
    private static final String UNABLE_TO_READ_KEYSTORE = "Unable to read keystore";
    private static final String PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE = "Password is required to open keystore";
    private static final String KEY_ALIAS_IS_REQUIRED = "key alias is required";
    private static final String KEYSTORE_PATH_IS_REQUIRED = "Keystore path is required";

    public static String getOrCreateJsseTrustStore(String javaHome) {
        File jsseCaCertfile = new File(javaHome, getCaCertsFile(Constants.JSSE_CA_CERT_FILE));
        File caCertFile = new File(javaHome, getCaCertsFile(Constants.CA_CERT_FILE));
        if (!jsseCaCertfile.isFile() && caCertFile.isFile()) {
            log.debug("File: {} not exists creating new using file: {}", jsseCaCertfile.getName(), caCertFile.getName());
            try {
                FileUtils.copyFile(caCertFile, jsseCaCertfile);
            } catch (IOException e) {
                log.warn("Unable to create jssecacert file");
                return caCertFile.getAbsolutePath();
            }
        }
        return jsseCaCertfile.getAbsolutePath();
    }

    private static String getCaCertsFile(String caCertFile) {
        return Constants.JAVA_SECURITY_PATH + File.separatorChar + caCertFile;
    }

    public static Optional<PrivateKey> getPrivateKey(String keystorePath, String alias, char[] phrase) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(alias, KEY_ALIAS_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        PrivateKey key = null;
        try {
            Optional<KeyStore.PrivateKeyEntry> entryOpt = loadDefaultKeystore(keystorePath, alias, phrase);
            if (entryOpt.isPresent()) {
                key = entryOpt.get().getPrivateKey();
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(UNABLE_TO_READ_KEYSTORE, e);
        }
        return Optional.ofNullable(key);
    }

    public static Optional<CertificateDetailHolder> getPrivateKeyAndCertificateChain(String keystorePath, String alias, char[] phrase) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        Assert.notNull(alias, KEY_ALIAS_IS_REQUIRED);
        CertificateDetailHolder certificateDetailHolder = null;
        Optional<KeyStore.PrivateKeyEntry> entryOpt = loadDefaultKeystore(keystorePath, alias, phrase);
        if (entryOpt.isPresent()) {
            KeyStore.PrivateKeyEntry entry = entryOpt.get();
            certificateDetailHolder = new CertificateDetailHolder(entry.getPrivateKey(), null, entry.getCertificateChain());
        }
        return Optional.ofNullable(certificateDetailHolder);
    }

    public static Optional<PrivateKey> getPrivateKeyUsingBC(String keystorePath, String alias, char[] phrase) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(alias, KEY_ALIAS_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        PrivateKey key = null;
        try {
            Optional<KeyStore.PrivateKeyEntry> entryOpt = loadPkcs12KeystoreUsingBC(keystorePath, alias, phrase);
            if (entryOpt.isPresent()) {
                key = entryOpt.get().getPrivateKey();
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(UNABLE_TO_READ_KEYSTORE, e);
        }
        return Optional.ofNullable(key);
    }

    public static Optional<CertificateDetailHolder> getPrivateKeyAndCertificateChainUsingBC(String keystorePath, String alias, char[] phrase) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        Assert.notNull(alias, KEY_ALIAS_IS_REQUIRED);
        CertificateDetailHolder certificateDetailHolder = null;
        Optional<KeyStore.PrivateKeyEntry> entryOpt = loadPkcs12KeystoreUsingBC(keystorePath, alias, phrase);
        if (entryOpt.isPresent()) {
            KeyStore.PrivateKeyEntry entry = entryOpt.get();
            certificateDetailHolder = new CertificateDetailHolder(entry.getPrivateKey(), null, entry.getCertificateChain());
        }
        return Optional.ofNullable(certificateDetailHolder);
    }

    private static Optional<KeyStore.PrivateKeyEntry> loadDefaultKeystore(String keystorePath, String alias, char[] phrase) {
        KeyStore ks;
        KeyStore.PrivateKeyEntry entry = null;
        try {
            ks = KeyStore.getInstance(Constants.JKS_KEYSTORE);
            ks.load(new FileInputStream(keystorePath), phrase);
            if (!ks.containsAlias(alias)) {
                throw new IllegalArgumentException("Keystore file does not have alias: " + alias);
            }
            entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(phrase));
        } catch (Exception e) {
            throw new IllegalArgumentException(UNABLE_TO_READ_KEYSTORE, e);
        }
        return Optional.ofNullable(entry);
    }

    private static Optional<KeyStore.PrivateKeyEntry> loadPkcs12KeystoreUsingBC(String keystorePath, String alias, char[] phrase) {
        KeyStore ks;
        KeyStore.PrivateKeyEntry entry = null;
        try {
            ks = KeyStore.getInstance(Constants.PKCS12_KEYSTORE, BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new FileInputStream(keystorePath), phrase);
            if (!ks.containsAlias(alias)) {
                throw new IllegalArgumentException("Keystore file does not have alias: " + alias);
            }
            entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(phrase));
        } catch (Exception e) {
            throw new IllegalArgumentException(UNABLE_TO_READ_KEYSTORE, e);
        }
        return Optional.ofNullable(entry);
    }

    public static void storeCertificateUsingBC(String keystorePath, char[] phrase, X509Certificate[] certs) {
        storeCertificate(Constants.PKCS12_KEYSTORE, keystorePath, phrase, certs, true);
    }

    public static void storeCertificate(String keystorePath, char[] phrase, X509Certificate[] certs) {
        storeCertificate(Constants.JKS_KEYSTORE, keystorePath, phrase, certs, false);
    }

    public static Optional<KeyStore> loadJksKeyStore(String filePath, char[] phrase) {
        log.info("Loading Default JKS KeyStore {} ...", filePath);
        KeyStore ks = null;
        try (InputStream in = new FileInputStream(filePath)) {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(in, phrase);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Failed to load keystore/truststore", e);
        }
        return Optional.ofNullable(ks);
    }

    public static Optional<KeyStore> loadPkcs12KeyStoreUsingBC(String filePath, char[] phrase) {
        log.info("Loading PKCS12 KeyStore {} ...", filePath);
        KeyStore ks = null;
        try (InputStream in = new FileInputStream(filePath)) {
            ks = KeyStore.getInstance(Constants.PKCS12_KEYSTORE, BouncyCastleProvider.PROVIDER_NAME);
            ks.load(in, phrase);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Failed to load keystore/truststore", e);
        } catch (NoSuchProviderException e) {
            log.error("Failed to load keystore/truststore due to no BC provider found");
        }
        return Optional.ofNullable(ks);
    }

    private static void storeCertificate(String keyStoreType, String keystorePath, char[] phrase, X509Certificate[] certs, boolean useBC) {
        Assert.notNull(keystorePath, KEYSTORE_PATH_IS_REQUIRED);
        Assert.notNull(phrase, PASSWORD_IS_REQUIRED_TO_OPEN_KEYSTORE);
        log.info("Updating Keystore: {} for updating certificate entries", keystorePath);
        KeyStore ks;
        try {
            ks = useBC ? KeyStore.getInstance(keyStoreType, BouncyCastleProvider.PROVIDER_NAME) : KeyStore.getInstance(keyStoreType);
            ks.load(new FileInputStream(keystorePath), phrase);
            for (X509Certificate x509Certificate : certs) {
                String[] tokens = StringUtils.split(x509Certificate.getSubjectX500Principal().getName(), ',');
                if (null == tokens || tokens.length == 0) {
                    continue;
                }

                Optional<String> cnEntry = Stream.of(tokens).filter(x -> x.startsWith("CN=")).map(x -> x.replace("CN=", "")).findFirst();
                if (cnEntry.isPresent()) {
                    log.debug("Adding certificate entry : {}", x509Certificate.getSubjectDN().getName());
                    log.debug("Adding certificate signature: {}", Hex.encodeHexString(x509Certificate.getSignature()));
                    addCertificateToKeystore(ks, x509Certificate, cnEntry.get());
                }
            }
            ks.store(new FileOutputStream(keystorePath), phrase);
        } catch (Exception e) {
            throw new IllegalArgumentException(UNABLE_TO_READ_KEYSTORE, e);
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
