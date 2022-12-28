package com.gm.utils.cert;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.IOUtils;

import com.gm.utils.cert.constants.Constants;
import com.gm.utils.cert.exception.HostNotReachableException;
import com.gm.utils.cert.util.KeyStoreUtil;
import com.gm.utils.cert.util.SystemUtil;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CertificateInstaller {
    public void performHostReachability(String host, int port) {
        Optional<String> javaHome = SystemUtil.getDefaultJavaHome();
        if (!javaHome.isPresent()) {
            throw new IllegalArgumentException("Java home environment variable not defined");
        }

        String truststore = KeyStoreUtil.getOrCreateJsseTrustStore(javaHome.get());
        Optional<KeyStore> ks = KeyStoreUtil.loadJksKeyStore(truststore, Constants.DEFAULT_KEYSTORE_PHRASE);
        if (!ks.isPresent()) {
            throw new IllegalStateException("Unable to get keystore");
        }
        SslContextHolder contextHolder = getSslContext(ks.get());
        if (!contextHolder.getSslContext().isPresent()) {
            throw new IllegalArgumentException("No SSLContext is available");
        }
        try {
            performHandshake(host, port, contextHolder.getSslContext().get());
        } catch (HostNotReachableException e) {
            installCertificate(truststore, Constants.DEFAULT_KEYSTORE_PHRASE, contextHolder.getTm());
        }
    }

    public void performHostReachability(String host, int port, String javaHome, char[] keyStorePhrase) {
        String truststore = KeyStoreUtil.getOrCreateJsseTrustStore(javaHome);
        Optional<KeyStore> ks = KeyStoreUtil.loadJksKeyStore(truststore, keyStorePhrase);
        if (!ks.isPresent()) {
            throw new IllegalStateException("Unable to get keystore");
        }
        SslContextHolder contextHolder = getSslContext(ks.get());
        if (!contextHolder.getSslContext().isPresent()) {
            throw new IllegalArgumentException("No SSLContext is available");
        }
        try {
            performHandshake(host, port, contextHolder.getSslContext().get());
        } catch (HostNotReachableException e) {
            installCertificate(truststore, keyStorePhrase, contextHolder.getTm());
        }
    }

    private void installCertificate(String ks, char[] phrase, SavingTrustManager tm) {
        if (tm == null || null == tm.chain || tm.chain.length == 0) {
            log.warn("Could not obtain server certificate chain");
            return;
        }

        if (tm.chain.length > 1) {
            X509Certificate[] certs = Arrays.copyOfRange(tm.chain, 1, tm.chain.length);
            KeyStoreUtil.storeCertificate(ks, phrase, certs);
        }
    }

    private void performHandshake(String host, int port, SSLContext context) {
        SSLSocket socket = null;
        SSLSocketFactory factory = context.getSocketFactory();
        try {
            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(10000);
            log.info("Starting SSL handshake...");
            socket.startHandshake();
            log.info("No errors, certificate is already trusted");
        } catch (IOException e) {
            log.error("Failed to perform SSL Handshake", e);
            throw new HostNotReachableException("Socket not reachable", e);
        } finally {
            IOUtils.closeQuietly(socket);
        }
    }

    private SslContextHolder getSslContext(KeyStore ks) {
        SSLContext context = null;
        SavingTrustManager tm = null;
        try {
            context = SSLContext.getInstance(Constants.PROTOCOL_TLS);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            tm = new SavingTrustManager(defaultTrustManager);
            context.init(null, new TrustManager[] { tm }, null);
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            log.error("Failed to get SSL Context", e);
        }
        return new SslContextHolder(Optional.ofNullable(context), tm);
    }

    @Getter
    @RequiredArgsConstructor
    public static class SslContextHolder {
        private final Optional<SSLContext> sslContext;
        private final SavingTrustManager tm;
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        @SuppressWarnings("unused")
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}