package com.gm.utils.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Value;

import com.gm.utils.cert.exception.CertificateCreationException;
import com.gm.utils.cert.exception.CsrCreationException;

public class CertificateAuthority {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String CA_X500_NAME_FMT = "E=support@{0},CN={0}-RootCA,OU=IT,O=ITDelivery,L=Pune,ST=MH,C=IN";
    private static final String LOCAL_CERT_X500_FMT = "C=IN,ST=MH,L=Pune,O=ITDelivery,OU=IT,CN={0},E=support@{0}";
    @Value("${certs.org-prefix:localhost}")
    private String org;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public X509Certificate createRootCaCertificate(KeyPair keyPair, int expiryInDays) throws Exception {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(expiryInDays)));

        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        X500Name x500Name = new X500Name(MessageFormat.format(CA_X500_NAME_FMT, org));

        // @formatter:off
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(x500Name,
                getSerialNumber(),
                notBefore,
                notAfter,
                x500Name,
                keyPair.getPublic());
        // @formatter:on

        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(rootCertHolder);
        cert.verify(keyPair.getPublic());
        return cert;
    }

    private BigInteger getSerialNumber() {
        return BigInteger.valueOf(Instant.now().toEpochMilli());
    }

    public X509Certificate createIntermediateRootCa(X509Certificate issuer, KeyPair keyPair, PrivateKey caKey, int expiryInDays) throws Exception {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(expiryInDays)));

        // set issuer and subject name
        X500Name issuedToCN = new X500Name(MessageFormat.format(CA_X500_NAME_FMT, org.concat("-Intermediate")));

        X509v3CertificateBuilder intermediateCertBuilder = new JcaX509v3CertificateBuilder(issuer, getSerialNumber(), notBefore, notAfter, issuedToCN,
                keyPair.getPublic());

        JcaX509ExtensionUtils intermediateCertExtUtils = new JcaX509ExtensionUtils();

        // Configure the extensions
        intermediateCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        intermediateCertBuilder.addExtension(Extension.keyUsage, true, new X509KeyUsage(
                X509KeyUsage.keyCertSign | X509KeyUsage.digitalSignature | X509KeyUsage.dataEncipherment | X509KeyUsage.keyAgreement));
        intermediateCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                intermediateCertExtUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        intermediateCertBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage));
        intermediateCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, intermediateCertExtUtils.createAuthorityKeyIdentifier(issuer));

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caKey);
        X509CertificateHolder certHldr = intermediateCertBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHldr);

        cert.verify(issuer.getPublicKey());

        return cert;
    }

    public PKCS10CertificationRequest createCsr(String commonName, KeyPair keyPair, KeyPair issuer) {
        try {
            X500Name localCertCsrName = new X500Name(MessageFormat.format(LOCAL_CERT_X500_FMT, commonName));
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(localCertCsrName, keyPair.getPublic());
            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BouncyCastleProvider.PROVIDER_NAME);
            ContentSigner signer = csrBuilder.build(issuer.getPrivate());
            return p10Builder.build(signer);
        } catch (OperatorCreationException e) {
            throw new CsrCreationException("Unable to create CSR Request", e);
        }
    }

    public X509Certificate signCsrAndGenerateCertificate(PKCS10CertificationRequest csr, PrivateKey caKey, X509Certificate caCertificate,
            String commonName) {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(90)));

        try {
            JcaX509ExtensionUtils certExtUtils = new JcaX509ExtensionUtils();
            X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());

            X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, getSerialNumber(), notBefore, notAfter, csr.getSubject(),
                    csr.getSubjectPublicKeyInfo());
            certgen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            certgen.addExtension(Extension.subjectKeyIdentifier, false, certExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
            certgen.addExtension(Extension.authorityKeyIdentifier, false, certExtUtils.createAuthorityKeyIdentifier(caCertificate));
            certgen.addExtension(Extension.keyUsage, false,
                    new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.dataEncipherment));
            certgen.addExtension(Extension.subjectAlternativeName, false, getSubjectAltnativeNames(commonName));

            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BouncyCastleProvider.PROVIDER_NAME);
            ContentSigner csrContentSigner = csrBuilder.build(caKey);
            X509CertificateHolder issuedCertHolder = certgen.build(csrContentSigner);
            X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(issuedCertHolder);

            issuedCert.verify(caCertificate.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
            return issuedCert;
        } catch (Exception e) {
            throw new CertificateCreationException("Failed to Sign CSR", e);
        }
    }

    private DERSequence getSubjectAltnativeNames(String commonName) {
        List<ASN1Encodable> sanEntries = new ArrayList<>(10);

        sanEntries.add(new GeneralName(GeneralName.iPAddress, "127.0.0.1"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, "localhost"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, "localhost.com"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, "*.localhost.com"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, "*.accounts.intern"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, commonName));

        if (commonName.indexOf("accounts.intern") == -1) {
            sanEntries.add(new GeneralName(GeneralName.dNSName, commonName.concat(".accounts.intern")));
        }
        return new DERSequence(sanEntries.toArray(new ASN1Encodable[sanEntries.size()]));
    }

    public KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        rsa.initialize(keySize);
        return rsa.generateKeyPair();
    }
}
