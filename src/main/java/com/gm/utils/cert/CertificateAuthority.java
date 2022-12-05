package com.gm.utils.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Value;

import com.gm.utils.cert.exception.CertificateCreationException;
import com.gm.utils.cert.exception.CsrCreationException;

public class CertificateAuthority {
    private static final String CONTENT_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String SUBJECT_NAME_FMT = "{0}-RootCA";
    @Value("${certs.org-prefix:localhost}")
    private String org;

    public X509Certificate createRootCaCertificate(KeyPair keyPair, int expiryInDays) {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now.minus(1, ChronoUnit.HOURS));
        final Date notAfter = Date.from(now.plus(Duration.ofDays(expiryInDays)));

        try {
            X500Name x500Name = getSubjectX500Name(MessageFormat.format(SUBJECT_NAME_FMT, org), true);

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
            ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(CONTENT_SIGNATURE_ALGORITHM)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
            X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(rootCertHolder);
            cert.verify(keyPair.getPublic());
            return cert;
        } catch (Exception e) {
            throw new CertificateCreationException("Unable to create Certificate", e);
        }
    }

    private BigInteger getSerialNumber() {
        return BigInteger.valueOf(Instant.now().toEpochMilli());
    }

    private X500Name getSubjectX500Name(String cn, boolean ca) {
        // @formatter:off
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.CN, cn)
                        .addRDN(BCStyle.C, "IN")
                        .addRDN(BCStyle.O, "ITDelivery");
        // @formatter:on

        if (!ca) {
            builder.addRDN(BCStyle.OU, "IT");
            builder.addRDN(BCStyle.ST, "MH");
            builder.addRDN(BCStyle.L, "PNE");
        }

        return builder.build();
    }

    public X509Certificate createIntermediateRootCa(X509Certificate issuer, KeyPair keyPair, PrivateKey caKey, int expiryInDays) {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now.minus(1, ChronoUnit.HOURS));
        final Date notAfter = Date.from(now.plus(Duration.ofDays(expiryInDays)));

        try {
            // set issuer and subject name
            X500Name issuedToCN = getSubjectX500Name(MessageFormat.format(SUBJECT_NAME_FMT, org.concat("-Intermediate")), true);

            X509v3CertificateBuilder intermediateCertBuilder = new JcaX509v3CertificateBuilder(issuer, getSerialNumber(), notBefore, notAfter,
                    issuedToCN, keyPair.getPublic());

            JcaX509ExtensionUtils intermediateCertExtUtils = new JcaX509ExtensionUtils();

            // Configure the extensions
            intermediateCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            intermediateCertBuilder.addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.digitalSignature
                    | X509KeyUsage.dataEncipherment | X509KeyUsage.keyAgreement | X509KeyUsage.cRLSign));
            intermediateCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    intermediateCertExtUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
            intermediateCertBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage));
            intermediateCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    intermediateCertExtUtils.createAuthorityKeyIdentifier(issuer));

            ContentSigner contentSigner = new JcaContentSignerBuilder(CONTENT_SIGNATURE_ALGORITHM).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(caKey);
            X509CertificateHolder certHldr = intermediateCertBuilder.build(contentSigner);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHldr);
            cert.verify(issuer.getPublicKey());

            return cert;
        } catch (Exception e) {
            throw new CertificateCreationException("Failed to create Intermediate Root CA", e);
        }
    }

    public PKCS10CertificationRequest createCsr(String commonName, KeyPair keypair, String signatureAlgorithm) {
        try {
            X500Name subject = getSubjectX500Name(commonName, false);
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keypair.getPrivate());
            PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keypair.getPublic());
            return requestBuilder.build(signer);
        } catch (OperatorCreationException e) {
            throw new CsrCreationException("Unable to create CSR Request", e);
        }
    }

    public X509Certificate signCsrAndGenerateCertificate(PKCS10CertificationRequest csr, PrivateKey caKey, X509Certificate caCertificate,
            String commonName) {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now.minus(1, ChronoUnit.HOURS));
        final Date notAfter = Date.from(now.plus(Duration.ofDays(30)));

        try {
            JcaX509ExtensionUtils certExtUtils = new JcaX509ExtensionUtils();

            X509CertificateHolder caCertHolder = new X509CertificateHolder(caCertificate.getEncoded());
            AlgorithmIdentifier signingAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("sha256WithRSA");
            AlgorithmIdentifier digestAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(signingAlgId);

            AsymmetricKeyParameter caPrivateKeyParameter = PrivateKeyFactory.createKey(caKey.getEncoded());
            SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();

            ContentSigner contentSigner = new BcRSAContentSignerBuilder(signingAlgId, digestAlgId).build(caPrivateKeyParameter);

            PKCS10CertificationRequest pk10CertReq = new PKCS10CertificationRequest(csr.getEncoded());

            X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(caCertHolder.getSubject(), getSerialNumber(), notBefore, notAfter,
                    pk10CertReq.getSubject(), subjectPublicKeyInfo);

            certgen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.nonRepudiation | KeyUsage.digitalSignature
                    | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));
            certgen.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth }));
            certgen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            certgen.addExtension(Extension.subjectKeyIdentifier, false, certExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
            certgen.addExtension(Extension.authorityKeyIdentifier, false, certExtUtils.createAuthorityKeyIdentifier(caCertificate));
            certgen.addExtension(Extension.subjectAlternativeName, false, getSubjectAltnativeNames(commonName));

            X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certgen.build(contentSigner));

            issuedCert.verify(caCertificate.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
            return issuedCert;
        } catch (Exception e) {
            throw new CertificateCreationException("Failed to Sign CSR", e);
        }
    }

    private DERSequence getSubjectAltnativeNames(String commonName) {
        List<ASN1Encodable> sanEntries = new ArrayList<>(10);

        sanEntries.add(new GeneralName(GeneralName.dNSName, commonName));
        if (commonName.indexOf("accounts.intern") == -1) {
            sanEntries.add(new GeneralName(GeneralName.dNSName, commonName.concat(".accounts.intern")));
        }
        sanEntries.add(new GeneralName(GeneralName.dNSName, "*.accounts.intern"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, "localhost"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, "localhost.com"));
        sanEntries.add(new GeneralName(GeneralName.dNSName, "*.localhost.com"));
        sanEntries.add(new GeneralName(GeneralName.iPAddress, "127.0.0.1"));

        return new DERSequence(sanEntries.toArray(new ASN1Encodable[sanEntries.size()]));
    }
}
