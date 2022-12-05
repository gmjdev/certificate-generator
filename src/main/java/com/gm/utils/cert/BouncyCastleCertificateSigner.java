package com.gm.utils.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class BouncyCastleCertificateSigner {
    private static final int ID_BIT_LENGTH = 159;
    private static final String SIGNATURE_ALGO = "sha256WithRSAEncryption";
    private static final Duration DEFAULT_VALIDITY_PERIOD = Duration.ofDays(365);
    private static final boolean CRITICAL = true;
    private static final boolean IS_CA = true;

    private final X509Certificate caCert;
    private final PrivateKey caPrivate;
    private final Set<String> dnsSubjAltNames = new LinkedHashSet<>();
    private final List<Extension> profileExtensions = new ArrayList<>();
    private final SecureRandom random = new SecureRandom();
    private byte[] id;
    private Duration validityPeriod = Duration.ofDays(365);

    public enum Profile {
        SERVICE_PROVIDER;
    }

    public BouncyCastleCertificateSigner(X509Certificate caCert, PrivateKey caPrivate) {
        this.caCert = caCert;
        this.caPrivate = caPrivate;
        Security.addProvider(new BouncyCastleProvider());
        reset();
    }

    public BouncyCastleCertificateSigner reset() {
        dnsSubjAltNames.clear();
        profileExtensions.clear();
        validityPeriod = DEFAULT_VALIDITY_PERIOD;
        id = newId();
        return this;
    }

    public BouncyCastleCertificateSigner addDnsSubjectAlternativeName(String name) {
        dnsSubjAltNames.add(name);
        return this;
    }

    public BouncyCastleCertificateSigner setValidityPeriod(Duration period) {
        validityPeriod = period;
        return this;
    }

    public BouncyCastleCertificateSigner useProfile(Profile profile) throws IOException {
        if (profile == Profile.SERVICE_PROVIDER) {
            profileExtensions.clear();
            profileExtensions.add(Extension.create(Extension.keyUsage, CRITICAL,
                    new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement)));
            profileExtensions.add(Extension.create(Extension.extendedKeyUsage, !CRITICAL,
                    new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth })));
            profileExtensions.add(Extension.create(Extension.basicConstraints, !CRITICAL, new BasicConstraints(!IS_CA)));
            profileExtensions.add(Extension.create(Extension.subjectKeyIdentifier, !CRITICAL, new SubjectKeyIdentifier(id)));
        }
        return this;
    }

    public X509Certificate sign(PKCS10CertificationRequest csr) throws IOException, OperatorCreationException, CertificateException {
        X509CertificateHolder caCertHolder = new X509CertificateHolder(caCert.getEncoded());
        AlgorithmIdentifier signingAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_ALGO);
        AlgorithmIdentifier digestAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(signingAlgId);
        AsymmetricKeyParameter caPrivateKeyParameter = PrivateKeyFactory.createKey(caPrivate.getEncoded());
        ContentSigner contentSigner = new BcRSAContentSignerBuilder(signingAlgId, digestAlgId).build(caPrivateKeyParameter);
        X500Name issuer = caCertHolder.getSubject();
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(validityPeriod));

        X500Name subject = csr.getSubject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();
        BigInteger serialNumber = BigInteger.valueOf(Instant.now().toEpochMilli());
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject,
                subjectPublicKeyInfo);

        // general extensions
        // XXX hack to get CA's subject key identifier
        byte[] encodedSubjKeyId = caCertHolder.getExtension(Extension.subjectKeyIdentifier).getExtnValue().getOctets();
        final int derHeaderLen = 2;
        byte[] caSubjectKeyId = Arrays.copyOfRange(encodedSubjKeyId, derHeaderLen, encodedSubjKeyId.length - derHeaderLen);
        certificateBuilder.addExtension(Extension.authorityKeyIdentifier, !CRITICAL, new AuthorityKeyIdentifier(caSubjectKeyId));

        // profile-based extensions
        for (Extension ext : profileExtensions) {
            certificateBuilder.addExtension(ext);
        }

        // SANs
        GeneralNames subjectAltNames = new GeneralNames(
                dnsSubjAltNames.stream().map(n -> new GeneralName(GeneralName.dNSName, n)).collect(Collectors.toList()).toArray(new GeneralName[0]));
        certificateBuilder.addExtension(Extension.subjectAlternativeName, !CRITICAL, subjectAltNames);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(contentSigner));
    }

    private byte[] newId() {
        return new BigInteger(ID_BIT_LENGTH, random).toByteArray();
    }
}
