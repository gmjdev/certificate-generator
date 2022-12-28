package com.gm.utils.cert.constants;

import java.io.File;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Constants {
    public static final String PFX_EXTENSION = ".pfx";
    public static final String CSR_EXTENSION = ".csr";
    public static final String CER_EXTENSION = ".cer";
    public static final String PEM_EXTENSION = ".pem";
    public static final String KEY_EXTENSION = ".key";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final int DEFAULT_KEYSIZE = 2048;
    public static final String PKCS12_KEYSTORE = "PKCS12";
    public static final String JKS_KEYSTORE = "JKS";
    public static final String CA_CERT_FILE = "cacerts";
    public static final String JSSE_CA_CERT_FILE = "jssecacerts";
    public static final char[] DEFAULT_KEYSTORE_PHRASE = "changeit".toCharArray();
    public static final String JAVA_SECURITY_PATH = File.separatorChar + "jre" + File.separatorChar + "lib" + File.separatorChar + "security";
    public static final String PROTOCOL_TLS = "TLS";
}
