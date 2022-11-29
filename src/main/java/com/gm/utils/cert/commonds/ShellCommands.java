package com.gm.utils.cert.commonds;

import com.gm.utils.cert.CertificateAuthority;

//@ShellComponent
public class ShellCommands {
//    @Autowired
    private CertificateAuthority authority;
    private static final char[] DEFAULT_PHRASE = "changeit".toCharArray();
    private static final String KEY_ALGORITHM = "RSA";
//    @Value("${certs.org-prefix:localhost}")
    private String org;

//    @ShellMethod("Generate Certificate")
    public void generate() {
    }
}
