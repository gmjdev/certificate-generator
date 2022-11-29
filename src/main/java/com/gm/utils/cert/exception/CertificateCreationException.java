package com.gm.utils.cert.exception;

public class CertificateCreationException extends RuntimeException {
    public CertificateCreationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateCreationException(String message) {
        super(message);
    }

    private static final long serialVersionUID = -5186009244678262044L;

}
