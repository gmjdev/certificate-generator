package com.gm.utils.cert.exception;

public class CsrCreationException extends CertificateCreationException {
    private static final long serialVersionUID = -7480473805980527857L;

    public CsrCreationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CsrCreationException(String message) {
        super(message);
    }

}
