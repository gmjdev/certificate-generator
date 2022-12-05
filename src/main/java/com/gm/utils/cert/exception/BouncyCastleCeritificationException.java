package com.gm.utils.cert.exception;

public class BouncyCastleCeritificationException extends RuntimeException {
    private static final long serialVersionUID = -2283931521092017116L;

    public BouncyCastleCeritificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public BouncyCastleCeritificationException(String message) {
        super(message);
    }

}
