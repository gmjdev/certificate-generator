package com.gm.utils.cert.exception;

public class HostNotReachableException extends RuntimeException {
    private static final long serialVersionUID = 2719600183034067908L;

    public HostNotReachableException(String message, Throwable cause) {
        super(message, cause);
    }

    public HostNotReachableException(String message) {
        super(message);
    }
}
