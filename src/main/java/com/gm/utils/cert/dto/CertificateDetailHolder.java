package com.gm.utils.cert.dto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class CertificateDetailHolder {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final Certificate[] certificateChain;
}
