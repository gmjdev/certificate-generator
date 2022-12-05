package com.gm.utils.cert;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class KeyPairGeneratorUtil {

    public static KeyPair generateBcRsaKeyPair(int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        rsa.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        return rsa.generateKeyPair();
    }

    public static KeyPair generateBcKeyPair(String alogorithm, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kp = KeyPairGenerator.getInstance(alogorithm, BouncyCastleProvider.PROVIDER_NAME);
        kp.initialize(keySize);
        return kp.generateKeyPair();
    }
}
