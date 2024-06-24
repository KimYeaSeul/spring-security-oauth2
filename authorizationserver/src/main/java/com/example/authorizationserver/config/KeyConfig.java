package com.example.authorizationserver.config;

import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;

public class KeyConfig {

    private static final String KEY_STORE_TYPE = "JKS";
    private static final String KEY_STORE_FILE = "jwt-test.jks";
    private static final String KEY_STORE_PASSWORD = "password";
    private static final String KEY_ALIAS = "auth";
    public static final String VERIFIER_KEY_ID = generateSecretKey();

    public static String generateSecretKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[32]; // 32 bytes = 256 bits
        secureRandom.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    public static KeyPair getKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        InputStream resourceAsStream = new ClassPathResource(KEY_STORE_FILE).getInputStream();
        keyStore.load(resourceAsStream, KEY_STORE_PASSWORD.toCharArray());

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_STORE_PASSWORD.toCharArray());
        Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
        PublicKey publicKey = certificate.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }
}
