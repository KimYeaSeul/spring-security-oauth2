package com.example.authorizationserver.config;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyConfig {
    private static final String KEY_STORE_FILE = "jwt-test.jks";
    private static final String KEY_STORE_PASSWORD = "password";
    private static final String KEY_ALIAS = "auth";
    private static KeyStoreKeyFactory KEY_STORE_KEY_FACTORY = new KeyStoreKeyFactory(
            new ClassPathResource(KEY_STORE_FILE), KEY_STORE_PASSWORD.toCharArray());
    public static final String VERIFIER_KEY_ID = new String(Base64.encode(KeyGenerators.secureRandom(32).generateKey()));

    static RSAPublicKey getVerifierKey() {
        return (RSAPublicKey) getKeyPair().getPublic();
    }

    public static RSAPrivateKey getSignerKey() {
        return (RSAPrivateKey) getKeyPair().getPrivate();
    }

    private static KeyPair getKeyPair() {
        return KEY_STORE_KEY_FACTORY.getKeyPair(KEY_ALIAS);
    }
}
