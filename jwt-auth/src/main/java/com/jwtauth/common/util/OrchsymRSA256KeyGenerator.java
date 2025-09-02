package com.jwtauth.common.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * 秘钥对生成类,使用构造方法传入私钥长度生成或将生成的秘钥对传入构造方法生成
 */
public class OrchsymRSA256KeyGenerator {

    private static final String RSA_ALGORITHM = "RSA";

    private RSAPublicKey publicKey;

    private RSAPrivateKey privateKey;

    public OrchsymRSA256KeyGenerator(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public String toString() {
        return "publicKey = \n" + Base64.getEncoder().encodeToString(this.publicKey.getEncoded()) + "\n"
                + "privateKey = \n" + Base64.getEncoder().encodeToString(this.privateKey.getEncoded());
    }
}
