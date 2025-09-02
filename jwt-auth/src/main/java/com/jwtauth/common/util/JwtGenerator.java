package com.jwtauth.common.util;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

/**
 * JWT Token生成类
 */
public class JwtGenerator {

    private static final String RSA_ALGORITHM = "RSA";

    private String token;

    /**
     * 生成token
     * @param str 使用RS256算法时为privateKey, 使用HS256算法时为secretCode
     * @param clientID 签发人
     * @param tokenPeriod token过期时间 单位秒
     */
    public JwtGenerator(String str, String clientID, Integer tokenPeriod, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {

        if (Objects.isNull(algorithm)) {
            this.token = null;
        }

        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.SECOND, tokenPeriod);
        Date expiresTime = instance.getTime();

        if ("RS256".equals(algorithm)) {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(str));
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            this.token = JWT.create()
                    .withIssuer(clientID)
                    .withExpiresAt(expiresTime)
                    .sign(Algorithm.RSA256(null, privateKey));
        }

        if ("HS256".equals(algorithm)) {
            this.token = JWT.create()
                    .withIssuer(clientID)
                    .withExpiresAt(expiresTime)
                    .sign(Algorithm.HMAC256(str));
        }
    }

    public String getToken() {
        return token;
    }

    @Override
    public String toString() {
        return "token = \n" + this.token;
    }
}
