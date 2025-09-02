package com.jwtauth.common.util;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class JwtRS256Test {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // 对应编辑app页APPCode字段
        String appCode = "b3JjaHN5bS1qd3QtYXV0aDM5MjMz";
        // 对应编辑app页Client Id字段
        String clientId = "fb7cc604-3732-446c-b2bc-4f92c414eba2";
        // 对应编辑app页privateKey字段
        String privateKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDViFrSfCpARiwkj4YFSIEqNv7OuYPNhM1E+qPVwYpb8eviEctR1/KzO0DHcAH/UTuoFOJK1/f6BeMU8ExEC3g/EGubKe3d+WUZXyoA0JDRkKKOjZW0Ad7s5ZVOYYjpc8sw6KuO0G5UNRoU7XP9t1BpUpcxuNfu5XdboF1GPHDZNrzACB7AU0wyt8FQMTXQvosJ4ofUVWZSd4tW8eGSYLYDBdqe7uocByAOg2fJg+62558fGhvh82SW3rVfcQO3o4JKS3J+pKjGywBa7x+JzfMpIryEYGjoh5pbogMdveuAX+457kiTy+XyjO0il+4Hke6B0gQiA4p3sT1CpSM1evPrAgMBAAECggEASsR9ZLE0TCAmCcE1gLkT/ReXngPoSjijdXE7l7e2fh5V5Wkso6I1KZvoQU0PbfpgJKj3WZSIkEOqcST412SavJ4/x2tljjFqvHkNaI6e/rohqT+bORXknFeBMZpGSdQRRDVcCNwjnZmgYc6JLEAZSF+ycCcUeOJhKjSbJGI6c1uq/Lm8DzKCeeKtkdmplejTqMzqQc86ZueGEwNS1o5QVKzq+3aWGZxI6DC6cZ7uT/oTaUn2t6nSoZZItn9cO2MIERcCs2+2X+IH6NsFoJnqsf5UVFuwp1kyQ/p1YrGwnGOCTzA3r3yBrwUgFhF9LLP8bSHLRv+w/EluGeUOKiLinQKBgQDpM2jYvE/boKC9L8PoUdMBE2HTzU6LN7rL9mG+rgojzjFMOVY+ihyIvvO9jP/zswBwkASXiQHNyqhZVhFIvFzqQTa6uo44mWQYPo+mYq2WokTzLf1WXgmjGRTWO8oow1XrRHKjzWSX37A7hpDIx5Fu+Xs2Aw23LNkyhX93pv2PVwKBgQDqaK/AzzY4LcNgEVSX1oAcx1iO3sbGJvWcAzkG8TMAddJhCzuZ9UzL1q99w9w9vV2Up1Ux3WiNYhTmTiY1QMYpgGAsT+7yy4389PcqcOZeqJn9DGxU6Z69mUfPOLjQqmsnqN0s7jSk5lXfoYhSkZa9IlaWsIiv96qdytP/RLFnjQKBgQCz778OvP7BcIeWcqyvLbOqONJbIydftHiluE5jWtboGclgDz3Es7ygpvZbY9h6qbvFHtrsMgL6T0zm4cokXXM0LW2VVy017uWU73DX6XwXps2c9fdsFNNKzaeORkQOf+pjxkTOr0TXCvpoc8Rzp8lH36h6XJDQrgJJQUjBglBTsQKBgQCG48EnkdYgk+0XDkIAsjW82dYTOQ1nn6m8onohjZEM1cA/ieg9W1RbBGquU5QcjykXzwcOj9uHaIagVR5VjLW70h0FwuW9H/fQNeM5sAhRNnKOlKSOZHWto1QYYgqwQTEyfFDydw0iS03lR54b7Z2xrt3nDyVJJZsv/DTsc0onTQKBgQCPRZcrFLHH6DegCmkyD2Q3AMWLz92Eg5EoDDC6YMkU6T6NE8UJy1FEECKZIno6FowxCmV6tHFltICJ43aqLnxoEL9hCyniuiEyPmmxeFIxc4rhPW54+mmfZbNAJZ1zdF6xKwT1oiTA8XLu3motwORVZQ5w8gr2Gx+L/Khr4/2nOg==";

        // 对应编辑app页Token有效期（这里的单位是s），如果和创建app时选择的Token有效期保持一致，则强依赖于调用方和网关的时间完全一致，哪怕只有1s的时差，也会导致调用报错403（token已过期）
        // 建议这个值比app的Token有效期设置的短一些，比如Token有效期是10min，这里就设置为8min或者5min，如果有报错，则需要核实双方的时间一致性
        // 网关会判断，如果Token有效期是5min，但你生成token时，设置的有效期是6min，则永远无法通过校验，因为网关不允许客户端生成的token有效期比app的token有效期长
        int tokenPeriod = 250;
        // jwt生成算法
        String algorithm = "RS256";

        JwtRS256Test.test(privateKey,  clientId, appCode, tokenPeriod, algorithm);
    }

    /**
     * 测试
     * @param str HS256算法时为privateKey, RS256算法时为secretCode
     * @param clientId 编辑app页Client Id字段
     * @param appCode 编辑app页APPCode字段
     * @param tokenPeriod 编辑app页Token有效期 单位秒 最大不超过60 * 60
     * @param algorithm 生成Jwt算法 HS256或者RS256
     */
    private static void test(String str, String clientId, String appCode, int tokenPeriod, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String urlStr = "http://orchsym-gateway.baishancloud.com/env-101/por-17834/propath/bsy/get";
        // 生成token
        JwtGenerator jwtGenerator = new JwtGenerator(str, clientId, tokenPeriod, algorithm);

        System.out.println("token : " + jwtGenerator.getToken());
        // 发起请求
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url(urlStr)
                .addHeader("orchsym-app-code", appCode)
                .addHeader("Authorization", "bearer " + jwtGenerator.getToken())
                .build();

        Call call = client.newCall(request);
        Response response = call.execute();
        System.out.println("Response Code: " + response.code());

        ResponseBody body = response.body();
        if (body != null) {
            System.out.println("Response Body: " + body.string());
        }

        response.close();
    }
}
