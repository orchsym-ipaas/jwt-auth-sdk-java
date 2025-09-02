package com.jwtauth.common.util;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class JwtHS256Test {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // 对应编辑app页APPCode字段
        String appCode = "b3JjaHN5bS1qd3QtYXV0aDM5MjU0";
        // 对应编辑app页Client Id字段
        String clientId = "38e935c4-666a-48ba-8c64-7c0e21ff6b4f";
        // 对应编辑app页secretCode字段
        String secretCode = "fadwsfteawsfd";
        
        // 对应编辑app页Token有效期（这里的单位是s），如果和创建app时选择的Token有效期保持一致，则强依赖于调用方和网关的时间完全一致，哪怕只有1s的时差，也会导致调用报错403（token已过期）
        // 建议这个值比app的Token有效期设置的短一些，比如Token有效期是10min，这里就设置为8min或者5min，如果有报错，则需要核实双方的时间一致性
        // 网关会判断，如果Token有效期是5min，但你生成token时，设置的有效期是6min，则永远无法通过校验，因为网关不允许客户端生成的token有效期比app的token有效期长
        int tokenPeriod = 250;
        // jwt生成算法
        String algorithm = "HS256";

        JwtHS256Test.test(secretCode,  clientId, appCode, tokenPeriod, algorithm);
    }

    /**
     * 测试
     * @param str RS256算法时为privateKey, HS256算法时为secretCode
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
